#include <QCoreApplication>
#include <QDebug>
#include <QEventLoop>
#include <QTimer>
#include <QUrl>
#include <QtOpcUa/QOpcUaApplicationDescription>
#include <QtOpcUa/QOpcUaClient>
#include <QtOpcUa/QOpcUaProvider>

#include "open62541.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>

#if UA_OPEN62541_VER_MAJOR == 1 && UA_OPEN62541_VER_MINOR < 4
#include <openssl/crypto.h>
#endif

// This is a regression test for QOpcUaClient::findServers() with the open62541
// backend, against a server that offers only secured endpoints but allows
// discovery over a SecurityPolicy#None SecureChannel.
//
// The backend calls UA_Client_findServers() on a client that only supports
// SecurityPolicy#None. From open62541 1.4 on, that discovery-only connect also
// runs GetEndpoints and requires a usable session endpoint, so findServers()
// fails with BadIdentityTokenRejected. See
// https://github.com/open62541/open62541/pull/8554 (1.5), #8553 (1.4) and
// #8042 (master).
//
// The client is the installed QtOpcUa and its open62541 backend plugin. The
// server runs in-process, built from the open62541 sources bundled by qtopcua.

enum class Endpoints {
    WithNone,   // SecurityPolicy#None endpoint offered
    SecuredOnly // Only secured endpoints, None is restricted to discovery
};

static bool createCertificate(UA_ByteString *privateKey, UA_ByteString *certificate)
{
    UA_String subject[] = {UA_STRING_STATIC("C=DE"), UA_STRING_STATIC("O=Test"),
                           UA_STRING_STATIC("CN=open62541Server@localhost")};
    UA_String subjectAltName[] = {UA_STRING_STATIC("DNS:localhost"),
                                  UA_STRING_STATIC("URI:urn:open62541.server.application")};
#if UA_OPEN62541_VER_MAJOR == 1 && UA_OPEN62541_VER_MINOR < 4
    UA_StatusCode result =
            UA_CreateCertificate(UA_Log_Stdout, subject, 3, subjectAltName, 2, 2048,
                                 UA_CERTIFICATEFORMAT_DER, privateKey, certificate);
    // 1.3 returns the DER buffers allocated by OpenSSL (i2d_*). Move them to
    // the open62541 heap, UA_free() on them breaks with mismatched CRTs.
    for (UA_ByteString *buffer : {privateKey, certificate}) {
        UA_ByteString copy = UA_BYTESTRING_NULL;
        if (result == UA_STATUSCODE_GOOD)
            result = UA_ByteString_copy(buffer, &copy);
        OPENSSL_free(buffer->data);
        *buffer = copy;
    }
#else
    const UA_StatusCode result =
            UA_CreateCertificate(UA_Log_Stdout, subject, 3, subjectAltName, 2,
                                 UA_CERTIFICATEFORMAT_DER, nullptr, privateKey, certificate);
#endif
    if (result != UA_STATUSCODE_GOOD)
        qCritical() << "UA_CreateCertificate returned" << UA_StatusCode_name(result);
    return result == UA_STATUSCODE_GOOD;
}

// Removes the SecurityPolicy#None endpoints. The None policy stays in the
// security policy list, but is only accepted for discovery services.
static bool removeNoneEndpoints(UA_ServerConfig *config)
{
    size_t kept = 0;
    for (size_t i = 0; i < config->endpointsSize; ++i) {
        UA_EndpointDescription *endpoint = &config->endpoints[i];
        if (UA_String_equal(&endpoint->securityPolicyUri, &UA_SECURITY_POLICY_NONE_URI)) {
            UA_EndpointDescription_clear(endpoint);
            continue;
        }
        if (kept != i)
            config->endpoints[kept] = *endpoint;
        ++kept;
    }
    config->endpointsSize = kept;
    if (kept == 0) {
        UA_free(config->endpoints);
        config->endpoints = nullptr;
    }
    config->securityPolicyNoneDiscoveryOnly = true;
    return kept > 0;
}

class TestServer
{
public:
    TestServer(UA_UInt16 port, Endpoints endpoints)
    {
        UA_ServerConfig config;
        std::memset(&config, 0, sizeof(config));
        if (endpoints == Endpoints::WithNone) {
            UA_ServerConfig_setMinimal(&config, port, nullptr);
        } else {
            UA_ByteString privateKey = UA_BYTESTRING_NULL;
            UA_ByteString certificate = UA_BYTESTRING_NULL;
            if (!createCertificate(&privateKey, &certificate))
                return;
            const UA_StatusCode result = UA_ServerConfig_setDefaultWithSecurityPolicies(
                    &config, port, &certificate, &privateKey, nullptr, 0, nullptr, 0, nullptr, 0);
            UA_ByteString_clear(&privateKey);
            UA_ByteString_clear(&certificate);
            if (result != UA_STATUSCODE_GOOD) {
                qCritical() << "UA_ServerConfig_setDefaultWithSecurityPolicies returned"
                            << UA_StatusCode_name(result);
                UA_ServerConfig_clean(&config);
                return;
            }
        }

        m_server = UA_Server_newWithConfig(&config);
        if (!m_server)
            return;

        if (UA_Server_run_startup(m_server) != UA_STATUSCODE_GOOD)
            return;

        // The server is not iterated in another thread yet, so the config can
        // be changed without locking
        UA_ServerConfig *serverConfig = UA_Server_getConfig(m_server);
        if (endpoints == Endpoints::SecuredOnly && !removeNoneEndpoints(serverConfig)) {
            qCritical() << "No secured endpoint configured, is encryption enabled?";
            UA_Server_run_shutdown(m_server);
            return;
        }
        for (size_t i = 0; i < serverConfig->endpointsSize; ++i) {
            const UA_EndpointDescription &endpoint = serverConfig->endpoints[i];
            qInfo().noquote() << "Server endpoint" << i
                              << QString::fromUtf8(reinterpret_cast<const char *>(
                                                           endpoint.securityPolicyUri.data),
                                                   endpoint.securityPolicyUri.length)
                              << "mode" << endpoint.securityMode;
        }

        m_running = true;
        m_thread = std::thread([this] {
            while (m_running)
                UA_Server_run_iterate(m_server, true);
        });
    }

    ~TestServer()
    {
        if (m_thread.joinable()) {
            m_running = false;
            m_thread.join();
            UA_Server_run_shutdown(m_server);
        }
        if (m_server)
            UA_Server_delete(m_server);
    }

    bool isRunning() const { return m_running; }

private:
    UA_Server *m_server = nullptr;
    std::atomic<bool> m_running{false};
    std::thread m_thread;
};

static bool findServers(const char *name, UA_UInt16 port, Endpoints endpoints)
{
    qInfo() << "===" << name;

    TestServer server(port, endpoints);
    if (!server.isRunning()) {
        qCritical() << name << "- could not start the test server on port" << port;
        return false;
    }

    QOpcUaProvider provider;
    std::unique_ptr<QOpcUaClient> client(provider.createClient(QStringLiteral("open62541")));
    if (!client) {
        qCritical() << name << "- could not create an open62541 client, available backends:"
                    << QOpcUaProvider::availableBackends();
        return false;
    }

    bool finished = false;
    QList<QOpcUaApplicationDescription> servers;
    QOpcUa::UaStatusCode statusCode = QOpcUa::UaStatusCode::Good;
    QEventLoop loop;
    QObject::connect(client.get(), &QOpcUaClient::findServersFinished, &loop,
                     [&](const QList<QOpcUaApplicationDescription> &result,
                         QOpcUa::UaStatusCode resultStatusCode) {
                         finished = true;
                         servers = result;
                         statusCode = resultStatusCode;
                         loop.quit();
                     });
    QTimer::singleShot(30000, &loop, &QEventLoop::quit);

    if (!client->findServers(QUrl(QStringLiteral("opc.tcp://localhost:%1").arg(port)))) {
        qCritical() << name << "- findServers() could not be dispatched";
        return false;
    }
    loop.exec();

    if (!finished) {
        qCritical() << name << "- findServers() did not finish";
        return false;
    }

    // Not every status code has a QOpcUa::UaStatusCode enumerator, e.g.
    // BadIdentityTokenRejected, so report the raw value
    if (statusCode != QOpcUa::UaStatusCode::Good || servers.isEmpty()) {
        qCritical().noquote() << name << "- findServers() returned status code"
                              << QStringLiteral("0x%1").arg(quint32(statusCode), 8, 16,
                                                            QLatin1Char('0'))
                              << "with" << servers.size() << "server(s)";
        return false;
    }

    qInfo() << name << "- found" << servers.size() << "server(s)";
    return true;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    qInfo() << "Test server uses open62541" << UA_OPEN62541_VER_MAJOR << UA_OPEN62541_VER_MINOR
            << UA_OPEN62541_VER_PATCH;

    int failures = 0;
    if (!findServers("withNoneEndpoint", 48401, Endpoints::WithNone))
        ++failures;
    if (!findServers("withoutNoneEndpoint", 48402, Endpoints::SecuredOnly))
        ++failures;

    if (failures != 0) {
        qCritical() << failures << "case(s) failed";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

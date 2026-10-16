cmake_minimum_required (VERSION 3.18)

set (CMAKE_BUILD_TYPE "Release" CACHE STRING "build type")

project (qt6-opcua-test C CXX)

# open62541.c/open62541.h bundled by qtopcua (src/3rdparty/open62541), used to
# build the test server
set (OPEN62541_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src/3rdparty/open62541"
     CACHE PATH "Directory containing the bundled open62541.c and open62541.h")

find_package (Qt6 CONFIG REQUIRED COMPONENTS Core OpcUa)
find_package (OpenSSL REQUIRED)

# The test server offers secured endpoints, so it needs encryption support
add_library (open62541 STATIC "${OPEN62541_SOURCE_DIR}/open62541.c")
target_include_directories (open62541 PUBLIC "${OPEN62541_SOURCE_DIR}")
target_compile_definitions (open62541 PUBLIC UA_ENABLE_ENCRYPTION_OPENSSL)
target_link_libraries (open62541 PUBLIC OpenSSL::SSL OpenSSL::Crypto)
set_target_properties (open62541 PROPERTIES C_STANDARD 99)
if (MSVC)
    target_compile_options (open62541 PRIVATE /wd4133)
else ()
    target_compile_options (open62541 PRIVATE
        -Wno-unused-parameter -Wno-uninitialized -Wno-unused-function -Wno-unused-variable)
endif ()
if (WIN32)
    target_link_libraries (open62541 PUBLIC ws2_32 iphlpapi)
else ()
    find_package (Threads REQUIRED)
    target_link_libraries (open62541 PUBLIC Threads::Threads m)
endif ()

add_executable (test_qopcuaclient_findservers test_qopcuaclient_findservers.cpp)
target_link_libraries (test_qopcuaclient_findservers Qt6::Core Qt6::OpcUa open62541)
set_target_properties (test_qopcuaclient_findservers PROPERTIES CXX_STANDARD 17)

enable_testing ()
add_test (NAME test_qopcuaclient_findservers COMMAND test_qopcuaclient_findservers)
# Load the backend from this prefix, and log to stderr: without a console, Qt
# on Windows logs to the debugger instead
set_tests_properties (test_qopcuaclient_findservers PROPERTIES
    TIMEOUT 120
    ENVIRONMENT "QT_PLUGIN_PATH=${QT6_INSTALL_PREFIX}/${QT6_INSTALL_PLUGINS};QT_FORCE_STDERR_LOGGING=1;QT_LOGGING_RULES=qt.opcua.plugins.open62541.debug=true")

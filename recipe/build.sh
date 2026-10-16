#!/bin/bash
set -ex

cmake -LAH -G"Ninja"                                          \
    -DCMAKE_BUILD_TYPE=Release                                \
    -DCMAKE_PREFIX_PATH="${PREFIX}"                           \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}"                        \
    -DCMAKE_UNITY_BUILD=ON -DCMAKE_UNITY_BUILD_BATCH_SIZE=32  \
    .

cmake --build . --target install --config Release

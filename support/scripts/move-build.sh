#!/bin/bash

PROJECT_ROOT=$(pwd)
BUILD_PATH=${PROJECT_ROOT}/build/docker/

mkdir -p ${BUILD_PATH}

rsync -r ${PROJECT_ROOT} ${BUILD_PATH}
rsync ${PROJECT_ROOT}/support/docker/deploy/Dockerfile ${BUILD_PATH}

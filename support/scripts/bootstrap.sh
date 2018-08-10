#!/bin/bash

PROJECT_ROOT=$(pwd)

cd ${PROJECT_ROOT}/ && \
    apt install autoconf -y && \
    ./boot.sh && \
    ./configure

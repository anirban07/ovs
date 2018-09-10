#!/bin/bash

PROJECT_ROOT=$(pwd)

# use TESTSUITEFLAGS='num num1-num2' for running specific tests

cd ${PROJECT_ROOT} && \
    make check

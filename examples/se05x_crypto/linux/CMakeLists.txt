# SPDX-License-Identifier: Apache-2.0

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(ex_se05x_crypto)

ADD_EXECUTABLE(${PROJECT_NAME} main.c ../src/ex_se05x_crypto.c)

ADD_SUBDIRECTORY(../../../lib build)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC se05x_lib)




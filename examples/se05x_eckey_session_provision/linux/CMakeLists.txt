# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(ex_se05x_eckey_session_provision)

ADD_EXECUTABLE(${PROJECT_NAME} main.c ../src/se05x_eckey_session_provision.c)

ADD_SUBDIRECTORY(../../../lib build)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC se05x_lib)

if(PLUGANDTRUST_DEBUG_LOGS)
    ADD_DEFINITIONS(-DSMLOG_DEBUG_MESSAGES)
ENDIF()

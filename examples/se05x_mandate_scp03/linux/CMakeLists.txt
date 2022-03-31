# SPDX-License-Identifier: Apache-2.0

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

# Build example to send 'PlatformSCPRequest_REQUIRED' OR 'PlatformSCPRequest_NOT_REQUIRED' command
IF(PLUGANDTRUST_SCP03)
	PROJECT(ex_se05x_mandate_scp03_remove)
ELSE()
	PROJECT(ex_se05x_mandate_scp03_set)
ENDIF()

ADD_EXECUTABLE(${PROJECT_NAME} main.c ../src/ex_se05x_mandate_scp03.c ../src/ex_se05x_userId_APDU.c)

ADD_SUBDIRECTORY(../../../lib build)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} se05x_lib)

if(PLUGANDTRUST_DEBUG_LOGS)
    ADD_DEFINITIONS(-DSMLOG_DEBUG_MESSAGES)
ENDIF()

IF(PLUGANDTRUST_SCP03)
	MESSAGE(STATUS "Building example to remove Mandate SCP03")
	ADD_DEFINITIONS(-DWITH_PlatformSCPRequest_NOT_REQUIRED)
ELSE()
	MESSAGE(STATUS "Building example to set Mandate SCP03")
	ADD_DEFINITIONS(-DWITH_PlatformSCPRequest_REQUIRED)
ENDIF()

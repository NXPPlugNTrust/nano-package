# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
IF(CONFIG_PLUGANDTRUST_SCP03)
	project(ex_se05x_mandate_scp03_remove)
ELSE()
	project(ex_se05x_mandate_scp03_set)
ENDIF()

target_sources(app PRIVATE src/main.c ../src/ex_se05x_mandate_scp03.c ../src/ex_se05x_userId_APDU.c)

IF(CONFIG_PLUGANDTRUST_SCP03)
	message(STATUS "Building example to remove Mandate SCP03")
	add_definitions(-DWITH_PlatformSCPRequest_NOT_REQUIRED)
ELSE()
	message(STATUS "Building example to set Mandate SCP03")
	add_definitions(-DWITH_PlatformSCPRequest_REQUIRED)
ENDIF()
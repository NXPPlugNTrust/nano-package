# SPDX-License-Identifier: Apache-2.0

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(test_se05x)

ADD_EXECUTABLE(
	${PROJECT_NAME}
	main.c
	../src/test_se05x.c
	../src/test_se05x_nist256.c
	../src/test_se05x_nist256_ecdsa.c
	../src/test_se05x_bin_objects.c
	../src/test_se05x_aes.c
	../src/test_se05x_misc.c
	../src/test_se05x_nist256_ecdh.c
	)

ADD_SUBDIRECTORY(../../lib build)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC se05x_lib)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    ../src/
    )

IF(PLUGANDTRUST_ENABLE_CODE_COVERAGE)
    set(CMAKE_C_FLAGS "-g -O0 --coverage -fprofile-arcs -ftest-coverage")
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC gcov)
ENDIF()



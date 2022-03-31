# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(se05x_tests)

target_sources(app PRIVATE
	src/main.c
	../src/test_se05x.c
	../src/test_se05x_nist256.c
	../src/test_se05x_nist256_ecdsa.c
	../src/test_se05x_nist256_ecdh.c
	../src/test_se05x_aes.c
	../src/test_se05x_bin_objects.c
	../src/test_se05x_misc.c
	)

target_include_directories(app PRIVATE ../../src)

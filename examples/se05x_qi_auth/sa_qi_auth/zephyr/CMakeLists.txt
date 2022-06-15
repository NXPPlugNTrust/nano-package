# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ex_qi_auth)

FILE(
    GLOB
    SRC_FILES
    ../*.c
    ../port/*.c
    ../../sa_qi_transmitter_auth/*.c
    ../../sa_qi_transmitter_auth/port/*.c
)

target_sources(app PRIVATE src/main.c ${SRC_FILES})
zephyr_include_directories(
    src/
    ../../src/
    ../
    ../port
    ../../sa_qi_transmitter_auth
    ../../sa_qi_transmitter_auth/port
)

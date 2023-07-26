# SPDX-License-Identifier: Apache-2.0

project(se05x_lib)

OPTION(PLUGANDTRUST_SCP03 "Build with Secure Channel" OFF)
OPTION(PLUGANDTRUST_DEBUG_LOGS "Build with Debug logs" OFF)

FILE(
    GLOB
    SE05X_SOURCES
    apdu/se05x_APDU_impl.c
    apdu/se05x_tlv.c
    platform/linux/sm_i2c.c
    platform/linux/sm_timer.c
)

IF(PLUGANDTRUST_SCP03)
    FILE(
        GLOB
        SCP03_SOURCES
        apdu/scp03/se05x_scp03.c
        apdu/scp03/openssl/se05x_scp03_crypto_openssl.c
    )
ENDIF(PLUGANDTRUST_SCP03)

FILE(
    GLOB
    SMCOM_SOURCES
    apdu/smCom.c
    t1oi2c/phNxpEse_Api.c
    t1oi2c/phNxpEsePal_i2c.c
    t1oi2c/phNxpEseProto7816_3.c
    )

ADD_LIBRARY(${PROJECT_NAME} ${SE05X_SOURCES} ${SMCOM_SOURCES} ${SCP03_SOURCES})

IF(PLUGANDTRUST_SCP03)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC ssl crypto)
ENDIF(PLUGANDTRUST_SCP03)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC
    apdu
    apdu/scp03
    apdu/scp03/openssl
    t1oi2c
    platform/linux
    )

ADD_DEFINITIONS(-DT1oI2C)
ADD_DEFINITIONS(-DT1oI2C_UM11225)


if(PLUGANDTRUST_DEBUG_LOGS)
    ADD_DEFINITIONS(-DSMLOG_DEBUG_MESSAGES)
ENDIF()

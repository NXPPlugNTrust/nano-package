# SPDX-License-Identifier: Apache-2.0

project(se05x_lib)

OPTION(PLUGANDTRUST_DEBUG_LOGS "Build with Debug logs" OFF)
SET(PLUGANDTRUST_SE05X_AUTH "None" CACHE STRING "SE050 Authentication")
SET_PROPERTY(CACHE PLUGANDTRUST_SE05X_AUTH PROPERTY STRINGS "None;PlatfSCP03;ECKey;ECKey_PlatSCP03")

FILE(
    GLOB
    SE05X_SOURCES
    apdu/se05x_APDU_impl.c
    apdu/se05x_tlv.c
    platform/linux/sm_i2c.c
    platform/linux/sm_timer.c
)

IF("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "PlatfSCP03")
    ADD_DEFINITIONS(-DWITH_PLATFORM_SCP03)
    FILE(
        GLOB
        SCP03_SOURCES
        apdu/scp03/se05x_scp03.c
        apdu/scp03/se05x_auth_utils.c
        apdu/scp03/openssl/se05x_scp03_crypto_openssl.c
    )
ENDIF()

IF("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "ECKey")
    ADD_DEFINITIONS(-DWITH_ECKEY_SESSION)
    FILE(
        GLOB
        SCP03_SOURCES
        apdu/eckey/se05x_ec_key_auth.c
        apdu/scp03/se05x_auth_utils.c
        apdu/scp03/openssl/se05x_scp03_crypto_openssl.c
    )
ENDIF()

IF("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "ECKey_PlatSCP03")
    ADD_DEFINITIONS(-DWITH_ECKEY_SCP03_SESSION)
    FILE(
        GLOB
        SCP03_SOURCES
        apdu/scp03/se05x_scp03.c
        apdu/eckey/se05x_ec_key_auth.c
        apdu/scp03/se05x_auth_utils.c
        apdu/scp03/openssl/se05x_scp03_crypto_openssl.c
    )
ENDIF()

FILE(
    GLOB
    SMCOM_SOURCES
    apdu/smCom.c
    t1oi2c/phNxpEse_Api.c
    t1oi2c/phNxpEsePal_i2c.c
    t1oi2c/phNxpEseProto7816_3.c
    )

ADD_LIBRARY(${PROJECT_NAME} ${SE05X_SOURCES} ${SMCOM_SOURCES} ${SCP03_SOURCES})

IF ( ("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "PlatfSCP03")  OR ("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "ECKey") OR ("${PLUGANDTRUST_SE05X_AUTH}" STREQUAL "ECKey_PlatSCP03") )
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} PUBLIC ssl crypto)
ENDIF()

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

IF(PLUGANDTRUST_SCP03)
    ADD_DEFINITIONS(-DWITH_PLATFORM_SCP03)
ENDIF(PLUGANDTRUST_SCP03)

if(PLUGANDTRUST_DEBUG_LOGS)
    ADD_DEFINITIONS(-DSMLOG_DEBUG_MESSAGES)
ENDIF()

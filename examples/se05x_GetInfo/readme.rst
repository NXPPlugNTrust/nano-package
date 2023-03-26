.. _ex_se05x_GetInfo:

SE05x GetInfo Example
======================

**Overview**

This example can be used to get SE05X platform information with or without applet installed.

Refer file - 'simw-nanopkg/examples/se05x_crypto/src/ex_se05x_GetInfo.c'

**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run ::

	cd simw-nanopkg/examples/ex_se05x_GetInfo/linux
	mkdir build
	cd build
	cmake ../
	make
	./ex_se05x_GetInfo

**Build options**

Platform SCP03 ::

	-DPLUGANDTRUST_SCP03=OFF -- Build with Platform SCP03 disabled

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON -- Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF -- Build with Debug logs disabled

**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	./ex_se05x_GetInfo
    Se05x Getinfo Example !
    Plug and Trust nano package - version: 1.2.0
    I2C driver supports plain i2c-level commands.
    #####################################################
    Close i2c device 3.
    Plug and Trust nano package - version: 1.2.0
    I2C driver supports plain i2c-level commands.
    #####################################################
    Applet Major = 7
    Applet Minor = 2
    Applet patch = 0
    AppletConfig = 3FFF
    With    ECDSA_ECDH_ECDHE
    With    EDDSA
    With    DH_MONT
    With    HMAC
    With    RSA_PLAIN
    With    RSA_CRT
    With    AES
    With    DES
    With    PBKDF
    With    TLS
    With    MIFARE
    With    I2CM
    Internal = FFFF
    #####################################################
    Tag value - proprietary data 0xFE = 0xFE
    Length of following data 0x45 = 0x45
    Length of card identification data = 0x42
    Tag configuration ID (Must be 0x01) = 0x01
    OEF ID = 0xA8 0xFA
    Tag patch ID (Must be 0x02) = 0x02
    Tag platform build ID1 (Must be 0x03) = 0x03
    JCOP Platform ID = J3R351029B411100
    Tag FIPS mode (Must be 0x05) = 0x05
    FIPS mode var = 0x00
    Tag pre-perso state (Must be 0x07) = 0x07
    Bit mask of pre-perso state var = 0x00
    Tag ROM ID (Must be 0x08) = 0x08
    se05x_GetInfoPlainApplet Example Success !!!...
    #####################################################
    Close i2c device 3.
    SE05x Getinfo Example Success !
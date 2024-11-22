.. _change-log:

ChangeLog
=========

ChangeLog
---------

**Release v1.5.1**

- Memory overlap issue fixed in function - Se05x_API_SCP03_Encrypt.

**Release v1.5.0**

- Example `se05x_mbedtls_alt_test` added to demonstrate MbedTLS ALT support in Zephyr.
- mcxn947 and mcxa153 examples updated to use SDK version 2.16
- Attestation APDU added. (Se05x_API_ReadObject_W_Attst).


**Release v1.4.0**

- Zephyr integration updated to v3.7.0
- New APDUs added: Se05x_API_ReadIDList, Se05x_API_ReadSize, Se05x_API_ReadType, Se05x_API_CreateECCurve, Se05x_API_DeleteECCurve, Se05x_API_SetECCurveParam, Se05x_API_ReadECCurveList.
- NIST P384 curve supported.
- Default max APDU buffer size increased to 512 (`MAX_APDU_BUFFER` in se05x_types.h).
- se05x_ReadIDList example added (Example to read the contents of secure element).
- se05x_eckey_session_provision example added (Example to provision key for EC-Key authentication session).
- MbedTLS ALT files (\lib\mbedtls_alt\) updated to support MbedTLS version 3.6.0
- Bug fix: In MbedTLS ALT ECDSA function (mbedtls_ecdsa_sign in \lib\mbedtls_alt\ecdsa_se05x.c), key length calculation is corrected.


**Release v1.3.0**

- EC Key Authentication support added.
- PlatformSCP03 + EC Key Authentication support added.
- New platforms - mcxn947 and mcxa153 support.
- IMPORTANT: cmake option `-DPLUGANDTRUST_SCP03` is removed. -DPLUGANDTRUST_SE05X_AUTH:STRING=<OPTION> is added to chose between multiple authentication.

**Release v1.2.4**

- Examples for Zephyr updated with board overlay files.
- Added manifest file for nano package integration in Zephyr OS (zephyr/west.yml)

**Release v1.2.3**

- Zephyr integration branch (feature/zephyr-integration) merged to master.
- Zephyr integration updated to zephyr release - v3.5.0.

**Release v1.2.2**

- MbedTLS alt ecdsa bug fix - Updated function used to extract r and s using mbedtls APIs

**Release v1.2.1**

- Updated log messages for k64 port files
- Added retry on I2C failed error. (Disabled by default). To enable - uncomment T1OI2C_RETRY_ON_I2C_FAILED in phNxpEsePal_i2c.h.
- Increased t=1oi2c retry count. (MAX_RETRY_COUNT).

**Release v1.2.0**

- Added security fix on 24-Feb-2023 to prevent buffer overflow on the T=1oI2C stack.
- se05x_GetInfo example added to get SE05X platform information.

**Release v1.1.1**

- Added a check to prevent a potential buffer overflow issue in T=1OI2C stack

**Release v1.1.0**

- Features
	- Added Secure Authenticator (Qi) examples
	- Integration of twister framework from zephyr OS

**Release v1.0.0**

- Initial commit
- Features
	- ECDSA and ECDH with NIST P256
	- AES Encrypt / Decrypt (ECB,CBC,CTR)
	- Binary Objects
	- Encrypted I2C communication using PlatformSCP channel based on Global Platform SCP03
	- Platforms - Linux, frdm-k64 bare metal, Zephyr OS

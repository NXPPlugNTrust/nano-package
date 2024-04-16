.. _change-log:

ChangeLog
=========

ChangeLog
---------


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

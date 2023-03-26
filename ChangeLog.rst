.. _change-log:

ChangeLog
=========

ChangeLog
---------

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

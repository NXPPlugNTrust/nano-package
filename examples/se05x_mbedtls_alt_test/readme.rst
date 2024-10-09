.. _tst_se05x_mbedtls_alt:

SE05x Mbedtls ALT Testing
=========================

**Overview**

Test Mbedtls ALT files for SE05x.

The example will

- Inject the actual key pair in SE05x at location 0x11223344

- Will set the reference key on host using Mbedtls APIs.
Reference key is Key data structure with only a reference to the Private Key
inside the Secure Element instead of the actual Private Key.

- Call Mbedtls ECDSA sign and verify functions.
The ECDSA sign is offloaded to secure element using Mbedtls alt file.
ECDSA Verify is done on host using Mbedtls.

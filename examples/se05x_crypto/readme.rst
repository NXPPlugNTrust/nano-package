.. _ex_se05x_crypto:

SE05x Crypto Example
====================

**Overview**

This example demonstrates SE05x crypto functionality using se05x APIs.

Refer file - 'simw-nanopkg/examples/se05x_crypto/src/ex_se05x_crypto.c'

.. note ::

	When building the example with 'Platform SCP' / `ECkey` enabled, make sure to
	assign valid scp03 / EC keys to session context.

**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run ::

	cd simw-nanopkg/examples/se05x_crypto/linux
	mkdir build
	cd build
	cmake ../
	make
	./ex_se05x_crypto

**Build options**

Authentication ::

	-DPLUGANDTRUST_SE05X_AUTH:STRING=None : Build with no authentication
	-DPLUGANDTRUST_SE05X_AUTH:STRING=PlatfSCP03 : Build with Platform SCP03 enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey : Build with ECKey Authentication enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey_PlatSCP03 : Build with EcKey and Platform SCP03 combined

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON -- Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF -- Build with Debug logs disabled

**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	./ex_se05x_crypto
	Plug and Trust nano package - version: 1.0.0
	Establish Secure Channel to SE05x !
	Get Version ==>
	Applet Version 6.0.0
	test_get_version complete
	test_generate_nist256_key complete
	test_set_get_nist256_key complete
	test_nist256_sign_verify complete
	test_set_certificate complete
	test_ecdh complete
	test_aes_ECB_NOPAD complete
	test_aes_CBC_NOPAD complete
	test_aes_CTR complete
	test_nist256_sign_policy complete


.. _se05x_eckey_session_provision:

SE05x EC-Key Session Provision
===============================

**Overview**

This example will provision the key for EC Key session with SE05x.

Refer file - 'simw-nanopkg/examples/se05x_eckey_session_provision/src/se05x_eckey_session_provision.c'.

.. note ::

	1. Run the example with either auth=none or auth=platformSCP03

	2. When building the example with 'Platform SCP' enabled, make sure to
	assign valid scp03 keys to session context.

**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run::

	cd simw-nanopkg/examples/se05x_eckey_session_provision/linux
	mkdir build
	cd build
	cmake ../
	make
	./ex_se05x_eckey_session_provision


**Build options**

Authentication ::

	-DPLUGANDTRUST_SE05X_AUTH:STRING=None : Build with no authentication
	-DPLUGANDTRUST_SE05X_AUTH:STRING=PlatfSCP03 : Build with Platform SCP03 enabled

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON : Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF : Build with Debug logs disabled


**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	Plug and Trust nano package - version: 1.4.0
	The example will provision the EC Auth Key (Only Public key) at location - ECKEY_AUTH_OBJECT_ID
	To Open EC Key session, pass the same key pair to session context (session_ctx->pEc_auth_key)
	SE05x EC-Key Provision Example Success !

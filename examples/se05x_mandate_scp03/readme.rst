.. _ex_se05x_mandate_scp03:

SE05x Mandate SCP03 Example
===========================

**Overview**

This example demonstrates how to mandate the use of Platform SCP by calling SetPlatformSCPRequest.

This is a persistent state.

SetPlatformSCPRequest APDU can be sent in session authenticated with 'RESERVED_ID_PLATFORM_SCP' user id.

The example can be used to either 'Mandate PlatformSCP' or remove the 'Mandate PlatformSCP' state.

When example is built with -DPLUGANDTRUST_SCP03=OFF, ex_se05x_mandate_scp03_set is built. (Set Mandate PlatformSCP).

When example is built with -DPLUGANDTRUST_SCP03=ON, ex_se05x_mandate_scp03_remove is built. (Removes Mandate PlatformSCP).

Refer file - 'simw-nanopkg/examples/se05x_mandate_scp03/src/ex_se05x_mandate_scp03.c'.

.. note ::

	When building the example with 'Platform SCP' enabled, make sure to
	assign valid scp03 keys to session context.


**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run ::

	cd simw-nanopkg/examples/se05x_mandate_scp03/linux
	mkdir build
	cd build
	cmake ../ -DPLUGANDTRUST_SCP03=OFF
	make
	./ex_se05x_mandate_scp03_set

	cd simw-nanopkg/examples/se05x_mandate_scp03/linux
	mkdir build
	cd build
	cmake ../ -DPLUGANDTRUST_SCP03=ON
	make
	./ex_se05x_mandate_scp03_remove


**Build options**

Platform SCP03 ::

	-DPLUGANDTRUST_SCP03=ON : Build with Platform SCP03 enabled
	-DPLUGANDTRUST_SCP03=OFF : Build with Platform SCP03 disabled

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON : Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF : Build with Debug logs disabled


**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	./ex_se05x_mandate_scp03_set
	Plug and Trust nano package - version: 1.0.0
	Sending PlatformSCPRequest_REQUIRED command
	Example successful

	./ex_se05x_mandate_scp03_remove
	Plug and Trust nano package - version: 1.0.0
	Establish Secure Channel to SE05x !
	Sending PlatformSCPRequest_NOT_REQUIRED command
	Example successful

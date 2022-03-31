.. _ex_se05x_rotate_scp03_keys:

SE05x Rotate SCP03 Example
==========================

**Overview**

This example demonstrates how to update SCP03 keys in SE05x.

On running the example, it will update the SCP03 keys and revert back to original keys.

**The example works only with Platform SCP03 enabled.**

Refer file - 'simw-nanopkg/examples/se05x_rotate_scp03_keys/src/ex_se05x_rotate_scp03_keys.c'.

.. note ::

	When building the example with 'Platform SCP' enabled, make sure to
	assign valid scp03 keys to session context. All keys are necessary for this operation - enc, mac, dek.


**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run ::

	cd simw-nanopkg/examples/se05x_rotate_scp03_keys/linux
	mkdir build
	cd build
	cmake ../ -DPLUGANDTRUST_SCP03=ON
	make
	./ex_se05x_rotate_scp03_keys


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

	./ex_se05x_rotate_scp03_keys
	Plug and Trust nano package - version: 1.0.0
	Establish Secure Channel to SE05x !
	Changing SCP03 keys(version - 0b) to NEW KEYS
	Congratulations !!! Key Rotation Successful!
	Reverting SCP03 keys(version - 0b) to OLD KEYS
	Congratulations !!! Key Rotation Successful!

.. _se05x_sign:

SE05x Sign Example
==================

**Overview**

This example demonstrates signing a data using nist256 key.

Refer file - 'simw-nanopkg/examples/se05x_crypto/src/ex_se05x_sign.c'.

.. note ::

	When building the example with 'Platform SCP' enabled, make sure to
	assign valid scp03 keys to session context.

**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run::

	cd simw-nanopkg/examples/se05x_crypto/linux
	mkdir build
	cd build
	cmake ../
	make
	./ex_se05x_sign


**Build options**

Authentication ::

	-DPLUGANDTRUST_SE05X_AUTH:STRING=None : Build with no authentication
	-DPLUGANDTRUST_SE05X_AUTH:STRING=PlatfSCP03 : Build with Platform SCP03 enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey : Build with ECKey Authentication enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey_PlatSCP03 : Build with EcKey and Platform SCP03 combined

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON : Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF : Build with Debug logs disabled


**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	Plug and Trust nano package - version: 1.0.0
	Generate ecc key
	Signature ==>
	0X30 0X46 0X2 0X21 0 0X84 0X69 0X1F 0XFE 0XBC 0XC2 0X2F 0X10 0XBB 0X8D 0X95 0X9A 0X26 0XD3 0XE2 0X11 0X62 0X81 0XF2 0X7D 0X3 0X5E 0X6B 0X42 0XC8 0X63 0X4F 0XC3 0X50 0XFF 0XE2 0X3 0X2 0X21 0 0XD6 0XEB 0XD3 0X8D 0X83 0XEB 0XF7 0X6F 0X46 0XF1 0XFA 0XF5 0XF5 0X24 0XFA 0X26 0X98 0X7A 0X92 0X79 0XBA 0X22 0XAE 0X11 0X1D 0X64 0X8E 0XB0 0XFD 0X48 0X3C 0XB7


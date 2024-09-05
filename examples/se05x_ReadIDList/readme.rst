.. _se05x_ReadIDList:

SE05x ReadIDList Example
=========================

**Overview**

This example can be used to get the List of ID's that are provisioned in the SE05x

Refer file - 'simw-nanopkg/examples/se05x_ReadIDList/src/ex_se05x_ReadIDList.c'.

.. note ::

	When building the example with 'Platform SCP' enabled, make sure to
	assign valid scp03 keys to session context.

**Linux Prerequisite**

Install cmake , Openssl 1.1.1 ::

	sudo apt-get install cmake cmake-curses-gui cmake-gui libssl-dev

**Linux build**

To build example run::

	cd simw-nanopkg/examples/se05x_ReadIDList/linux
	mkdir build
	cd build
	cmake ../
	make
	./ex_se05x_ReadIDList


**Build options**

Authentication ::

	-DPLUGANDTRUST_SE05X_AUTH:STRING=None : Build with no authentication
	-DPLUGANDTRUST_SE05X_AUTH:STRING=PlatfSCP03 : Build with Platform SCP03 enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey : Build with ECKey Authentication enabled
	-DPLUGANDTRUST_SE05X_AUTH:STRING=ECKey_PlatSCP03 : Build with EcKey and Platform SCP03 combined

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON : Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF : Build with Debug logs disabled

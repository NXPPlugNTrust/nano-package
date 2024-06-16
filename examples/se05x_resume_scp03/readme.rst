.. _se05x_scp03_resume:

SE05x SCP03 Resume example
==========================

**Overview**

This example demonstrates SCP03 session resumption with SE05x.

Refer file - 'simw-nanopkg/examples/se05x_resume_scp03/src/ex_resume_scp03.c'.

.. note ::

	Make sure to assign valid SCP03 keys to session context.

**Linux build**

To build example run::

	cd simw-nanopkg/examples/se05x_resume_scp03/src
	mkdir build
	cd build
	cmake ../ -DPLUGANDTRUST_SE05X_AUTH:STRING=PlatfSCP03
	make
	./ex_establish_scp03
	./ex_resume_scp03


**Build options**

Debug Logs ::

	-DPLUGANDTRUST_DEBUG_LOGS=ON : Build with Debug logs enabled
	-DPLUGANDTRUST_DEBUG_LOGS=OFF : Build with Debug logs disabled


**Sample Output**

If everything is successful, the output will be similar to:

.. code-block:: console

	SE05x SCP03 Establish !
	Plug and Trust nano package - version: 1.0.0
	Establish Secure Channel to SE05x !
	Simply writing the session keys to the file system is not a secure implementation. It must not be used in production !!!...
	SE05x SCP03 Establish Success !

	SE05x SCP03 Resume Example !
	Plug and Trust nano package - version: 1.0.0
	Resuming Secure Channel to SE05x !
	Simply writing the session keys to the file system is not a secure implementation. It must not be used in production !!!...
	SE05x SCP03 Resume Success !

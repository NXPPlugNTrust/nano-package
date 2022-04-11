.. _se05x_zephyr_integration:

Getting Started with Zephyr + SE05x
===================================

**Overview**

Plug-and-trust nano package can be used to add the EdgeLock SE05x and A5000 secure elements and authenticators support in Zephyr OS.

Refer 'modules/crypto/nxp-plugandtrust/doc/plug-and-trust-nano-package-api-doc.pdf' for Plug and Trust Crypto APIs.

**Zephyr Integration / Build**

Clone Plug-and-Trust nano package in Zephyr crypto modules -- `<ZEPHYR_PROJECT>/modules/crypto`.

Update west.yml file with NXP github remote and Plug-and-Trust module path
::

	remotes:
    - name: upstream
      url-base: https://github.com/zephyrproject-rtos
    - name: nxp-git
      url-base: https://github.com/NXPPlugNTrust

    ...

	name: nano-package
	path: modules/crypto/nxp-plugandtrust
	revision: c15d0316334000724f0c94ee7943696edf3d6917
	remote: nxp-git


**Build Options**

Use the below options in prj.conf file of the example.

::

	CONFIG_PLUGANDTRUST=y/n   =================> Enable / Disable Plug and Trust lib support.
	CONFIG_PLUGANDTRUST_SCP03=y/n =============> Enable / Disable Platform SCP03 support.
	CONFIG_PLUGANDTRUST_I2C_PORT_NAME="I2C_0" => Set I2C port used by SE05x on host.
	CONFIG_PLUGANDTRUST_LOG_LEVEL_DBG=y/n =====> Enable / Disable Plug and Trust logs.

**Examples**

Build Plug and Trust examples on Zephyr OS as
::

	cd <ZEPHYR_PROJECT>/zephyr
	west build -b <BOARD> ../modules/crypto/nxp-plugandtrust/examples/<EXAMPLE_NAME>/zephyr/ --pristine


.. note ::

	Currently examples are tested with Frdm-k64 board.

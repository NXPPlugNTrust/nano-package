.. _se05x_zephyr_integration:

Getting Started with Zephyr + SE05x
###################################

Overview
===================================

Plug-and-Trust nano package can be used to add the EdgeLock SE05x and A5000
secure elements and authenticators support in Zephyr OS. (Tested with release tag - zephyr-v3.5.0)

Refer :file:`doc/plug-and-trust-nano-package-api-doc.pdf`
for Plug and Trust Crypto APIs.

Zephyr Integration / Build
===================================

Clone Plug-and-Trust nano package in Zephyr crypto modules -- :file:`<ZEPHYR_PROJECT>/modules/crypto`.

Update west.yml file with NXP github remote and Plug-and-Trust module path  (updated the revision to latest),
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


Build Options
===================================

Use the below options in prj.conf file of the example.

::

	CONFIG_PLUGANDTRUST=y/n   =================> Enable / Disable Plug and Trust lib support.
	CONFIG_PLUGANDTRUST_SCP03=y/n =============> Enable / Disable Platform SCP03 support.
	CONFIG_PLUGANDTRUST_LOG_LEVEL_DBG=y/n =====> Enable / Disable Plug and Trust logs.

Set I2C port used by SE05x in 'lib/platform/zephyr/sm_i2c.c'

::

	#define SE05X_I2C_DEV i2c0


Examples
===================================

Build Plug and Trust examples on Zephyr OS as
::

	cd <ZEPHYR_PROJECT>/zephyr
	west build -b <BOARD> ../modules/crypto/nxp-plugandtrust/examples/<EXAMPLE_NAME>/zephyr/ --pristine


.. note ::

	Currently examples are tested with frdm_k64f board.


Test Runner (Twister)
===================================

Using the zephyr twister script, Plug and Trust examples / tests can be run on K64F as
::

	python3 scripts/twister -p frdm_k64f --device-testing -device-serial <serial_port> -T ../modules/crypto/nxp-plugandtrust/ --west-flash --west-runner=jlink


.. note ::

	Twister script is tested with ubuntu 20.04 machine and zephyr 3.0.0.


.. _zephyr_demos:

Qi examples
========================

.. toctree::
   :maxdepth: 1

   zephyr/sa_qi/qi_auth_readme

   zephyr/sa_qi/qi_prov_readme


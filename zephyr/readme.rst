.. _se05x_zephyr_integration:

Getting Started with Zephyr + SE05x
###################################

Overview
===================================

Plug-and-Trust nano package can be used to add the EdgeLock SE05x and A5000
secure elements and authenticators support in Zephyr OS. (Tested with release tag - zephyr-v3.7.0)

Refer :file:`doc/plug-and-trust-nano-package-api-doc.pdf`
for Plug and Trust Crypto APIs.


Zephyr Integration / Build
===================================

Refer official Zephyr Getting Started Guide to Set up the Zephyr development environment.

Clone the nano package and Zephyr (required modules) as below
::

	west init -m https://github.com/NXPPlugNTrust/nano-package.git --mf zephyr\west.yml workspace
	cd workspace
	west update


.. note ::

	The west.yml file will clone the Zephyr v3.7.0.


Build Options
===================================

Use the below options in prj.conf file of the example.

::

	CONFIG_PLUGANDTRUST=y/n   =================> Enable / Disable Plug and Trust lib support.
	CONFIG_PLUGANDTRUST_SCP03=y/n =============> Enable / Disable Platform SCP03 support.
	CONFIG_PLUGANDTRUST_ECKEY=y/n =============> Enable / Disable ECKey Auth support.
	CONFIG_PLUGANDTRUST_ECKEY_SCP03=y/n =======> Enable / Disable ECKey + Platform SCP03 support.
	CONFIG_PLUGANDTRUST_LOG_LEVEL_DBG=y/n =====> Enable / Disable Plug and Trust logs.


Use the board overlay files to set the i2c port to alias - `se05x-i2c`. Refer frdm_k64f.overlay file for reference.


Examples
===================================

Build Plug and Trust examples on Zephyr OS as
::

	cd workspace/
	west build -b <BOARD> modules/crypto/nxp-plugandtrust/examples/<EXAMPLE_NAME>/zephyr/ --pristine


Test Runner (Twister)
===================================

Using the zephyr twister script, Plug and Trust examples / tests can be run on K64F as
::

	python3 scripts/twister -p frdm_k64f --device-testing --device-serial <serial_port> -T ../modules/crypto/nxp-plugandtrust/ --west-flash --west-runner=jlink


.. note ::

	Twister script is tested with ubuntu 20.04 machine and zephyr 3.7.0.


.. _zephyr_demos:

Qi examples
========================

.. toctree::
   :maxdepth: 1

   zephyr/sa_qi/qi_auth_readme

   zephyr/sa_qi/qi_prov_readme


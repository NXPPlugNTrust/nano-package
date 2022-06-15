..
    Copyright 2022 NXP

.. highlight:: bat

.. _ex-se05x-qi-auth:

Secure Authenticator (Qi) Authentication demo
#########################################################

Overview
=======================================================================

This project is used to demonstrate the Qi authentication flow between a Power Transmitter and 
a Power Receiver. The Power Transmitter implements 3 functions for the 3 authentication requests 
a Receiver can issue to the Transmitter : ``GetCertificateChainDigest``, ``ReadCertificates``, ``Authenticate``.


Pre-requisites
=======================================================================

- The secure element should be trust provisioned with correct keys and 
  certificates for Qi Authentication. Keys and certificates can be provisioned 
  for test purpose by updating keys in :file:`examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_credentials.c`
  and running example :ref:`ex-se05x-qi-provisioning`.

- By default WPC Root certificate is used in the certificate chain.
  If example :ref:`ex-se05x-qi-provisioning` is run, you would need to disable 
  macro ``USE_ROOT_WPCCA`` in :file:`sa_qi_rootcert.c` to use test RootCA:

  .. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_auth/sa_qi_rootcert.c
      :language: c
      :start-after: /* doc:start:qi-UseRootWpcCert */
      :end-before: /* doc:start:qi-UseRootWpcCert */

GetCertificateChainDigest (GET_DIGESTS)
=======================================================================

This function reads the digests of certificate chains stored inside the secure element
and returns all the digests as requested by the Power Receiver.

.. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_transmitter_auth/sa_qi_transmitter.c
    :language: c
    :start-after: /* doc:start:qi-GetCertificateChainDigest */
    :end-before: /* doc:end:qi-GetCertificateChainDigest */


ReadCertificates (GET_CERTIFICATE)
=======================================================================

This function reads the certificate chain on the provided slot ID starting 
from the provided offset and reading provided length bytes.

If the provided offset exceeds ``0x600`` then that indicates the power 
transmitter to offset from the Product Unit Certificate. Otherwise the offset
starts from the beginning of the certificate chain.

.. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_transmitter_auth/sa_qi_transmitter.c
    :language: c
    :start-after: /* doc:start:qi-ReadCertificates */
    :end-before: /* doc:end:qi-ReadCertificates */


Authenticate (CHALLENGE)
=======================================================================

This function performs the CHALLENGE operation and returns the signature ``R`` 
and signature ``S`` values to the power receiver.

.. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_transmitter_auth/sa_qi_transmitter.c
    :language: c
    :start-after: /* doc:start:qi-Authenticate */
    :end-before: /* doc:end:qi-Authenticate */


Building
=======================================================================

Build the example ``examples/se05x_qi_auth/sa_qi_auth`` for ``lpcxpresso55s69_cpu0`` with 
Zephyr build system. See :ref:`se05x_zephyr_integration` for details on how to build with Zephyr.


Porting
=======================================================================

The example can be built for different controllers from zephyr build system.
If you want to build for a different OS, you need to do these steps:

- Add platform specific port files in :file:`lib/platform/<board-name>` and include it in CMake for compilation. You would need to add timer, I2C and board port files. For reference see :file:`lib/platform/k64`.
- Add host crypto port for Qi authentication example in :file:`examples/se05x_qi_auth/sa_qi_auth/port` to enable host verification operations.

  .. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_auth/port/sa_qi_helper_port.c
	  :start-after: /* doc:start:qi-auth-port */
	  :end-before: /* doc:end:qi-auth-port */
	  :language: c


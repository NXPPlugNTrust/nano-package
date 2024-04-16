.. ..
..     Copyright 2022 NXP

.. .. highlight:: bat

.. _ex-se05x-qi-provisioning:

Secure Authenticator (Qi) Provisioning demo
#########################################################

This project is used to provision Qi credentials (ECDSA Key pair and Device certificate chain) inside 
the secure element.

.. warning:: This example is only for demonstration purpose. Maintaining 
    and provisioning the credentials should be done in a secure way.

The user should update the credentials ``qi_ec_priv_key``
and ``qi_certificate_chain`` in :file:`examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_credentials.c`

By default the demo will provision the credentials for Slot ID 0. The user can update the macro ``QI_PROVISIONING_SLOT_ID``
in :file:`examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_provisioning.h` to provision for a different slot:

.. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_provisioning.h
    :language: c
    :start-after: /* doc:start:qi-slot-id */
    :end-before: /* doc:end:qi-slot-id */

This demo requires the credentials to be provisioned using a management credential. 
In this example we use the demo key provisioned at ``EX_MANAGEMENT_CREDENTIAL_ID``
to open an AESKey session and provision the credentials. The user is expected to 
provision their own authentication key and use that for provisioning the Qi credentials 
by updating the auth object ID in :file:`examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_provisioning.c`:

.. literalinclude:: /../../../../examples/se05x_qi_auth/sa_qi_provisioning/sa_qi_provisioning.c
    :language: c
    :start-after: /* doc:start:aes-key-auth */
    :end-before: /* doc:end:aes-key-auth */

Pre-requisites
=======================================================================

- AESKey must be provisioned on the Secure Element before running this demo

Building the Demo
=======================================================================

Build the example ``examples/se05x_qi_auth/sa_qi_provisioning`` for ``lpcxpresso55s69_cpu0`` with 
Zephyr build system. See :ref:`se05x_zephyr_integration` for details on how to build with Zephyr.


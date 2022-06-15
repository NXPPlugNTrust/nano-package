/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_COMMON_H__
#define __SA_QI_COMMON_H__

#define QI_PROVISIONING_ID_BASE 0x51690000
#define QI_PROVISIONING_KEY_ID_OFFSET 0xE0
#define QI_PROVISIONING_CERT_ID_OFFSET 0xC0
#define MAX_SLOTS 0x4

/*
 * QI provisioning IDs are defined as QI_PROVISIONING_ID_BASE + offset +
 * SlotNumber Where, QI_PROVISIONING_ID_BASE is 0x51690000 offset is 0xE0 for EC
 * Private keys and 0xC0 for certificate chains SlotNumber is the slot for which
 * provisioning needs to be done
 */
#define QI_SLOT_ID_TO_KEY_ID(SLOT_ID) QI_PROVISIONING_ID_BASE + QI_PROVISIONING_KEY_ID_OFFSET + SLOT_ID
#define QI_SLOT_ID_TO_CERT_ID(SLOT_ID) QI_PROVISIONING_ID_BASE + QI_PROVISIONING_CERT_ID_OFFSET + SLOT_ID

#endif // __SA_QI_COMMON_H__

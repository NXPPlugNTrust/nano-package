/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_PROVISIONING_H_
#define __SA_QI_PROVISIONING_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

// #include "ex_sss_boot.h"
// #include "ex_sss_objid.h"
#include "sa_qi_common.h"
#include "se05x_APDU_apis.h"
#include "sm_port.h"
/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* doc:start:qi-slot-id */
/* Update the SLOT_ID to provision for another slot
 * Valid values are 0, 1, 2, 3
 */
#define QI_PROVISIONING_SLOT_ID 0
/* doc:end:qi-slot-id */

// #define EX_MANAGEMENT_CREDENTIAL_ID kEX_SSS_ObjID_APPLETSCP03_Auth

extern const uint8_t qi_ec_priv_key[];
extern const uint8_t qi_ec_pub_key[];
extern const uint8_t qi_certificate_chain[];
extern size_t qi_ec_priv_key_len;
extern size_t qi_ec_pub_key_len;
extern size_t qi_certificate_chain_len;

#endif /* __SA_QI_PROVISIONING_H_ */

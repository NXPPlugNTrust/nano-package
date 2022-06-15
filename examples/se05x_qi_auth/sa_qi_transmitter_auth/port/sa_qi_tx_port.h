/* Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SA_QI_TX_PORT_H__
#define __SA_QI_TX_PORT_H__

#include "sm_port.h"
#include "sa_qi_nano_helper_apis.h"

#include "se05x_APDU_apis.h"

#ifndef SSS_MALLOC
#define SSS_MALLOC sm_malloc
#endif // SSS_MALLOC

#ifndef SSS_FREE
#define SSS_FREE sm_free
#endif // SSS_FREE

#define BINARY_WRITE_MAX_LEN 128

#endif // __SA_QI_TX_PORT_H__

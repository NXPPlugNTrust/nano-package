/** @file sm_timer.h
 *  @brief Timer APIs.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SM_TIMER_H_INC
#define SM_TIMER_H_INC

/* ********************** Include files ********************** */
#include <stdint.h>

/* ********************** Funtion Prototypes ********************** */

#ifdef __cplusplus
extern "C" {
#endif

/* function used for delay loops */
uint32_t sm_initSleep(void);
void sm_sleep(uint32_t msec);
void sm_usleep(uint32_t microsec);

#ifdef __cplusplus
}
#endif

#endif // #ifndef SM_TIMER_H_INC

/*
 *
 * Copyright 2016-2018,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sm_timer.h>
#include <stdint.h>

#include "board.h"

#if defined(__GNUC__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

volatile uint32_t gtimer_kinetis_msticks; // counter for 1ms SysTicks

volatile int gusleep_delay;

#define CORR_FRDM_MCXA_ARMCC (1000 / 100)
#define CORR_FRDM_MCXA_ICCARM (1000 / 108)
#define CORR_FRDM_MCXA_GCC (1000 / 100)

#if defined(__ARMCC_VERSION)
#define CORRECTION_TOLERENCE CORR_FRDM_MCXA_ARMCC
#elif defined(__ICCARM__)
#define CORRECTION_TOLERENCE CORR_FRDM_MCXA_ICCARM
#else
#define CORRECTION_TOLERENCE CORR_FRDM_MCXA_GCC
#endif

void sm_usleep(uint32_t microsec)
{
    gusleep_delay = microsec * CORRECTION_TOLERENCE;
    while (gusleep_delay--) {
        __NOP();
    }
}

#if !defined(SDK_OS_FREE_RTOS) && !defined(SDK_OS_FREE_RTOS)

extern volatile uint32_t gtimer_kinetis_msticks; // counter for 1ms SysTicks

//__INLINE
static void systick_delay(const uint32_t delayTicks)
{
    volatile uint32_t currentTicks;
    if (delayTicks >= 0x7FFFFFFFu) {
        return;
    }

    __disable_irq();

    if ((gtimer_kinetis_msticks)&0x80000000u) {
        /* gtimer_kinetis_msticks has increased drastically (MSB is set),
         * So, reset gtimer_kinetis_msticks before it's too late to detect an
         * overflow. */
        gtimer_kinetis_msticks = 0;
    }

    currentTicks = gtimer_kinetis_msticks; // read current tick counter

    __DSB();
    __enable_irq();

    // Now loop until required number of ticks passes
    while ((gtimer_kinetis_msticks - currentTicks) <= delayTicks) {
#if !defined(IMX_RT)
#ifdef __WFI
        __WFI();
#endif
#endif
    }
}

#define WEAK __attribute__((weak))

WEAK void SysTick_Handler_APP_CB(void);
WEAK void SysTick_Handler_APP_CB()
{
}

/* interrupt handler for system ticks */
void SysTick_Handler(void)
{
    gtimer_kinetis_msticks += 1;
    SysTick_Handler_APP_CB();
}

/* initializes the system tick counter
 * return 0 on succes, 1 on failure */
uint32_t sm_initSleep()
{
    gtimer_kinetis_msticks = 0;
    SysTick_Config(SystemCoreClock / 1000);
    __enable_irq();
    return 0;
}

/**
 * Implement a blocking (for the calling thread) wait for a number of milliseconds.
 */
void sm_sleep(uint32_t msec)
{
#if SSS_HAVE_NXPNFCRDLIB
    //NXPNFCRDLIB also uses systick for a different purpose hence this is done
    sm_initSleep();
#endif
    /* if struck here check whether sm_initSleep() is called */
    systick_delay(MS_TO_TICKS(msec));
}
#endif /* !SDK_OS_FREE_RTOS && ! SDK_OS_FREE_RTOS */

#if defined(__GNUC__)
#pragma GCC pop_options
#endif

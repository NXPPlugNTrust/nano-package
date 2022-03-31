/*
 *
 * Copyright 2017-2020,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* Common header file used by Freedom K64F */

/* Exposed variables */
#define HAVE_KSDK_LED_APIS 1

//#include "ax_reset.h"
#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"
#include "sm_timer.h"

#if (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
#include "ksdk_mbedtls.h"
#endif

extern void axReset_HostConfigure(void);
extern void axReset_PowerUp(void);

#ifdef USE_SERGER_RTT
extern void nInit_segger_Log(void);
#endif

void platformInit()
{
    BOARD_BootClockRUN();
    BOARD_InitPins();
    BOARD_InitDebugConsole();

    LED_BLUE_INIT(1);
    LED_GREEN_INIT(1);
    LED_RED_INIT(1);
    LED_BLUE_ON();

    /* For DHCP Ethernet */
    SYSMPU_Type *base = SYSMPU;
    base->CESR &= ~SYSMPU_CESR_VLD_MASK;

    axReset_HostConfigure();
    axReset_PowerUp();

#if (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
    CRYPTO_InitHardware();
#if defined(FSL_FEATURE_SOC_SHA_COUNT) && (FSL_FEATURE_SOC_SHA_COUNT > 0)
    CLOCK_EnableClock(kCLOCK_Sha0);
    RESET_PeripheralReset(kSHA_RST_SHIFT_RSTn);
#endif /* SHA */
#endif /* defined(MBEDTLS) */
#ifdef USE_SERGER_RTT
    nInit_segger_Log();
#endif

    sm_initSleep();
}

void ex_sss_main_ksdk_boot_rtos_task()
{
}

void ex_sss_main_ksdk_success()
{
    LED_BLUE_OFF();
    LED_RED_OFF();
    LED_GREEN_ON();
}

void ex_sss_main_ksdk_failure()
{
    LED_BLUE_OFF();
    LED_RED_ON();
    LED_GREEN_OFF();
}

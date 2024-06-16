/*
 *
 * Copyright 2017-2020,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* Common header file used by MCXN947 */

/* Exposed variables */
#define HAVE_KSDK_LED_APIS 1

//#include "ax_reset.h"
#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"
#include "sm_timer.h"

#if (EX_SE05X_USE_MBEDTLS)
#include "els_pkc_mbedtls.h"
#endif

extern void axReset_HostConfigure(void);
extern void axReset_PowerUp(void);

#ifdef USE_SERGER_RTT
extern void nInit_segger_Log(void);
#endif

void platformInit()
{
    /* attach FRO 12M to FLEXCOMM4 (debug console) */
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom4Clk, 1u);
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    /* attach FROM 12M to FLEXCOMM2 */
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom2Clk, 1u);
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM2);

    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    //    LED_BLUE_INIT(1);
    //    LED_GREEN_INIT(1);
    //    LED_RED_INIT(1);
    //    LED_BLUE_ON();

    //    /* For DHCP Ethernet */
    //    SYSMPU_Type *base = SYSMPU;
    //    base->CESR &= ~SYSMPU_CESR_VLD_MASK;

    axReset_HostConfigure();
    axReset_PowerUp();

#if (EX_SE05X_USE_MBEDTLS)
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

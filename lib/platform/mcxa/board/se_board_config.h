/* Copyright 2023,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SE_BOARD_CONFIG_H
#define _SE_BOARD_CONFIG_H

#include "board.h"
#include "fsl_clock.h"

#if FSL_FEATURE_SOC_PIT_COUNT
#include "fsl_pit.h"
#endif /* FSL_FEATURE_SOC_PIT_COUNT */

/*
 * Platform based definitions for Enable pin
 * Define GPIO port for enable pin
 * Define Pin number on GPIO port for enable pin
 */

#define SE05X_ENA_HOST_PORT GPIO3
#define SE05X_ENA_HOST_PIN  12U

#if defined(FSL_FEATURE_SOC_I2C_COUNT) && FSL_FEATURE_SOC_I2C_COUNT > 0

#define AX_I2CM        I2C2
#define AX_I2C_CLK_SRC I2C2_CLK_SRC
#define AX_I2CM_IRQN   I2C2_IRQn

#endif /* FSL_FEATURE_SOC_I2C_COUNT */

#if FSL_FEATURE_SOC_PIT_COUNT
#define SE_PIT_RESET_HANDLER PIT0_IRQHandler
#define PIT_BASE_ADDR        PIT
#define PIT_IRQ_ID           PIT0_IRQn
/* Get source clock for PIT driver */
#define PIT_SOURCE_CLOCK CLOCK_GetFreq(kCLOCK_BusClk)
#endif /* FSL_FEATURE_SOC_PIT_COUNT */

/*
 * Where applicable, Configure the PINs on the Host
 *
 */
void se05x_host_configure(void);

/*
 * Where applicable, put SE in low power/standby mode
 *
 * Pre-Requistie: @ref se05x_host_configure has been called
 */
void se05x_host_powerdown(void);

/*
 * Where applicable, put SE in powered/active mode
 *
 * Pre-Requistie: @ref se05x_host_configure has been called
 */
void se05x_host_powerup(void);

#endif // _SE_BOARD_CONFIG_H

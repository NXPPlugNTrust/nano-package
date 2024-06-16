/* Copyright 2018,2020,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <board.h>
#include <stdio.h>

#include "fsl_gpio.h"
#include "sm_timer.h"
//#include "sm_types.h"
#include "fsl_common.h"

#include "smCom.h"
//#include "nxLog_smCom.h"

#define SE05X_ENA_HOST_PORT GPIO1
#define SE05X_ENA_HOST_PIN 21U

/*
 * Define Reset logic for reset pin on SE
 * Active high for SE050
 */
#define SE_RESET_LOGIC 1

void axReset_HostConfigure(void);
void axReset_ResetPluseDUT(void);
void axReset_PowerDown(void);
void axReset_PowerUp(void);
void axReset_HostUnconfigure(void);
void se05x_ic_reset(void);

void se05x_ic_reset()
{
    axReset_ResetPluseDUT();
    smComT1oI2C_ComReset(NULL);
    sm_usleep(3000);
    return;
}

/*
 * Where applicable, Configure the PINs on the Host
 *
 */
void axReset_HostConfigure()
{
    gpio_pin_config_t reset_pin_cfg = {kGPIO_DigitalOutput, SE_RESET_LOGIC};
    GPIO_PinInit(SE05X_ENA_HOST_PORT, SE05X_ENA_HOST_PIN, &reset_pin_cfg);
    return;
}

/*
 * Where applicable, PowerCycle the SE
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_ResetPluseDUT()
{
    axReset_PowerDown();
    sm_usleep(2000);
    axReset_PowerUp();
    return;
}

/*
 * Where applicable, put SE in low power/standby mode
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_PowerDown()
{
    GPIO_PinWrite(SE05X_ENA_HOST_PORT, SE05X_ENA_HOST_PIN, !SE_RESET_LOGIC);
}

/*
 * Where applicable, put SE in powered/active mode
 *
 * Pre-Requistie: @ref axReset_Configure has been called
 */
void axReset_PowerUp()
{
    GPIO_PinWrite(SE05X_ENA_HOST_PORT, SE05X_ENA_HOST_PIN, SE_RESET_LOGIC);
}

void axReset_HostUnconfigure()
{
    /* Nothing to be done */
    return;
}

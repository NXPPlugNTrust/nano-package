/** @file sm_i2c.c
 *  @brief I2C Interface functions.
 *
 * Copyright 2021,2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdlib.h>
#include "sm_i2c.h"
#include <zephyr/drivers/i2c.h>

#define PNT_LOG_REGISTER
#include "sm_port.h"

/* ********************** Defines ********************** */
#define SE05X_I2C_DEV i2c0
#define SE05X_I2C_DEV_ADDR 0x48

/* ********************** Global variables ********************** */
const struct device *i2c_dev = NULL;

/* ********************** Functions ********************** */

/**
* Opens the communication channel to I2C device
*/
i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    uint32_t i2c_cfg = I2C_SPEED_SET(I2C_SPEED_STANDARD) | I2C_MODE_CONTROLLER;

    i2c_dev = DEVICE_DT_GET(DT_NODELABEL(SE05X_I2C_DEV));
    if (!i2c_dev) {
        SMLOG_E("Error in i2c device_get_binding \n");
        return I2C_FAILED;
    }

    /* Test i2c_configure() */
    if (i2c_configure(i2c_dev, i2c_cfg)) {
        SMLOG_E("Error in i2c_configure \n");
        return I2C_FAILED;
    }

    return I2C_OK;
}

/**
* Closes the communication channel to I2C device
*/
void axI2CTerm(void *conn_ctx, int mode)
{
    return;
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pTx, unsigned short txLen)
{
    if (i2c_write(i2c_dev, pTx, txLen, SE05X_I2C_DEV_ADDR)) {
        return I2C_FAILED;
    }
    return I2C_OK;
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pRx, unsigned short rxLen)
{
    if (i2c_read(i2c_dev, pRx, rxLen, SE05X_I2C_DEV_ADDR)) {
        return I2C_FAILED;
    }
    return I2C_OK;
}

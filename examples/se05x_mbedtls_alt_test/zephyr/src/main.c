/** @file main.c
 *  @brief .
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* ********************** Extern functions ********************** */
extern int ex_se05x_mbedtls_alt_test();

int main(void)
{
    printk("Se05x Mbedtls Alt Test ! %s\n", CONFIG_BOARD);
    if (ex_se05x_mbedtls_alt_test() != 0) {
        printk("Se05x Mbedtls Alt Test Failed !\n");
    }
    else {
        printk("Se05x Mbedtls Alt Test Success !\n");
    }
    return 0;
}

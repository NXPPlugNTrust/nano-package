/** @file main.c
 *  @brief .
 *
 * Copyright 2021,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>

/* ********************** Extern functions ********************** */
extern int set_qi_key_cert(void);

int main(void)
{
    printk("Se05x Qi Provisioning Example ! %s\n", CONFIG_BOARD);
    if (set_qi_key_cert() != 0) {
        printk("SE05x Qi Provisioning Example Failed !\n");
    }
    else {
        printk("SE05x Qi Provisioning Example Success ! \n");
    }
    return 0;
}

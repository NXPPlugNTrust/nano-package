/** @file main.c
 *  @brief Unit tests.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include <stdio.h>
#include <stdint.h>
#include "test_se05x.h"
#include "sm_port.h"

#define LOG_I(...)        \
    SMLOG_I(__VA_ARGS__); \
    SMLOG_I("\n");
#define LOG_W(...)        \
    SMLOG_W(__VA_ARGS__); \
    SMLOG_W("\n");
#define LOG_E(...)        \
    SMLOG_E(__VA_ARGS__); \
    SMLOG_E("\n");

/* ********************** Extern functions ********************** */
extern void test_se05x(uint8_t *pass, uint8_t *fail, uint8_t *ignore);
#define test_main main
#define unit_test_setup_teardown(TEST_GROUP, TEST_SETUP, TEST_TEARDOWN) \
    TEST_SETUP();                                                       \
    TEST_GROUP();                                                       \
    TEST_TEARDOWN(NULL);

uint8_t gPass   = 0;
uint8_t gFail   = 0;
uint8_t gIgnore = 0;

void test_fail(void)
{
    // Do nothing
}

void test_run_se05x_nist256(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_nist256(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_nist256");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_nist256");
    }
    else {
        LOG_W(" IGNORE - test_se05x_nist256");
    }
}
void test_run_se05x_nist256_ecdsa(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_nist256_ecdsa(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_nist256_ecdsa");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_nist256_ecdsa");
    }
    else {
        LOG_W(" IGNORE - test_se05x_nist256_ecdsa");
    }
}
void test_run_se05x_bin_objects(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_bin_objects(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_bin_objects");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_bin_objects");
    }
    else {
        LOG_W(" IGNORE - test_se05x_bin_objects");
    }
}
void test_run_se05x_aes(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_aes(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_aes");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_aes");
    }
    else {
        LOG_W(" IGNORE - test_se05x_aes");
    }
}
void test_run_se05x_misc(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_misc(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_misc");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_misc");
    }
    else {
        LOG_W(" IGNORE - test_se05x_misc");
    }
}
void test_run_se05x_nist256_ecdh(void)
{
    uint8_t pass   = gPass;
    uint8_t fail   = gFail;
    uint8_t ignore = gIgnore;
    test_se05x_nist256_ecdh(&se05x_session, &gPass, &gFail, &gIgnore);
    if (gFail > fail) {
        LOG_E(" FAIL - test_se05x_nist256_ecdh");
    }
    else if (gPass > pass) {
        LOG_W(" PASS - test_se05x_nist256_ecdh");
    }
    else {
        LOG_W(" IGNORE - test_se05x_nist256_ecdh");
    }
}

void test_main(void)
{
    LOG_W("Running test suite framework_tests");
    LOG_W("===================================================================");

    unit_test_setup_teardown(test_run_se05x_nist256, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_nist256, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_nist256_ecdsa, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_bin_objects, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_aes, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_misc, test_setup, test_teardown);
    unit_test_setup_teardown(test_run_se05x_nist256_ecdh, test_setup, test_teardown);

    LOG_W("Test suite framework_tests completed");
    LOG_W("===================================================================");
}

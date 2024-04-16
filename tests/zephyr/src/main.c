/** @file main.c
 *  @brief Unit tests.
 *
 * Copyright 2022,2024 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include "test_se05x.h"

void test_fail(void)
{
    ztest_test_fail();
}

void test_run_se05x_nist256(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256 failed");
}
void test_run_se05x_nist256_ecdsa(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256_ecdsa(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256_ecdsa failed");
}
void test_run_se05x_bin_objects(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_bin_objects(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_bin_objects failed");
}
void test_run_se05x_aes(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_aes(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_aes failed");
}
void test_run_se05x_misc(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_misc(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_misc failed");
}
void test_run_se05x_nist256_ecdh(void)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256_ecdh(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256_ecdh failed");
}

void test_main(void)
{
    ztest_test_suite(framework_tests,
        ztest_unit_test_setup_teardown(test_run_se05x_nist256, test_setup, test_teardown),
        ztest_unit_test_setup_teardown(test_run_se05x_nist256_ecdsa, test_setup, test_teardown),
        ztest_unit_test_setup_teardown(test_run_se05x_bin_objects, test_setup, test_teardown),
        ztest_unit_test_setup_teardown(test_run_se05x_aes, test_setup, test_teardown),
        ztest_unit_test_setup_teardown(test_run_se05x_misc, test_setup, test_teardown),
        ztest_unit_test_setup_teardown(test_run_se05x_nist256_ecdh, test_setup, test_teardown));

    ztest_run_test_suite(framework_tests);
}

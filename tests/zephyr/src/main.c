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

ZTEST_SUITE(se05x_tests, NULL, test_setup, NULL, NULL, test_teardown);

ZTEST(se05x_tests, test_run_se05x_nist256_ecdh)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256_ecdh(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256_ecdh failed");
}

ZTEST(se05x_tests, test_run_se05x_misc)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_misc(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_misc failed");
}

ZTEST(se05x_tests, test_run_se05x_aes)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_aes(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_aes failed");
}

ZTEST(se05x_tests, test_run_se05x_bin_objects)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_bin_objects(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_bin_objects failed");
}

ZTEST(se05x_tests, test_run_se05x_nist256_ecdsa)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256_ecdsa(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256_ecdsa failed");
}

ZTEST(se05x_tests, test_run_se05x_nist256)
{
    uint8_t pass   = 0;
    uint8_t fail   = 0;
    uint8_t ignore = 0;
    test_se05x_nist256(&se05x_session, &pass, &fail, &ignore);
    zassert_equal(fail, 0, "test_run_se05x_nist256 failed");
}

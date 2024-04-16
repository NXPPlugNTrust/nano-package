/*
 * Copyright 2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NX_LOG_APP_H__
#define __NX_LOG_APP_H__

#define LOG_D(...)        \
    SMLOG_D("App: ");     \
    SMLOG_D(__VA_ARGS__); \
    SMLOG_D("\n")
#define LOG_W(...)        \
    SMLOG_W("App: ");     \
    SMLOG_W(__VA_ARGS__); \
    SMLOG_W("\n")
#define LOG_I(...)        \
    SMLOG_I("App: ");     \
    SMLOG_I(__VA_ARGS__); \
    SMLOG_I("\n")
#define LOG_E(...)        \
    SMLOG_E("App: ");     \
    SMLOG_E(__VA_ARGS__); \
    SMLOG_E("\n")
#define LOG_MAU8_D(...) \
    SMLOG_D("App: ");   \
    SMLOG_MAU8_D(__VA_ARGS__);
#define LOG_MAU8_I(...) // SMLOG_I("App: "); SMLOG_MAU8_I(__VA_ARGS__);

#endif /* __NX_LOG_APP_H__ */

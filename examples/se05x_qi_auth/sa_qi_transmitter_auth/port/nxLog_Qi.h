/*
 *
 * Copyright 2018 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NX_LOG_QI_H
#define NX_LOG_QI_H

#define LOG_D(...)        \
    SMLOG_D("Qi:  ");     \
    SMLOG_D(__VA_ARGS__); \
    SMLOG_D("\n")
#define LOG_W(...)        \
    SMLOG_W("Qi:  ");     \
    SMLOG_W(__VA_ARGS__); \
    SMLOG_W("\n")
#define LOG_I(...)        \
    SMLOG_I("Qi:  ");     \
    SMLOG_I(__VA_ARGS__); \
    SMLOG_I("\n")
#define LOG_E(...)        \
    SMLOG_E("Qi:  ");     \
    SMLOG_E(__VA_ARGS__); \
    SMLOG_E("\n")
#define LOG_MAU8_D(...)        \
    SMLOG_D("Qi:  ");          \
    SMLOG_MAU8_D(__VA_ARGS__); \
    SMLOG_D("\n")
#define LOG_MAU8_I(...) //SMLOG_I("Qi:  "); SMLOG_MAU8_I(__VA_ARGS__); SMLOG_I("\n")

#endif /* NX_LOG_QI_H */

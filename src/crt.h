#ifndef AWS_CRT_CRT_H
#define AWS_CRT_CRT_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* clang-format off */
#include <aws/common/common.h> /* must be present so api.h knows about inttypes and allocators */
#include "api.h"
/* clang-format on */

/* Utility functions for use within this library */

/* Get default allocator */
struct aws_allocator *aws_crt_allocator(void);

#endif /* AWS_CRT_CRT_H */

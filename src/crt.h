#ifndef AWS_CRT_CRT_H
#define AWS_CRT_CRT_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "api.h"

/* Utility functions for use within this library */

/* Get default allocator */
struct aws_allocator *aws_crt_allocator(void);

#endif /* AWS_CRT_CRT_H */

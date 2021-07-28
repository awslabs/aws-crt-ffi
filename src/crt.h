#ifndef AWS_CRT_CRT_H
#define AWS_CRT_CRT_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* clang-format off */
#include <aws/common/common.h> /* must be present so api.h knows about inttypes and allocators */
#include <aws/common/ref_count.h>
#include "api.h"
/* clang-format on */

/**
 * Every object that can be vended externally (into a consuming library/language) should
 * have a resource as its first member. This acts as a refcount and a place to store associated
 * user data with any given object. Any object whose ownership is assumed via aws_crt_resource_new()
 * will be freed by aws_crt_resource_release() when its refcount hits 0.
 */
typedef struct _aws_crt_resource {
    struct aws_ref_count rc;
    void *user_data;
    void (*dtor)(void *);
} aws_crt_resource;

/**
 * Take ownership of object memory, and initialize the associated resource.
 * NOTE: Whatever structure is passed in here MUST have an aws_crt_resource as its first member
 */
void *aws_crt_resource_new(void *object);
void aws_crt_resource_init(aws_crt_resource *resource);

void aws_crt_resource_acquire(aws_crt_resource *resource);
void aws_crt_resource_release(aws_crt_resource *resource);

#endif /* AWS_CRT_CRT_H */

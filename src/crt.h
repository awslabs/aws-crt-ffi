#ifndef AWS_CRT_CRT_H
#define AWS_CRT_CRT_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* clang-format off */
#include <aws/common/common.h> /* must be present so api.h knows about inttypes and allocators */
#include <aws/common/ref_count.h>
#include <aws/common/logging.h>
#include "api.h"
/* clang-format on */

#define AWS_CRT_FFI_PACKAGE_ID 12
enum aws_crt_ffi_errors {
    AWS_ERROR_FFI_GENERAL = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_CRT_FFI_PACKAGE_ID),
    AWS_ERROR_FFI_END_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_CRT_FFI_PACKAGE_ID),
};

enum aws_crt_ffi_log_subject {
    AWS_LS_CRT_HOST_LANGUAGE = AWS_LOG_SUBJECT_BEGIN_RANGE(AWS_CRT_FFI_PACKAGE_ID),
    AWS_LS_CRT_FFI,
    AWS_LS_CRT_LAST = AWS_LOG_SUBJECT_END_RANGE(AWS_CRT_FFI_PACKAGE_ID),
};

void aws_crt_log_init(void);

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
void *aws_crt_resource_new(size_t size_of_object);
void aws_crt_resource_init(aws_crt_resource *resource);

void aws_crt_resource_acquire(aws_crt_resource *resource);
void aws_crt_resource_release(aws_crt_resource *resource);

#endif /* AWS_CRT_CRT_H */

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/auth.h>
#include <aws/cal/cal.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/compression/compression.h>
#include <aws/http/http.h>

struct aws_allocator *aws_crt_allocator(void) {
    return aws_default_allocator();
}

void aws_crt_init(void) {
    struct aws_allocator *allocator = aws_crt_allocator();
    aws_common_library_init(allocator);
    aws_io_library_init(allocator);
    aws_compression_library_init(allocator);
    aws_http_library_init(allocator);
    aws_cal_library_init(allocator);
    aws_auth_library_init(allocator);
}

void aws_crt_clean_up(void) {
    aws_auth_library_clean_up();
    aws_cal_library_clean_up();
    aws_http_library_clean_up();
    aws_compression_library_clean_up();
    aws_io_library_clean_up();
    aws_common_library_clean_up();
}

int aws_crt_test_error(int err) {
    return aws_raise_error(err);
}

struct aws_crt_test_struct *aws_crt_test_pointer_error(void) {
    aws_raise_error(AWS_ERROR_OOM);
    return NULL;
}

void *aws_crt_mem_acquire(size_t size) {
    return aws_mem_acquire(aws_crt_allocator(), size);
}

void aws_crt_mem_release(void *ptr) {
    aws_mem_release(aws_crt_allocator(), ptr);
}

aws_crt_mutex *aws_crt_mutex_new(void) {
    aws_crt_mutex *mutex = aws_crt_mem_acquire(sizeof(aws_crt_mutex));
    aws_mutex_init(mutex);
    return mutex;
}

void aws_crt_mutex_delete(aws_crt_mutex *mutex) {
    aws_mutex_clean_up(mutex);
    aws_crt_mem_release(mutex);
}

void aws_crt_mutex_lock(aws_crt_mutex *mutex) {
    aws_mutex_lock(mutex);
}

void aws_crt_mutex_unlock(aws_crt_mutex *mutex) {
    aws_mutex_unlock(mutex);
}

void *aws_crt_current_thread_id(void) {
    return (void*)aws_thread_current_thread_id();
}

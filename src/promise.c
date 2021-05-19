/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "api.h"

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>
#include <aws/common/condition_variable.h>

struct _aws_crt_promise {
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    /* atomic allows for observability without holding the lock */
    struct aws_atomic_var complete;
    int error_code;
    void *value;
};

aws_crt_promise *aws_crt_promise_new(void) {
    aws_crt_promise *promise = aws_crt_mem_acquire(sizeof(aws_crt_promise));
    aws_mutex_init(&promise->mutex);
    aws_condition_variable_init(&promise->cv);
    aws_atomic_init_int(&promise->complete,0);
    promise->error_code = 0;
    promise->value = NULL;
    return promise;
}

void aws_crt_promise_delete(aws_crt_promise *promise) {
    aws_condition_variable_clean_up(&promise->cv);
    aws_mutex_clean_up(&promise->mutex);
    aws_crt_mem_release(promise);
}

static bool s_promise_completed(void *user_data) {
    aws_crt_promise *promise = user_data;
    return aws_crt_promise_completed(promise);
}

_Bool aws_crt_promise_wait(aws_crt_promise *promise) {
    aws_mutex_lock(&promise->mutex);
    aws_condition_variable_wait_pred(&promise->cv, &promise->mutex, s_promise_completed, promise);
    aws_mutex_unlock(&promise->mutex);
    AWS_FATAL_ASSERT(aws_crt_promise_completed(promise));
    return promise->error_code == 0;
}

_Bool aws_crt_promise_wait_for(aws_crt_promise *promise, size_t milliseconds) {
    aws_mutex_lock(&promise->mutex);
    aws_condition_variable_wait_for_pred(&promise->cv, &promise->mutex, milliseconds, s_promise_completed, promise);
    aws_mutex_unlock(&promise->mutex);
    return aws_crt_promise_completed(promise) && promise->error_code == 0;
}

_Bool aws_crt_promise_completed(aws_crt_promise *promise) {
    return aws_atomic_load_int(&promise->complete) != 0;
}

void aws_crt_promise_complete(aws_crt_promise *promise, void *value) {
    aws_mutex_lock(&promise->mutex);
    aws_atomic_store_int(&promise->complete, 1);
    promise->value = value;
    aws_mutex_unlock(&promise->mutex);
    aws_condition_variable_notify_one(&promise->cv);
}

void aws_crt_promise_fail(aws_crt_promise *promise, int error_code) {
    aws_atomic_store_int(&promise->complete, 1);
    promise->error_code = error_code;
    aws_condition_variable_notify_one(&promise->cv);
}

int aws_crt_promise_error_code(aws_crt_promise *promise) {
    return promise->error_code;
}

void *aws_crt_promise_value(aws_crt_promise *promise) {
    AWS_FATAL_ASSERT(aws_crt_promise_completed(promise));
    return promise->value;
}

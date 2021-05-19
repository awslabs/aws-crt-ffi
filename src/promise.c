/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "api.h"

#include <aws/common/atomics.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>

struct _aws_crt_promise {
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    bool complete;
    int error_code;
    void *value;
    void (*dtor)(void *);
};

aws_crt_promise *aws_crt_promise_new(void) {
    aws_crt_promise *promise = aws_crt_mem_acquire(sizeof(aws_crt_promise));
    memset(promise, 0, sizeof(*promise));
    aws_mutex_init(&promise->mutex);
    aws_condition_variable_init(&promise->cv);
    return promise;
}

void aws_crt_promise_delete(aws_crt_promise *promise) {
    aws_condition_variable_clean_up(&promise->cv);
    aws_mutex_clean_up(&promise->mutex);
    if (promise->value && promise->dtor) {
        promise->dtor(promise->value);
    }
    aws_crt_mem_release(promise);
}

static bool s_promise_completed(void *user_data) {
    aws_crt_promise *promise = user_data;
    return aws_crt_promise_completed(promise);
}

_Bool aws_crt_promise_wait(aws_crt_promise *promise) {
    aws_mutex_lock(&promise->mutex);
    aws_condition_variable_wait_pred(&promise->cv, &promise->mutex, s_promise_completed, promise);
    const int error_code = promise->error_code;
    aws_mutex_unlock(&promise->mutex);
    return error_code == 0;
}

_Bool aws_crt_promise_wait_for(aws_crt_promise *promise, size_t milliseconds) {
    aws_mutex_lock(&promise->mutex);
    aws_condition_variable_wait_for_pred(&promise->cv, &promise->mutex, (int64_t)milliseconds, s_promise_completed, promise);
    aws_mutex_unlock(&promise->mutex);
    return aws_crt_promise_completed(promise) && promise->error_code == 0;
}

_Bool aws_crt_promise_completed(aws_crt_promise *promise) {
    aws_mutex_lock(&promise->mutex);
    const bool complete = promise->complete;
    aws_mutex_unlock(&promise->mutex);
    return complete;
}

void aws_crt_promise_complete(aws_crt_promise *promise, void *value, void (*dtor)(void*)) {
    AWS_FATAL_ASSERT(!aws_crt_promise_completed(promise) && "aws_crt_promise_complete: cannot complete a promise more than once");
    aws_mutex_lock(&promise->mutex);
    promise->value = value;
    promise->dtor = dtor;
    promise->complete = true;
    aws_mutex_unlock(&promise->mutex);
    aws_condition_variable_notify_one(&promise->cv);
}

void aws_crt_promise_fail(aws_crt_promise *promise, int error_code) {
    AWS_FATAL_ASSERT(!aws_crt_promise_completed(promise) && "aws_crt_promise_fail: cannot fail a promise more than once");
    aws_mutex_lock(&promise->mutex);
    promise->error_code = error_code;
    promise->complete = true;
    aws_mutex_unlock(&promise->mutex);
    aws_condition_variable_notify_one(&promise->cv);
}

int aws_crt_promise_error_code(aws_crt_promise *promise) {
    AWS_FATAL_ASSERT(aws_crt_promise_completed(promise));
    aws_mutex_lock(&promise->mutex);
    int error_code = promise->error_code;
    aws_mutex_unlock(&promise->mutex);
    return error_code;
}

void *aws_crt_promise_value(aws_crt_promise *promise) {
    AWS_FATAL_ASSERT(aws_crt_promise_completed(promise));
    return promise->value;
}

void *aws_crt_promise_take_value(aws_crt_promise *promise) {
    AWS_FATAL_ASSERT(aws_crt_promise_completed(promise));
    void *value = promise->value;
    promise->value = NULL;
    promise->dtor = NULL;
    return value;
}

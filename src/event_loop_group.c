/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/io/event_loop.h>

struct _aws_crt_event_loop_group_options {
    aws_crt_resource resource;
    uint16_t max_threads;
};

struct _aws_crt_event_loop_group {
    aws_crt_resource resource;
    struct aws_event_loop_group *elg;
};

aws_crt_event_loop_group_options *aws_crt_event_loop_group_options_new() {
    return aws_crt_resource_new(aws_crt_mem_calloc(1, sizeof(aws_crt_event_loop_group_options)));
}

void aws_crt_event_loop_group_options_release(aws_crt_event_loop_group_options *options) {
    aws_mem_release(aws_crt_default_allocator(), options);
}

void aws_crt_event_loop_group_options_set_max_threads(aws_crt_event_loop_group_options *options, uint16_t max_threads) {
    options->max_threads = max_threads;
}

void elg_shutdown(void *user_data) {
    aws_crt_event_loop_group *elg = user_data;
    aws_crt_resource_release(&elg->resource);
}

aws_crt_event_loop_group *aws_crt_event_loop_group_new(const aws_crt_event_loop_group_options *options) {
    aws_crt_event_loop_group *elg = aws_crt_resource_new(aws_crt_mem_calloc(1, sizeof(aws_crt_event_loop_group)));
    struct aws_shutdown_callback_options shutdown_options = {
        .shutdown_callback_fn = elg_shutdown,
        .shutdown_callback_user_data = elg,
    };
    elg->elg = aws_event_loop_group_new_default(
        aws_crt_default_allocator(), options->max_threads, &shutdown_options);
    return elg;
}

aws_crt_event_loop_group *aws_crt_event_loop_group_acquire(aws_crt_event_loop_group *elg) {
    aws_event_loop_group_acquire(elg->elg);
    return elg;
}

void aws_crt_event_loop_group_release(aws_crt_event_loop_group *elg) {
    aws_event_loop_group_release(elg->elg);
}

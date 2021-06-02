/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/io/event_loop.h>

struct _aws_crt_event_loop_group_options {
    uint16_t max_threads;
};

aws_crt_event_loop_group_options *aws_crt_event_loop_group_options_new() {
    aws_crt_event_loop_group_options *options =
        aws_mem_acquire(aws_crt_default_allocator(), sizeof(aws_crt_event_loop_group_options));
    AWS_FATAL_ASSERT(options != NULL);
    return options;
}

void aws_crt_event_loop_group_options_release(aws_crt_event_loop_group_options *options) {
    aws_mem_release(aws_crt_default_allocator(), options);
}

void aws_crt_event_loop_group_options_set_max_threads(aws_crt_event_loop_group_options *options, uint16_t max_threads) {
    options->max_threads = max_threads;
}

aws_crt_event_loop_group *aws_crt_event_loop_group_new(const aws_crt_event_loop_group_options *options) {
    return aws_event_loop_group_new_default(aws_crt_default_allocator(), options->max_threads, NULL /*shutdown_options*/);
}

aws_crt_event_loop_group *aws_crt_event_loop_group_acquire(aws_crt_event_loop_group *elg) {
    return aws_event_loop_group_acquire(elg);
}

void aws_crt_event_loop_group_release(aws_crt_event_loop_group *elg) {
    aws_event_loop_group_release(elg);
}

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/io/event_loop.h>

struct aws_event_loop_group *
aws_crt_event_loop_group_new(uint16_t max_threads) {
  return aws_event_loop_group_new_default(aws_crt_allocator(), max_threads,
                                          NULL /*shutdown_options*/);
}

void aws_crt_event_loop_group_release(struct aws_event_loop_group *elg) {
  aws_event_loop_group_release(elg);
}

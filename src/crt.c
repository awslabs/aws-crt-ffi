/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/auth.h>
#include <aws/cal/cal.h>
#include <aws/compression/compression.h>
#include <aws/http/http.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>

struct aws_allocator *s_crt_allocator = NULL;

struct aws_allocator *init_allocator(void) {
    /* Default to a small block allocator in front of the CRT default allocator */
    s_crt_allocator = aws_small_block_allocator_new(aws_default_allocator(), true);

    /* Check to see if the user has requested memory tracing */
    enum aws_mem_trace_level trace_level = AWS_MEMTRACE_NONE;
    struct aws_string *mem_tracing_key = aws_string_new_from_c_str(s_crt_allocator, "AWS_CRT_MEMORY_TRACING");
    struct aws_string *mem_tracing_value = NULL;
    if (aws_get_environment_value(s_crt_allocator, mem_tracing_key, &mem_tracing_value) == AWS_OP_SUCCESS && mem_tracing_value != NULL) {
        int tracing_value = (int)strtol((const char *)aws_string_bytes(mem_tracing_value), NULL, 10);
        if (tracing_value < 0 || tracing_value > AWS_MEMTRACE_STACKS) {
            tracing_value = 0;
        }
        trace_level = (enum aws_mem_trace_level)tracing_value;
    }
    aws_string_destroy(mem_tracing_key);
    aws_string_destroy(mem_tracing_value);

    s_crt_allocator = aws_mem_tracer_new(s_crt_allocator, NULL, trace_level, 16);
    return s_crt_allocator;
}

void shutdown_allocator(void) {
    /* destroy/unwrap traced allocator, then destroy it */
    s_crt_allocator = aws_mem_tracer_destroy(s_crt_allocator);
    aws_small_block_allocator_destroy(s_crt_allocator);
    s_crt_allocator = NULL;
}

aws_crt_allocator *aws_crt_default_allocator(void) {
    return s_crt_allocator;
}

void aws_crt_init(void) {
    init_allocator();
    aws_common_library_init(aws_crt_default_allocator());
    aws_io_library_init(aws_crt_default_allocator());
    aws_compression_library_init(aws_crt_default_allocator());
    aws_http_library_init(aws_crt_default_allocator());
    aws_cal_library_init(aws_crt_default_allocator());
    aws_auth_library_init(aws_crt_default_allocator());
}

void aws_crt_clean_up(void) {
    aws_auth_library_clean_up();
    aws_cal_library_clean_up();
    aws_http_library_clean_up();
    aws_compression_library_clean_up();
    aws_io_library_clean_up();
    aws_common_library_clean_up();
    shutdown_allocator();
}

int aws_crt_test_error(int err) {
    return aws_raise_error(err);
}

struct aws_crt_test_struct *aws_crt_test_pointer_error(void) {
    aws_raise_error(AWS_ERROR_OOM);
    return NULL;
}

void *aws_crt_mem_acquire(size_t size) {
    return aws_mem_acquire(aws_crt_default_allocator(), size);
}

void *aws_crt_mem_calloc(size_t element_count, size_t element_size) {
    return aws_mem_calloc(aws_crt_default_allocator(), element_count, element_size);
}

void aws_crt_mem_release(void *ptr) {
    aws_mem_release(aws_crt_default_allocator(), ptr);
}

uint64_t aws_crt_mem_bytes(void) {
    return aws_mem_tracer_bytes(s_crt_allocator);
}

uint64_t aws_crt_mem_count(void) {
    return aws_mem_tracer_count(s_crt_allocator);
}

void aws_crt_mem_dump(void) {
    aws_mem_tracer_dump(s_crt_allocator);
}

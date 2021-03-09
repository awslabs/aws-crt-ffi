/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/credentials.h>
#include <aws/common/string.h>

struct _aws_crt_credentials_options {
    struct aws_byte_buf access_key_id;
    struct aws_byte_buf secret_access_key;
    struct aws_byte_buf session_token;
    uint64_t expiration_timepoint_seconds;
};

aws_crt_credentials_options *aws_crt_credentials_options_new() {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_options));
}

void aws_crt_credentials_options_release(aws_crt_credentials_options *options) {
    aws_byte_buf_clean_up_secure(&options->access_key_id);
    aws_byte_buf_clean_up_secure(&options->secret_access_key);
    aws_byte_buf_clean_up_secure(&options->session_token);
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_options_set_access_key_id(aws_crt_credentials_options *options, const char *access_key_id) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(access_key_id);
    aws_byte_buf_init_copy(&options->access_key_id, aws_crt_allocator(), &input);
}

void aws_crt_credentials_options_set_secret_access_key(
    aws_crt_credentials_options *options,
    const char *secret_access_key) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(secret_access_key);
    aws_byte_buf_init_copy(&options->secret_access_key, aws_crt_allocator(), &input);
}

void aws_crt_credentials_options_set_session_token(aws_crt_credentials_options *options, const char *session_token) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(session_token);
    aws_byte_buf_init_copy(&options->session_token, aws_crt_allocator(), &input);
}

void aws_crt_credentials_options_set_expiration_timepoint_seconds(
    aws_crt_credentials_options *options,
    uint64_t expiration_timepoint_seconds) {
    options->expiration_timepoint_seconds = expiration_timepoint_seconds;
}

aws_crt_credentials *aws_crt_credentials_new(aws_crt_credentials_options *options) {
    struct aws_allocator *allocator = aws_crt_allocator();
    return aws_credentials_new(
        allocator,
        aws_byte_cursor_from_buf(&options->access_key_id),
        aws_byte_cursor_from_buf(&options->secret_access_key),
        aws_byte_cursor_from_buf(&options->session_token),
        options->expiration_timepoint_seconds);
}

void aws_crt_credentials_release(struct aws_credentials *credentials) {
    aws_credentials_release(credentials);
}

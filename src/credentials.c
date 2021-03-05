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

aws_crt_credentials *aws_crt_credentials_new(aws_crt_credentials_options *options) {
    struct aws_allocator *allocator = aws_crt_allocator();
    return aws_credentials_new(
        allocator,
        aws_byte_cursor_from_buf(&options->access_key_id),
        aws_byte_cursor_from_buf(&options->secret_access_key),
        aws_byte_cursor_from_buf(&options->session_token),
        options->expiration_timepoint_seconds);
}

struct aws_byte_cursor aws_crt_credentials_get_access_key_id(const struct aws_credentials *credentials) {
    return aws_credentials_get_access_key_id(credentials);
}

struct aws_byte_cursor aws_crt_credentials_get_secret_access_key(const struct aws_credentials *credentials) {
    return aws_credentials_get_secret_access_key(credentials);
}

struct aws_byte_cursor aws_crt_credentials_get_session_token(const struct aws_credentials *credentials) {
    return aws_credentials_get_session_token(credentials);
}

uint64_t aws_crt_credentials_get_expiration_timepoint_seconds(const struct aws_credentials *credentials) {
    return aws_credentials_get_expiration_timepoint_seconds(credentials);
}

void aws_crt_credentials_release(struct aws_credentials *credentials) {
    aws_credentials_release(credentials);
}

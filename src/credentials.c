/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/credentials.h>
#include <aws/common/string.h>

struct aws_credentials *aws_crt_credentials_new(
    const char *access_key_id,
    const char *secret_access_key,
    const char *session_token,
    uint64_t expiration_timepoint_seconds) {

    struct aws_allocator *allocator = aws_crt_allocator();
    return aws_credentials_new(
        allocator,
        aws_byte_cursor_from_c_str(access_key_id),
        aws_byte_cursor_from_c_str(secret_access_key),
        aws_byte_cursor_from_c_str(session_token),
        expiration_timepoint_seconds);
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

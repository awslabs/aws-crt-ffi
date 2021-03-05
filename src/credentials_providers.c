/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/credentials.h>
#include <aws/common/string.h>

struct _aws_crt_credentials_provider_static_options {
    struct aws_credentials_provider_static_options options;
    struct aws_byte_buf access_key_id;
    struct aws_byte_buf secret_access_key;
    struct aws_byte_buf session_token;
};

aws_crt_credentials_provider_static_options *
    aws_crt_credentials_provider_static_options_new(void) {
    aws_crt_credentials_provider_static_options *options = aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_static_options));
    return options;
}

void aws_crt_credentials_provider_options_static_release(
    aws_crt_credentials_provider_static_options *options){
    aws_byte_buf_clean_up_secure(&options->access_key_id);
    aws_byte_buf_clean_up_secure(&options->secret_access_key);
    aws_byte_buf_clean_up_secure(&options->session_token);
    aws_mem_release(aws_crt_allocator(), options);
}

const char *aws_crt_credentials_provider_static_options_get_access_key_id(
    aws_crt_credentials_provider_static_options *options){
    return (const char*)options->access_key_id.buffer;
}

void aws_crt_credentials_provider_static_options_set_access_key_id(
    aws_crt_credentials_provider_static_options *options,
    const char *access_key_id){
    struct aws_byte_buf input = aws_byte_buf_from_c_str(access_key_id);
    aws_byte_buf_init_copy(&options->access_key_id, aws_crt_allocator(), &input);
}

const char *aws_crt_credentials_provider_static_options_get_secret_access_key(
    aws_crt_credentials_provider_static_options *options){
    return (const char*)options->secret_access_key.buffer;
}

void aws_crt_credentials_provider_static_options_set_secret_access_key(
    aws_crt_credentials_provider_static_options *options,
    const char *secret_access_key){
    struct aws_byte_buf input = aws_byte_buf_from_c_str(secret_access_key);
    aws_byte_buf_init_copy(&options->secret_access_key, aws_crt_allocator(), &input);
}

const char *aws_crt_credentials_provider_static_options_get_session_token(
    aws_crt_credentials_provider_static_options *options){
    return (const char*)options->session_token.buffer;
}

void aws_crt_credentials_provider_static_options_set_session_token(
    aws_crt_credentials_provider_static_options *options,
    const char *session_token){
    struct aws_byte_buf input = aws_byte_buf_from_c_str(session_token);
    aws_byte_buf_init_copy(&options->session_token, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_static_new(
    aws_crt_credentials_provider_static_options *options){
    options->options.access_key_id = aws_byte_cursor_from_buf(&options->access_key_id);
    options->options.secret_access_key = aws_byte_cursor_from_buf(&options->secret_access_key);
    options->options.session_token = aws_byte_cursor_from_buf(&options->session_token);
    aws_crt_credentials_provider *credentials_provider = aws_credentials_provider_new_static(aws_crt_allocator(), &options->options);
    return credentials_provider;
}

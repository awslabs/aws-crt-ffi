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

aws_crt_credentials_provider_static_options *aws_crt_credentials_provider_static_options_new(void) {
    aws_crt_credentials_provider_static_options *options =
        aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_static_options));
    return options;
}

void aws_crt_credentials_provider_options_static_release(aws_crt_credentials_provider_static_options *options) {
    aws_byte_buf_clean_up_secure(&options->access_key_id);
    aws_byte_buf_clean_up_secure(&options->secret_access_key);
    aws_byte_buf_clean_up_secure(&options->session_token);
    aws_mem_release(aws_crt_allocator(), options);
}

const char *aws_crt_credentials_provider_static_options_get_access_key_id(
    aws_crt_credentials_provider_static_options *options) {
    return (const char *)options->access_key_id.buffer;
}

void aws_crt_credentials_provider_static_options_set_access_key_id(
    aws_crt_credentials_provider_static_options *options,
    const char *access_key_id) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(access_key_id);
    aws_byte_buf_init_copy(&options->access_key_id, aws_crt_allocator(), &input);
}

const char *aws_crt_credentials_provider_static_options_get_secret_access_key(
    aws_crt_credentials_provider_static_options *options) {
    return (const char *)options->secret_access_key.buffer;
}

void aws_crt_credentials_provider_static_options_set_secret_access_key(
    aws_crt_credentials_provider_static_options *options,
    const char *secret_access_key) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(secret_access_key);
    aws_byte_buf_init_copy(&options->secret_access_key, aws_crt_allocator(), &input);
}

const char *aws_crt_credentials_provider_static_options_get_session_token(
    aws_crt_credentials_provider_static_options *options) {
    return (const char *)options->session_token.buffer;
}

void aws_crt_credentials_provider_static_options_set_session_token(
    aws_crt_credentials_provider_static_options *options,
    const char *session_token) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(session_token);
    aws_byte_buf_init_copy(&options->session_token, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_static_new(
    aws_crt_credentials_provider_static_options *options) {
    options->options.access_key_id = aws_byte_cursor_from_buf(&options->access_key_id);
    options->options.secret_access_key = aws_byte_cursor_from_buf(&options->secret_access_key);
    options->options.session_token = aws_byte_cursor_from_buf(&options->session_token);
    aws_crt_credentials_provider *credentials_provider =
        aws_credentials_provider_new_static(aws_crt_allocator(), &options->options);
    return credentials_provider;
}

aws_crt_credentials_provider_environment_options *aws_crt_credentials_provider_environment_options_new() {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_environment_options));
}

void aws_crt_credentials_provider_environment_options_release(
    aws_crt_credentials_provider_environment_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_environment_new(
    aws_crt_credentials_provider_environment_options *options) {
    return aws_credentials_provider_new_environment(aws_crt_allocator(), options);
}

struct _aws_credentials_provider_profile_options {
    struct aws_credentials_provider_profile_options options;
    struct aws_byte_buf profile_name;
    struct aws_byte_buf config_file_name;
    struct aws_byte_buf credentials_file_name;
};

aws_crt_credentials_provider_profile_options *
    aws_crt_credentials_provider_profile_options_new() {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_profile_options));
}

void aws_crt_credentials_provider_options_release(aws_crt_credentials_provider_profile_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_profile_options_get_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_profile_name,
    size_t *out_profile_name_len) {
    if (options->profile_name.len > 0) {
        *out_profile_name = options->profile_name.buffer;
        *out_profile_name_len = options->profile_name.len;
    }
}

void aws_crt_credentials_provider_profile_options_set_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *profile_name,
    size_t profile_name_len) {
    struct aws_byte_buf input = aws_byte_buf_from_array(profile_name, profile_name_len);
    aws_byte_buf_init_copy(&options->profile_name, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_profile_options_get_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_config_file_name,
    size_t *out_config_file_name_length) {
    if (options->config_file_name.len > 0) {
        *out_config_file_name = options->config_file_name.buffer;
        *out_config_file_name_length = options->config_file_name.len;
    }
}

void aws_crt_credentials_provider_profile_options_set_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *config_file_name,
    size_t config_file_name_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(config_file_name, config_file_name_length);
    aws_byte_buf_init_copy(&options->config_file_name, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_profile_options_get_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_credentials_file_name,
    size_t *out_credentials_file_name_length) {
        if (options->credentials_file_name.len > 0) {
            *out_credentials_file_name = options->credentials_file_name.buffer;
            *out_credentials_file_name_length = options->credentials_file_name.len;
        }
    }

void aws_crt_credentials_provider_profile_options_set_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *credentials_file_name,
    size_t credentials_file_name_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(credentials_file_name, credentials_file_name_length);
    aws_byte_buf_init_copy(&options->credentials_file_name, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_profile_new(
    aws_crt_credentials_provider_profile_options *options) {
    return aws_credentials_provider_new_profile(aws_crt_allocator(), &options->options);
}

aws_crt_credentials_provider_cached_options *aws_crt_credentials_provider_cached_options_new(void){
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_cached_options));
}

void aws_crt_credentials_provider_cached_options_release(
    aws_crt_credentials_provider_cached_options *options){
    aws_mem_release(aws_crt_allocator(), options);
}

uint64_t aws_crt_credentials_provider_cached_options_get_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options){
    return options->refresh_time_in_milliseconds;
}

void aws_crt_credentials_provider_cached_options_set_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options,
    uint64_t refresh_time_in_milliseconds){
    options->refresh_time_in_milliseconds = refresh_time_in_milliseconds;
}

aws_crt_credentials_provider *aws_crt_credentials_provider_cached_new(
    aws_crt_credentials_provider_cached_options *options){
    return aws_credentials_provider_new_cached(aws_crt_allocator(), options);
}

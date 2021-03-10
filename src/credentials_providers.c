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

void aws_crt_credentials_provider_acquire(aws_crt_credentials_provider *credentials_provider) {
    aws_crt_credentials_provider_acquire(credentials_provider);
}

void aws_crt_credentials_provider_release(aws_crt_credentials_provider *credentials_provider) {
    aws_crt_credentials_provider_release(credentials_provider);
}

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

void aws_crt_credentials_provider_static_options_set_access_key_id(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *access_key_id,
    size_t access_key_id_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(access_key_id, access_key_id_length);
    aws_byte_buf_init_copy(&options->access_key_id, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_static_options_set_secret_access_key(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *secret_access_key,
    size_t secret_access_key_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(secret_access_key, secret_access_key_length);
    aws_byte_buf_init_copy(&options->secret_access_key, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_static_options_set_session_token(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *session_token,
    size_t session_token_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(session_token, session_token_length);
    aws_byte_buf_init_copy(&options->session_token, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_static_new(
    const aws_crt_credentials_provider_static_options *options) {
    aws_crt_credentials_provider_static_options *mutable_options =
        (aws_crt_credentials_provider_static_options *)options;
    mutable_options->options.access_key_id = aws_byte_cursor_from_buf(&options->access_key_id);
    mutable_options->options.secret_access_key = aws_byte_cursor_from_buf(&options->secret_access_key);
    mutable_options->options.session_token = aws_byte_cursor_from_buf(&options->session_token);
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
    const aws_crt_credentials_provider_environment_options *options) {
    return aws_credentials_provider_new_environment(aws_crt_allocator(), options);
}

struct _aws_credentials_provider_profile_options {
    struct aws_credentials_provider_profile_options options;
    struct aws_byte_buf profile_name;
    struct aws_byte_buf config_file_name;
    struct aws_byte_buf credentials_file_name;
};

aws_crt_credentials_provider_profile_options *aws_crt_credentials_provider_profile_options_new() {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_profile_options));
}

void aws_crt_credentials_provider_options_release(aws_crt_credentials_provider_profile_options *options) {
    aws_byte_buf_clean_up(&options->profile_name);
    aws_byte_buf_clean_up(&options->config_file_name);
    aws_byte_buf_clean_up(&options->credentials_file_name);
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_profile_options_set_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *profile_name,
    size_t profile_name_len) {
    struct aws_byte_buf input = aws_byte_buf_from_array(profile_name, profile_name_len);
    aws_byte_buf_init_copy(&options->profile_name, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_profile_options_set_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *config_file_name,
    size_t config_file_name_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(config_file_name, config_file_name_length);
    aws_byte_buf_init_copy(&options->config_file_name, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_profile_options_set_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *credentials_file_name,
    size_t credentials_file_name_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(credentials_file_name, credentials_file_name_length);
    aws_byte_buf_init_copy(&options->credentials_file_name, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_profile_new(
    const aws_crt_credentials_provider_profile_options *options) {
    aws_crt_credentials_provider_profile_options *mutable_options =
        (aws_crt_credentials_provider_profile_options *)options;
    mutable_options->options.profile_name_override = aws_byte_cursor_from_buf(&options->profile_name);
    mutable_options->options.config_file_name_override = aws_byte_cursor_from_buf(&options->config_file_name);
    mutable_options->options.credentials_file_name_override = aws_byte_cursor_from_buf(&options->credentials_file_name);
    return aws_credentials_provider_new_profile(aws_crt_allocator(), &options->options);
}

aws_crt_credentials_provider_cached_options *aws_crt_credentials_provider_cached_options_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_cached_options));
}

void aws_crt_credentials_provider_cached_options_release(aws_crt_credentials_provider_cached_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_cached_options_set_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options,
    uint64_t refresh_time_in_milliseconds) {
    options->refresh_time_in_milliseconds = refresh_time_in_milliseconds;
}

aws_crt_credentials_provider *aws_crt_credentials_provider_cached_new(
    const aws_crt_credentials_provider_cached_options *options) {
    return aws_credentials_provider_new_cached(aws_crt_allocator(), options);
}

aws_crt_credentials_provider_imds_options *aws_crt_credentials_provider_imds_options_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_imds_options));
}

void aws_crt_credentials_provider_imds_options_release(aws_crt_credentials_provider_imds_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_imds_options_set_imds_version(
    aws_crt_credentials_provider_imds_options *options,
    enum aws_crt_imds_protocol_version imds_version) {
    options->imds_version = imds_version;
}

aws_crt_credentials_provider *aws_crt_credentials_provider_imds_new(
    const aws_crt_credentials_provider_imds_options *options) {
    return aws_credentials_provider_new_imds(aws_crt_allocator(), options);
}

struct _aws_crt_credentials_provider_ecs_options {
    struct aws_credentials_provider_ecs_options options;
    struct aws_byte_buf host;
    struct aws_byte_buf path_and_query;
    struct aws_byte_buf auth_token;
};

aws_crt_credentials_provider_ecs_options *aws_crt_credentials_provider_ecs_options_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_ecs_options));
}

void aws_crt_credentials_provider_ecs_options_release(aws_crt_credentials_provider_ecs_options *options) {
    aws_byte_buf_clean_up(&options->host);
    aws_byte_buf_clean_up(&options->path_and_query);
    aws_byte_buf_clean_up_secure(&options->auth_token);
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_ecs_options_set_host(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *host,
    size_t host_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(host, host_length);
    aws_byte_buf_init_copy(&options->host, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_ecs_options_set_path_and_query(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *path_and_query,
    size_t path_and_query_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(path_and_query, path_and_query_length);
    aws_byte_buf_init_copy(&options->path_and_query, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_ecs_options_set_auth_token(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *auth_token,
    size_t auth_token_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(auth_token, auth_token_length);
    aws_byte_buf_init_copy(&options->auth_token, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_ecs_new(
    const aws_crt_credentials_provider_ecs_options *options) {
    aws_crt_credentials_provider_ecs_options *mutable_options = (aws_crt_credentials_provider_ecs_options *)options;
    mutable_options->options.host = aws_byte_cursor_from_buf(&options->host);
    mutable_options->options.path_and_query = aws_byte_cursor_from_buf(&options->path_and_query);
    mutable_options->options.auth_token = aws_byte_cursor_from_buf(&options->auth_token);
    return aws_credentials_provider_new_ecs(aws_crt_allocator(), &options->options);
}

struct _aws_crt_credentials_provider_x509_options {
    struct aws_credentials_provider_x509_options options;
    struct aws_byte_buf thing_name;
    struct aws_byte_buf role_alias;
    struct aws_byte_buf endpoint;
};

aws_crt_credentials_provider_x509_options *aws_crt_credentials_provider_x509_options_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_x509_options));
}

void aws_crt_credentials_provider_x509_options_release(aws_crt_credentials_provider_x509_options *options) {
    aws_byte_buf_clean_up(&options->thing_name);
    aws_byte_buf_clean_up(&options->role_alias);
    aws_byte_buf_clean_up(&options->endpoint);
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_credentials_provider_x509_options_set_thing_name(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *thing_name,
    size_t thing_name_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(thing_name, thing_name_length);
    aws_byte_buf_init_copy(&options->thing_name, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_x509_options_set_role_alias(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *role_alias,
    size_t role_alias_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(role_alias, role_alias_length);
    aws_byte_buf_init_copy(&options->role_alias, aws_crt_allocator(), &input);
}

void aws_crt_credentials_provider_x509_options_set_endpoint(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *endpoint,
    size_t endpoint_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(endpoint, endpoint_length);
    aws_byte_buf_init_copy(&options->endpoint, aws_crt_allocator(), &input);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_x509_new(
    aws_crt_credentials_provider_x509_options *options) {
    options->options.thing_name = aws_byte_cursor_from_buf(&options->thing_name);
    options->options.role_alias = aws_byte_cursor_from_buf(&options->role_alias);
    options->options.endpoint = aws_byte_cursor_from_buf(&options->endpoint);
    return aws_credentials_provider_new_x509(aws_crt_allocator(), &options->options);
}

aws_crt_credentials_provider_sts_web_identity_options *aws_crt_credentials_provider_sts_web_identity_options_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_credentials_provider_sts_web_identity_options));
}

void aws_crt_credentials_provider_sts_web_identity_options_release(
    aws_crt_credentials_provider_sts_web_identity_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

aws_crt_credentials_provider *aws_crt_credentials_provider_sts_web_identity_new(
    const aws_crt_credentials_provider_sts_web_identity_options *options) {
    return aws_credentials_provider_new_sts_web_identity(aws_crt_allocator(), options);
}

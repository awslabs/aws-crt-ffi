/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_result.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>

#include "http.h"

struct _aws_crt_signing_config_aws {
    struct aws_signing_config_aws config;
    aws_crt_should_sign_header_fn *should_sign_header;
    void *should_sign_header_user_data;
    struct aws_byte_buf region;
    struct aws_byte_buf service;
    struct aws_byte_buf signed_body_value;
};

aws_crt_signing_config_aws *aws_crt_signing_config_aws_new(void) {
    aws_crt_signing_config_aws *signing_config =
        aws_mem_calloc(aws_crt_default_allocator(), 1, sizeof(aws_crt_signing_config_aws));
    signing_config->config.config_type = AWS_SIGNING_CONFIG_AWS;
    return signing_config;
}

void aws_crt_signing_config_aws_release(aws_crt_signing_config_aws *signing_config) {
    aws_byte_buf_clean_up(&signing_config->region);
    aws_byte_buf_clean_up(&signing_config->service);
    aws_byte_buf_clean_up_secure(&signing_config->signed_body_value);
    aws_mem_release(aws_crt_default_allocator(), signing_config);
}

void aws_crt_signing_config_aws_set_algorithm(
    aws_crt_signing_config_aws *signing_config,
    enum aws_crt_signing_algorithm algorithm) {
    signing_config->config.algorithm = (int)algorithm;
}

void aws_crt_signing_config_aws_set_signature_type(
    aws_crt_signing_config_aws *signing_config,
    enum aws_crt_signature_type sig_type) {
    signing_config->config.signature_type = (int)sig_type;
}

void aws_crt_signing_config_aws_set_credentials_provider(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_credentials_provider *credentials_provider) {
    signing_config->config.credentials_provider = credentials_provider;
}

void aws_crt_signing_config_aws_set_region(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *region,
    size_t region_length) {
    aws_byte_buf_clean_up(&signing_config->region);
    struct aws_byte_buf input = aws_byte_buf_from_array(region, region_length);
    aws_byte_buf_init_copy(&signing_config->region, aws_crt_default_allocator(), &input);
    signing_config->config.region = aws_byte_cursor_from_buf(&signing_config->region);
}

void aws_crt_signing_config_aws_set_service(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *service,
    size_t service_length) {
    aws_byte_buf_clean_up(&signing_config->service);
    struct aws_byte_buf input = aws_byte_buf_from_array(service, service_length);
    aws_byte_buf_init_copy(&signing_config->service, aws_crt_default_allocator(), &input);
    signing_config->config.service = aws_byte_cursor_from_buf(&signing_config->service);
}

void aws_crt_signing_config_aws_set_use_double_uri_encode(
    aws_crt_signing_config_aws *signing_config,
    bool use_double_uri_encode) {
    signing_config->config.flags.use_double_uri_encode = use_double_uri_encode;
}

void aws_crt_signing_config_aws_set_should_normalize_uri_path(
    aws_crt_signing_config_aws *signing_config,
    bool should_normalize_uri_path) {
    signing_config->config.flags.should_normalize_uri_path = should_normalize_uri_path;
}

void aws_crt_signing_config_aws_set_omit_session_token(
    aws_crt_signing_config_aws *signing_config,
    bool omit_session_token) {
    signing_config->config.flags.omit_session_token = omit_session_token;
}

void aws_crt_signing_config_aws_set_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *signed_body,
    size_t signed_body_length) {
    aws_byte_buf_clean_up(&signing_config->signed_body_value);
    struct aws_byte_buf input = aws_byte_buf_from_array(signed_body, signed_body_length);
    aws_byte_buf_init_copy(&signing_config->signed_body_value, aws_crt_default_allocator(), &input);
    signing_config->config.signed_body_value = aws_byte_cursor_from_buf(&signing_config->signed_body_value);
}

void aws_crt_signing_config_aws_set_signed_body_header_type(
    aws_crt_signing_config_aws *signing_config,
    enum aws_crt_signed_body_header_type signed_body_header_type) {
    signing_config->config.signed_body_header = (int)signed_body_header_type;
}

void aws_crt_signing_config_aws_set_expiration_in_seconds(
    aws_crt_signing_config_aws *signing_config,
    uint64_t expiration_in_seconds) {
    signing_config->config.expiration_in_seconds = expiration_in_seconds;
}

void aws_crt_signing_config_aws_set_date(aws_crt_signing_config_aws *signing_config, uint64_t seconds_since_epoch) {
    aws_date_time_init_epoch_secs(&signing_config->config.date, (double)seconds_since_epoch);
}

/* translate between the FFI version of the callback and the auth/signer version */
static bool should_sign_header_thunk(const struct aws_byte_cursor *name, void *user_data) {
    aws_crt_signing_config_aws *signing_config = user_data;
    return signing_config->should_sign_header(
        (const char *)name->ptr, name->len, signing_config->should_sign_header_user_data);
}

void aws_crt_signing_config_aws_set_should_sign_header_fn(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_should_sign_header_fn *should_sign_header_fn,
    void *user_data) {
    /* store the target function and user data */
    signing_config->should_sign_header = should_sign_header_fn;
    signing_config->should_sign_header_user_data = user_data;

    /* auth will call the FFI version with the FFI user data, which will dispatch to the target function */
    signing_config->config.should_sign_header = should_sign_header_thunk;
    signing_config->config.should_sign_header_ud = signing_config;
}

_Bool aws_crt_signing_config_aws_validate(aws_crt_signing_config_aws *signing_config) {
    return aws_validate_aws_signing_config_aws(&signing_config->config) == AWS_OP_SUCCESS;
}

aws_crt_signable *aws_crt_signable_new_from_http_request(const aws_crt_http_message *request) {
    return aws_signable_new_http_request(aws_crt_default_allocator(), request->message);
}

aws_crt_signable *aws_crt_signable_new_from_chunk(
    aws_crt_input_stream *chunk_stream,
    const uint8_t *previous_signature,
    size_t previous_signature_length) {
    return aws_signable_new_chunk(
        aws_crt_default_allocator(),
        chunk_stream,
        aws_byte_cursor_from_array(previous_signature, previous_signature_length));
}

aws_crt_signable *aws_crt_signable_new_from_canonical_request(
    const uint8_t *canonical_request,
    size_t canonical_request_length) {
    return aws_signable_new_canonical_request(
        aws_crt_default_allocator(), aws_byte_cursor_from_array(canonical_request, canonical_request_length));
}

void aws_crt_signable_release(aws_crt_signable *signable) {
    aws_signable_destroy(signable);
}

int aws_crt_signing_result_apply_to_http_request(const aws_crt_signing_result *result, aws_crt_http_message *request) {
    return aws_apply_signing_result_to_http_request(request->message, aws_crt_default_allocator(), result);
}

void aws_crt_signing_result_release(aws_crt_signing_result *result) {
    aws_signing_result_clean_up(result);
    aws_mem_release(aws_crt_default_allocator(), result);
}

int aws_crt_sign_request_aws(
    aws_crt_signable *signable,
    const aws_crt_signing_config_aws *signing_config,
    aws_crt_signing_complete_fn *on_complete,
    void *user_data) {
    return aws_sign_request_aws(
        aws_crt_default_allocator(),
        signable,
        (struct aws_signing_config_base *)&signing_config->config,
        on_complete,
        user_data);
}

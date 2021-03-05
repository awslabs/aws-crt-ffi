/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/signing.h>
#include <aws/common/string.h>

struct _aws_crt_signing_config_aws {
    struct aws_signing_config_aws config;
    struct aws_byte_buf region;
    struct aws_byte_buf service;
    struct aws_byte_buf signed_body_value;
};

aws_crt_signing_config_aws *aws_crt_signing_config_aws_new(void) {
    return aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_signing_config_aws));
}

void aws_crt_signing_config_aws_release(aws_crt_signing_config_aws *signing_config) {
    aws_byte_buf_clean_up(&signing_config->region);
    aws_byte_buf_clean_up(&signing_config->service);
    aws_byte_buf_clean_up_secure(&signing_config->signed_body_value);
    aws_mem_release(aws_crt_allocator(), signing_config);
}

int aws_crt_signing_config_aws_get_algorithm(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.algorithm;
}

void aws_crt_signing_config_aws_set_algorithm(aws_crt_signing_config_aws *signing_config, int algorithm) {
    signing_config->config.algorithm = algorithm;
}

int aws_crt_signing_config_aws_get_signature_type(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.signature_type;
}

void aws_crt_signing_config_aws_set_signature_type(aws_crt_signing_config_aws *signing_config, int sig_type) {
    signing_config->config.signature_type = sig_type;
}

aws_crt_credentials_provider *aws_crt_signing_config_aws_get_credentials_provider(
    aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.credentials_provider;
}

void aws_crt_signing_config_aws_set_credentials_provider(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_credentials_provider *credentials_provider) {
    signing_config->config.credentials_provider = credentials_provider;
}

const char *aws_crt_signing_config_aws_get_region(aws_crt_signing_config_aws *signing_config) {
    return (const char *)signing_config->region.buffer;
}

void aws_crt_signing_config_aws_set_region(aws_crt_signing_config_aws *signing_config, const char *region) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(region);
    input.len++; /* ensure copy is null terminated */
    aws_byte_buf_init_copy(&signing_config->region, aws_crt_allocator(), &input);
}

const char *aws_crt_signing_config_aws_get_service(aws_crt_signing_config_aws *signing_config) {
    return (const char *)signing_config->service.buffer;
}

void aws_crt_signing_config_aws_set_service(aws_crt_signing_config_aws *signing_config, const char *service) {
    struct aws_byte_buf input = aws_byte_buf_from_c_str(service);
    input.len++; /* ensure copy is null terminated */
    aws_byte_buf_init_copy(&signing_config->service, aws_crt_allocator(), &input);
}

bool aws_crt_signing_config_aws_get_use_double_uri_encode(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.flags.use_double_uri_encode;
}

void aws_crt_signing_config_aws_set_use_double_uri_encode(
    aws_crt_signing_config_aws *signing_config,
    bool use_double_uri_encode) {
    signing_config->config.flags.use_double_uri_encode = use_double_uri_encode;
}

bool aws_crt_signing_config_aws_get_should_normalize_uri_path(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.flags.should_normalize_uri_path;
}

void aws_crt_signing_config_aws_set_should_normalize_uri_path(
    aws_crt_signing_config_aws *signing_config,
    bool should_normalize_uri_path) {
    signing_config->config.flags.should_normalize_uri_path = should_normalize_uri_path;
}

bool aws_crt_signing_config_aws_get_omit_session_token(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.flags.omit_session_token;
}

void aws_crt_signing_config_aws_set_omit_session_token(
    aws_crt_signing_config_aws *signing_config,
    bool omit_session_token) {
    signing_config->config.flags.omit_session_token = omit_session_token;
}

void aws_crt_signing_config_aws_get_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    uint8_t **out_signed_body,
    size_t *out_signed_body_length) {
    if (signing_config->signed_body_value.len > 0) {
        *out_signed_body = signing_config->signed_body_value.buffer;
        *out_signed_body_length = signing_config->signed_body_value.len;
    }
}

void aws_crt_signing_config_aws_set_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    uint8_t *signed_body,
    size_t signed_body_length) {
    struct aws_byte_buf input = aws_byte_buf_from_array(signed_body, signed_body_length);
    aws_byte_buf_init_copy(&signing_config->signed_body_value, aws_crt_allocator(), &input);
}

int aws_crt_signing_config_aws_get_signed_body_header_type(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.signed_body_header;
}

void aws_crt_signing_config_aws_set_signed_body_header_type(
    aws_crt_signing_config_aws *signing_config,
    int signed_body_header_type) {
    signing_config->config.signed_body_header = signed_body_header_type;
}

uint64_t aws_crt_signing_config_aws_get_expiration_in_seconds(aws_crt_signing_config_aws *signing_config) {
    return signing_config->config.expiration_in_seconds;
}

void aws_crt_signing_config_aws_set_expiration_in_seconds(
    aws_crt_signing_config_aws *signing_config,
    uint64_t expiration_in_seconds) {
    signing_config->config.expiration_in_seconds = expiration_in_seconds;
}

struct aws_crt_signable *aws_crt_signable_new(void) {
    return aws_signable_
}

void aws_crt_signable_release(aws_crt_signable *signable) {
    aws_signable_destroy(signable);
}

void aws_crt_signable_append_property(
    struct aws_crt_signable *signable,
    const char *property_name,
    const char *property_value) {
    aws_signable_
}

void aws_crt_signable_set_payload_stream(aws_crt_signable *signable, aws_crt_input_stream *input_stream) {}

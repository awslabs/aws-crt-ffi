#ifndef AWS_CRT_CREDENTIALS_H
#define AWS_CRT_CREDENTIALS_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/auth/credentials.h>
#include <aws/common/string.h>

struct _aws_crt_credentials_options {
    aws_crt_resource resource;
    struct aws_byte_buf access_key_id;
    struct aws_byte_buf secret_access_key;
    struct aws_byte_buf session_token;
    uint64_t expiration_timepoint_seconds;
};

struct _aws_crt_credentials {
    aws_crt_resource resource;
    struct aws_credentials *credentials;
};

struct _aws_crt_credentials_provider {
    aws_crt_resource resource;
    struct aws_credentials_provider *provider;
};

struct _aws_crt_credentials_provider_static_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_static_options options;
    struct aws_byte_buf access_key_id;
    struct aws_byte_buf secret_access_key;
    struct aws_byte_buf session_token;
};

struct _aws_crt_credentials_provider_environment_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_environment_options options;
};

struct _aws_crt_credentials_provider_profile_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_profile_options options;
    struct aws_byte_buf profile_name;
    struct aws_byte_buf config_file_name;
    struct aws_byte_buf credentials_file_name;
};

struct _aws_crt_credentials_provider_cached_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_cached_options options;
};

struct _aws_crt_credentials_provider_imds_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_imds_options options;
};

struct _aws_crt_credentials_provider_ecs_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_ecs_options options;
    struct aws_byte_buf host;
    struct aws_byte_buf path_and_query;
    struct aws_byte_buf auth_token;
};

struct _aws_crt_credentials_provider_x509_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_x509_options options;
    struct aws_byte_buf thing_name;
    struct aws_byte_buf role_alias;
    struct aws_byte_buf endpoint;
};

struct _aws_crt_credentials_provider_sts_web_identity_options {
    aws_crt_resource resource;
    struct aws_credentials_provider_sts_web_identity_options options;
};

#endif // AWS_CRT_CREDENTIALS_H

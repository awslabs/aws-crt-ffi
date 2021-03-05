#ifndef AWS_CRT_API_H
#define AWS_CRT_API_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/common.h>

/* AWS_CRT_API marks a function as public */
#if defined(_WIN32)
#    define AWS_CRT_API __declspec(dllexport)
#else
#    if ((__GNUC__ >= 4) || defined(__clang__))
#        define AWS_CRT_API __attribute__((visibility("default")))
#    else
#        define AWS_CRT_API
#    endif
#endif

struct _aws_crt_input_stream_options;
struct _aws_crt_event_loop_group_options;
struct _aws_crt_credentials_provider_static_options;

/* Public function definitions */
AWS_EXTERN_C_BEGIN

/* CRT */
AWS_CRT_API void aws_crt_init(void);
AWS_CRT_API void aws_crt_clean_up(void);
AWS_CRT_API int aws_crt_test_error(int);

/* Errors */
AWS_CRT_API int aws_crt_last_error(void);
AWS_CRT_API const char *aws_crt_error_str(int);
AWS_CRT_API const char *aws_crt_error_name(int);
AWS_CRT_API const char *aws_crt_error_debug_str(int);
AWS_CRT_API void aws_crt_reset_error(void);

/* IO */
typedef struct aws_event_loop_group aws_crt_event_loop_group;
typedef struct _aws_crt_event_loop_group_options aws_crt_event_loop_group_options;
AWS_CRT_API aws_crt_event_loop_group_options *aws_crt_event_loop_group_options_new(void);
AWS_CRT_API void aws_crt_event_loop_group_options_release(aws_crt_event_loop_group_options *options);
AWS_CRT_API void aws_crt_event_loop_group_options_set_max_threads(
    aws_crt_event_loop_group_options *options,
    uint16_t max_threads);
AWS_CRT_API aws_crt_event_loop_group *aws_crt_event_loop_group_new(aws_crt_event_loop_group_options *options);
AWS_CRT_API void aws_crt_event_loop_group_release(aws_crt_event_loop_group *elg);

/* Input stream */
typedef struct aws_input_stream aws_crt_input_stream;
typedef struct _aws_crt_input_stream_options aws_crt_input_stream_options;
typedef struct aws_stream_status aws_crt_stream_status;
typedef int(aws_crt_input_stream_seek_fn)(void *user_data, int64_t offset, int seek_basis);
typedef int(aws_crt_input_stream_read_fn)(void *user_data, uint8_t *dest, size_t dest_length);
typedef int(aws_crt_input_stream_get_status_fn)(void *user_data, aws_crt_stream_status *status);
typedef int(aws_crt_input_stream_get_length_fn)(void *user_data, int64_t *out_length);
typedef int(aws_crt_input_stream_destroy_fn)(void *user_data);
AWS_CRT_API aws_crt_input_stream_options *aws_crt_input_stream_options_new(void);
AWS_CRT_API void aws_crt_input_stream_options_release(aws_crt_input_stream_options *options);
AWS_CRT_API void aws_crt_input_stream_options_set_user_data(aws_crt_input_stream_options *options, void *user_data);
AWS_CRT_API void aws_crt_input_stream_options_set_seek(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_seek_fn *seek_fn);
AWS_CRT_API void aws_crt_input_stream_options_set_read(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_read_fn *read_fn);
AWS_CRT_API void aws_crt_input_stream_options_set_get_status(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_get_status_fn *get_status_fn);
AWS_CRT_API void aws_crt_input_stream_options_set_get_length(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_get_length_fn *get_length_fn);
AWS_CRT_API void aws_crt_input_stream_options_set_destroy(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_destroy_fn *destroy_fn);

AWS_CRT_API aws_crt_input_stream *aws_crt_input_stream_new(aws_crt_input_stream_options *options);
AWS_CRT_API void aws_crt_input_stream_release(aws_crt_input_stream *input_stream);

/* Auth */
typedef struct aws_credentials aws_crt_credentials;
typedef struct _aws_crt_credentials_options aws_crt_credentials_options;
AWS_CRT_API aws_crt_credentials *aws_crt_credentials_new(aws_crt_credentials_options *options);

AWS_CRT_API void aws_crt_credentials_release(aws_crt_credentials *credentials);
AWS_CRT_API struct aws_byte_cursor aws_crt_credentials_get_access_key_id(const aws_crt_credentials *credentials);
AWS_CRT_API struct aws_byte_cursor aws_crt_credentials_get_secret_access_key(const aws_crt_credentials *credentials);
AWS_CRT_API struct aws_byte_cursor aws_crt_credentials_get_session_token(const aws_crt_credentials *credentials);
AWS_CRT_API uint64_t aws_crt_credentials_get_expiration_timepoint_seconds(const struct aws_credentials *credentials);

/* Credentials providers */
typedef struct aws_credentials_provider aws_crt_credentials_provider;

/* static credentials provider */
typedef struct _aws_crt_credentials_provider_static_options aws_crt_credentials_provider_static_options;
AWS_CRT_API aws_crt_credentials_provider_static_options *aws_crt_credentials_provider_static_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_options_static_release(
    aws_crt_credentials_provider_static_options *options);
AWS_CRT_API const char *aws_crt_credentials_provider_static_options_get_access_key_id(
    aws_crt_credentials_provider_static_options *options);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_access_key_id(
    aws_crt_credentials_provider_static_options *options,
    const char *access_key_id);
AWS_CRT_API const char *aws_crt_credentials_provider_static_options_get_secret_access_key(
    aws_crt_credentials_provider_static_options *options);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_secret_access_key(
    aws_crt_credentials_provider_static_options *options,
    const char *secret_access_key);
AWS_CRT_API const char *aws_crt_credentials_provider_static_options_get_session_token(
    aws_crt_credentials_provider_static_options *options);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_session_token(
    aws_crt_credentials_provider_static_options *options,
    const char *session_token);

AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_static_new(
    aws_crt_credentials_provider_static_options *options);

/* environment credentials provider */
typedef struct aws_credentials_provider_environment_options aws_crt_credentials_provider_environment_options;
AWS_CRT_API aws_crt_credentials_provider_environment_options *aws_crt_credentials_provider_environment_options_new(
    void);
AWS_CRT_API void aws_crt_credentials_provider_environment_options_release(
    aws_crt_credentials_provider_environment_options *options);

AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_environment_new(
    aws_crt_credentials_provider_environment_options *options);

/* profile credentials provider */
typedef struct aws_credentials_provider_profile_options aws_crt_credentials_provider_profile_options;
AWS_CRT_API aws_crt_credentials_provider_profile_options *aws_crt_credentials_provider_profile_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_release(
    aws_crt_credentials_provider_profile_options *options);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_get_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_profile_name,
    size_t *out_profile_name_len);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *profile_name,
    size_t profile_name_len);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_get_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_config_file_name,
    size_t *out_config_file_name_length);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *config_file_name,
    size_t config_file_name_length);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_get_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t **out_credentials_file_name,
    size_t *out_credentials_file_name_length);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    uint8_t *credentials_file_name,
    size_t credentials_file_name_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_profile_new(
    aws_crt_credentials_provider_profile_options *options);

/* cached credentials provider */
typedef struct aws_credentials_provider_cached_options aws_crt_credentials_provider_cached_options;
AWS_CRT_API aws_crt_credentials_provider_cached_options *aws_crt_credentials_provider_cached_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_cached_options_release(
    aws_crt_credentials_provider_cached_options *options);
AWS_CRT_API uint64_t aws_crt_credentials_provider_cached_options_get_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options);
AWS_CRT_API void aws_crt_credentials_provider_cached_options_set_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options,
    uint64_t refresh_time_in_milliseconds);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_cached_new(
    aws_crt_credentials_provider_cached_options *options);

/* IMDS credentials provider */
typedef struct aws_credentials_provider_imds_options aws_crt_credentials_provider_imds_options;
AWS_CRT_API aws_crt_credentials_provider_imds_options *aws_crt_credentials_provider_imds_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_imds_options_release(aws_crt_credentials_provider_imds_options *options);
AWS_CRT_API int aws_crt_credentials_provider_imds_options_get_imds_version(
    aws_crt_credentials_provider_imds_options *options);
AWS_CRT_API void aws_crt_credentials_provider_imds_options_set_imds_version(
    aws_crt_credentials_provider_imds_options *options,
    int imds_version);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_imds_new(
    aws_crt_credentials_provider_imds_options *options);

/* ECS credentials provider */
typedef struct aws_credentials_provider_ecs_options *aws_crt_credentials_provider_ecs_options;
AWS_CRT_API aws_crt_credentials_provider_ecs_options *aws_crt_credentials_provider_ecs_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_release(aws_crt_credentials_provider_ecs_options *options);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_get_host(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t **out_host,
    size_t *out_host_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_host(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t *host,
    size_t host_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_get_path_and_query(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t **out_path_and_query,
    size_t *out_path_and_query_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_path_and_query(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t *path_and_query,
    size_t path_and_query_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_get_auth_token(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t **out_auth_token,
    size_t *out_auth_token_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_auth_token(
    aws_crt_credentials_provider_ecs_options *options,
    uint8_t *auth_token,
    size_t auth_token_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_ecs_new(
    aws_crt_credentials_provider_ecs_options *options);

/* X509 credentials provider */
typedef struct aws_credentials_provider_x509_options aws_crt_credentials_provider_x509_options;
AWS_CRT_API aws_crt_credentials_provider_x509_options *aws_crt_credentials_provider_x509_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_release(aws_crt_credentials_provider_x509_options *options);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_get_thing_name(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t **out_thing_name,
    size_t *out_thing_name_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_thing_name(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t *thing_name,
    size_t thing_name_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_get_role_alias(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t **out_role_alias,
    size_t *out_role_alias_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_role_alias(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t *role_alias,
    size_t role_alias_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_get_endpoint(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t **out_endpoint,
    size_t *out_endpoint_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_endpoint(
    aws_crt_credentials_provider_x509_options *options,
    uint8_t *endpoint,
    size_t endpoint_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_x509_new(void);

/* STS Web Identity provider */
typedef struct aws_credentials_provider_sts_web_identity_options aws_crt_credentials_provider_sts_web_identity_options;
AWS_CRT_API aws_crt_credentials_provider_sts_web_identity_options *
    aws_crt_credentials_provider_sts_web_identity_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_sts_web_identity_options_release(
    aws_crt_credentials_provider_sts_web_identity_options *options);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_sts_web_identity_new(
    aws_crt_credentials_provider_sts_web_identity_options *options);

/* Generic credentials provider release */
AWS_CRT_API void aws_crt_credentials_provider_release(aws_crt_credentials_provider *credentials_provider);

/* aws_signing_config_aws */
typedef struct aws_signing_config_aws aws_crt_signing_config_aws;
AWS_CRT_API aws_crt_signing_config_aws *aws_crt_signing_config_aws_new(void);
AWS_CRT_API void aws_crt_signing_config_aws_release(aws_crt_signing_config_aws *signing_config);

AWS_CRT_API int aws_crt_signing_config_aws_get_algorithm(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_algorithm(aws_crt_signing_config_aws *signing_config, int algorithm);
AWS_CRT_API int aws_crt_signing_config_aws_get_signature_type(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_signature_type(
    aws_crt_signing_config_aws *signing_config,
    int sig_type);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_signing_config_aws_get_credentials_provider(
    aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_credentials_provider(
    struct aws_signing_config_aws *signing_config,
    aws_crt_credentials_provider *credentials_provider);
AWS_CRT_API const char *aws_crt_signing_config_aws_get_region(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_region(aws_crt_signing_config_aws *signing_config, const char *region);
AWS_CRT_API const char *aws_crt_signing_config_aws_get_service(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_service(
    aws_crt_signing_config_aws *signing_config,
    const char *service);
AWS_CRT_API bool aws_crt_signing_config_aws_get_use_double_uri_encode(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_use_double_uri_encode(
    aws_crt_signing_config_aws *signing_config,
    bool use_double_uri_encode);
AWS_CRT_API bool aws_crt_signing_config_aws_get_should_normalize_uri_path(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_should_normalize_uri_path(
    aws_crt_signing_config_aws *signing_config,
    bool should_normalize_uri_path);
AWS_CRT_API bool aws_crt_signing_config_aws_get_omit_session_token(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_omit_session_token(
    aws_crt_signing_config_aws *signing_config,
    bool omit_session_token);
AWS_CRT_API void aws_crt_signing_config_aws_get_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    uint8_t **out_signed_body,
    size_t *out_signed_body_length);
AWS_CRT_API void aws_crt_signing_config_aws_set_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    uint8_t *signed_body,
    size_t signed_body_length);
AWS_CRT_API int aws_crt_signing_config_aws_get_signed_body_header_type(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_signed_body_header_type(
    aws_crt_signing_config_aws *signing_config,
    int signed_body_header_type);
AWS_CRT_API uint64_t aws_crt_signing_config_aws_get_expiration_in_seconds(aws_crt_signing_config_aws *signing_config);
AWS_CRT_API void aws_crt_signing_config_aws_set_expiration_in_seconds(
    aws_crt_signing_config_aws *signing_config,
    uint64_t expiration_in_seconds);

/* aws_signable */
typedef struct aws_signable aws_crt_signable;
AWS_CRT_API struct aws_crt_signable *aws_crt_signable_new(void);
AWS_CRT_API void aws_crt_signable_release(aws_crt_signable *signable);
AWS_CRT_API void aws_crt_signable_append_property(
    struct aws_crt_signable *signable,
    const char *property_name,
    const char *property_value);
AWS_CRT_API void aws_crt_signable_set_payload_stream(aws_crt_signable *signable, aws_crt_input_stream *input_stream);

/* aws_sign_request_aws */
typedef struct aws_signing_result aws_crt_signing_result;
typedef void(aws_crt_signing_complete_fn)(aws_crt_signing_result *result, int error_code, void *user_data);
AWS_CRT_API int aws_crt_sign_request_aws(
    aws_crt_signable *signable,
    aws_crt_signing_config_aws *signing_config,
    aws_crt_signing_complete_fn *on_complete,
    void *user_data);

AWS_EXTERN_C_END

#endif /* AWS_CRT_API_H */

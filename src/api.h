#ifndef AWS_CRT_API_H
#define AWS_CRT_API_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/*
 * NOTE: This header gets processed by libffi's FFI header parser. Includes and macros will not be
 * evaluated, so they are stripped before installation. While int types work, bool does not, so
 * you will see _Bool throughout the API (C99 standard). This also means that implementations must
 * use _Bool in their signatures, or they will create linking problems on some platforms.
 *
 * There are also some functions in this header that are not decorated with AWS_CRT_API. This is for
 * functions that are useful to native language extension authors linking to this library, but are not
 * for FFI consumption, or do not obey ref-counted ownership rules like the other resources in the FFI API.
 */

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

/* Public function definitions */

/* CRT */
AWS_CRT_API void aws_crt_init(void);
AWS_CRT_API void aws_crt_clean_up(void);
AWS_CRT_API int aws_crt_test_error(int);

typedef struct aws_allocator aws_crt_allocator;

AWS_CRT_API aws_crt_allocator *aws_crt_default_allocator(void);
AWS_CRT_API void *aws_crt_mem_acquire(size_t size);
AWS_CRT_API void *aws_crt_mem_calloc(size_t element_count, size_t element_size);
AWS_CRT_API void aws_crt_mem_release(void *mem);

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
AWS_CRT_API aws_crt_event_loop_group *aws_crt_event_loop_group_new(const aws_crt_event_loop_group_options *options);
AWS_CRT_API aws_crt_event_loop_group *aws_crt_event_loop_group_acquire(aws_crt_event_loop_group *elg);
AWS_CRT_API void aws_crt_event_loop_group_release(aws_crt_event_loop_group *elg);

/* Input stream */
typedef struct aws_input_stream aws_crt_input_stream;
typedef struct _aws_crt_input_stream_options aws_crt_input_stream_options;
typedef struct _aws_crt_input_stream_status {
    _Bool is_end_of_stream;
    _Bool is_valid;
} aws_crt_input_stream_status;
typedef enum aws_crt_input_stream_seek_basis {
    AWS_CRT_STREAM_SEEK_BASIS_BEGIN = 0,
    AWS_CRT_STREAM_SEEK_BASIS_END = 2,
} aws_crt_input_stream_seek_basis;
typedef int(aws_crt_input_stream_seek_fn)(void *user_data, int64_t offset, aws_crt_input_stream_seek_basis seek_basis);
typedef int(aws_crt_input_stream_read_fn)(void *user_data, uint8_t *dest, size_t dest_length);
typedef int(aws_crt_input_stream_get_status_fn)(void *user_data, aws_crt_input_stream_status *out_status);
typedef int(aws_crt_input_stream_get_length_fn)(void *user_data, int64_t *out_length);
typedef void(aws_crt_input_stream_destroy_fn)(void *user_data);
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

AWS_CRT_API aws_crt_input_stream *aws_crt_input_stream_new(const aws_crt_input_stream_options *options);
AWS_CRT_API void aws_crt_input_stream_release(aws_crt_input_stream *input_stream);
AWS_CRT_API int aws_crt_input_stream_seek(
    aws_crt_input_stream *input_stream,
    int64_t offset,
    aws_crt_input_stream_seek_basis seek_basis);
AWS_CRT_API int aws_crt_input_stream_read(aws_crt_input_stream *stream, uint8_t *dest, size_t dest_length);
AWS_CRT_API int aws_crt_input_stream_get_status(aws_crt_input_stream *stream, aws_crt_input_stream_status *status);
AWS_CRT_API int aws_crt_input_stream_get_length(aws_crt_input_stream *stream, int64_t *length);

/* HTTP */
typedef struct _aws_crt_http_headers aws_crt_http_headers;
AWS_CRT_API aws_crt_http_headers *aws_crt_http_headers_new_from_blob(const uint8_t *blob, size_t blob_length);
AWS_CRT_API aws_crt_http_headers *aws_crt_http_headers_acquire(aws_crt_http_headers *headers);
AWS_CRT_API void aws_crt_http_headers_release(aws_crt_http_headers *headers);
AWS_CRT_API void aws_crt_http_headers_to_blob(
    const aws_crt_http_headers *headers,
    uint8_t **out_blob,
    size_t *out_blob_length);

typedef struct _aws_crt_http_message aws_crt_http_message;
AWS_CRT_API aws_crt_http_message *aws_crt_http_message_new_from_blob(const uint8_t *blob, size_t blob_length);
AWS_CRT_API void aws_crt_http_message_release(aws_crt_http_message *message);
AWS_CRT_API void aws_crt_http_message_to_blob(
    const aws_crt_http_message *message,
    uint8_t **out_blob,
    size_t *out_blob_length);

/* Auth */
typedef struct aws_credentials aws_crt_credentials;
typedef struct _aws_crt_credentials_options aws_crt_credentials_options;
AWS_CRT_API aws_crt_credentials_options *aws_crt_credentials_options_new(void);
AWS_CRT_API void aws_crt_credentials_options_release(aws_crt_credentials_options *options);
AWS_CRT_API void aws_crt_credentials_options_set_access_key_id(
    aws_crt_credentials_options *options,
    const uint8_t *access_key_id,
    size_t access_key_id_length);
AWS_CRT_API void aws_crt_credentials_options_set_secret_access_key(
    aws_crt_credentials_options *options,
    const uint8_t *secret_access_key,
    size_t secret_access_key_length);
AWS_CRT_API void aws_crt_credentials_options_set_session_token(
    aws_crt_credentials_options *options,
    const uint8_t *session_token,
    size_t session_token_length);
AWS_CRT_API void aws_crt_credentials_options_set_expiration_timepoint_seconds(
    aws_crt_credentials_options *options,
    uint64_t expiration_timepoint_seconds);
AWS_CRT_API aws_crt_credentials *aws_crt_credentials_new(const aws_crt_credentials_options *options);
AWS_CRT_API aws_crt_credentials *aws_crt_credentials_acquire(aws_crt_credentials *credentials);
AWS_CRT_API void aws_crt_credentials_release(aws_crt_credentials *credentials);

/* Credentials providers */
typedef struct aws_credentials_provider aws_crt_credentials_provider;
/* Generic credentials provider acquire/release */
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_acquire(
    aws_crt_credentials_provider *credentials_provider);
AWS_CRT_API void aws_crt_credentials_provider_release(aws_crt_credentials_provider *credentials_provider);

/* static credentials provider */
typedef struct _aws_crt_credentials_provider_static_options aws_crt_credentials_provider_static_options;
AWS_CRT_API aws_crt_credentials_provider_static_options *aws_crt_credentials_provider_static_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_static_options_release(
    aws_crt_credentials_provider_static_options *options);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_access_key_id(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *access_key_id,
    size_t access_key_id_length);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_secret_access_key(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *secret_access_key,
    size_t secret_access_key_length);
AWS_CRT_API void aws_crt_credentials_provider_static_options_set_session_token(
    aws_crt_credentials_provider_static_options *options,
    const uint8_t *session_token,
    size_t session_token_length);

AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_static_new(
    const aws_crt_credentials_provider_static_options *options);

/* environment credentials provider */
typedef struct aws_credentials_provider_environment_options aws_crt_credentials_provider_environment_options;
AWS_CRT_API aws_crt_credentials_provider_environment_options *aws_crt_credentials_provider_environment_options_new(
    void);
AWS_CRT_API void aws_crt_credentials_provider_environment_options_release(
    aws_crt_credentials_provider_environment_options *options);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_environment_new(
    const aws_crt_credentials_provider_environment_options *options);

/* profile credentials provider */
typedef struct _aws_credentials_provider_profile_options aws_crt_credentials_provider_profile_options;
AWS_CRT_API aws_crt_credentials_provider_profile_options *aws_crt_credentials_provider_profile_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_release(
    aws_crt_credentials_provider_profile_options *options);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_profile_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *profile_name,
    size_t profile_name_len);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_config_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *config_file_name,
    size_t config_file_name_length);
AWS_CRT_API void aws_crt_credentials_provider_profile_options_set_credentials_file_name_override(
    aws_crt_credentials_provider_profile_options *options,
    const uint8_t *credentials_file_name,
    size_t credentials_file_name_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_profile_new(
    const aws_crt_credentials_provider_profile_options *options);

/* cached credentials provider */
typedef struct aws_credentials_provider_cached_options aws_crt_credentials_provider_cached_options;
AWS_CRT_API aws_crt_credentials_provider_cached_options *aws_crt_credentials_provider_cached_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_cached_options_release(
    aws_crt_credentials_provider_cached_options *options);
AWS_CRT_API void aws_crt_credentials_provider_cached_options_set_refresh_time_in_milliseconds(
    aws_crt_credentials_provider_cached_options *options,
    uint64_t refresh_time_in_milliseconds);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_cached_new(
    const aws_crt_credentials_provider_cached_options *options);

/* IMDS credentials provider */
typedef struct aws_credentials_provider_imds_options aws_crt_credentials_provider_imds_options;
typedef enum aws_crt_imds_protocol_version {
    AWS_CRT_IMDS_PROTOCOL_V2,
    AWS_CRT_IMDS_PROTOCOL_V1,
} aws_crt_imds_protocol_version;
AWS_CRT_API aws_crt_credentials_provider_imds_options *aws_crt_credentials_provider_imds_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_imds_options_release(aws_crt_credentials_provider_imds_options *options);
AWS_CRT_API void aws_crt_credentials_provider_imds_options_set_imds_version(
    aws_crt_credentials_provider_imds_options *options,
    aws_crt_imds_protocol_version imds_version);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_imds_new(
    const aws_crt_credentials_provider_imds_options *options);

/* ECS credentials provider */
typedef struct _aws_crt_credentials_provider_ecs_options aws_crt_credentials_provider_ecs_options;
AWS_CRT_API aws_crt_credentials_provider_ecs_options *aws_crt_credentials_provider_ecs_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_release(aws_crt_credentials_provider_ecs_options *options);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_host(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *host,
    size_t host_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_path_and_query(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *path_and_query,
    size_t path_and_query_length);
AWS_CRT_API void aws_crt_credentials_provider_ecs_options_set_auth_token(
    aws_crt_credentials_provider_ecs_options *options,
    const uint8_t *auth_token,
    size_t auth_token_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_ecs_new(
    const aws_crt_credentials_provider_ecs_options *options);

/* X509 credentials provider */
typedef struct _aws_crt_credentials_provider_x509_options aws_crt_credentials_provider_x509_options;
AWS_CRT_API aws_crt_credentials_provider_x509_options *aws_crt_credentials_provider_x509_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_release(aws_crt_credentials_provider_x509_options *options);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_thing_name(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *thing_name,
    size_t thing_name_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_role_alias(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *role_alias,
    size_t role_alias_length);
AWS_CRT_API void aws_crt_credentials_provider_x509_options_set_endpoint(
    aws_crt_credentials_provider_x509_options *options,
    const uint8_t *endpoint,
    size_t endpoint_length);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_x509_new(
    aws_crt_credentials_provider_x509_options *options);

/* STS Web Identity provider */
typedef struct aws_credentials_provider_sts_web_identity_options aws_crt_credentials_provider_sts_web_identity_options;
AWS_CRT_API aws_crt_credentials_provider_sts_web_identity_options *
    aws_crt_credentials_provider_sts_web_identity_options_new(void);
AWS_CRT_API void aws_crt_credentials_provider_sts_web_identity_options_release(
    aws_crt_credentials_provider_sts_web_identity_options *options);
AWS_CRT_API aws_crt_credentials_provider *aws_crt_credentials_provider_sts_web_identity_new(
    const aws_crt_credentials_provider_sts_web_identity_options *options);

/* aws_signing_config_aws */
typedef struct _aws_crt_signing_config_aws aws_crt_signing_config_aws;
typedef enum aws_crt_signing_algorithm {
    AWS_CRT_SIGNING_ALGORITHM_V4 = 0,
} aws_crt_signing_algorithm;
typedef enum aws_crt_signature_type {
    AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_HEADERS,
    AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_QUERY_PARAMS,
    AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_CHUNK,
    AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_EVENT,
    AWS_CRT_SIGNATURE_TYPE_CANONICAL_REQUEST_HEADERS,
    AWS_CRT_SIGNATURE_TYPE_CANONICAL_REQUEST_QUERY_PARAMS,
} aws_crt_signature_type;
typedef enum aws_crt_signed_body_header_type {
    AWS_CRT_SIGNED_BODY_HEADER_TYPE_NONE,
    AWS_CRT_SIGNED_BODY_HEADER_TYPE_X_AMZ_CONTENT_SHA256,
} aws_crt_signed_body_header_type;
AWS_CRT_API aws_crt_signing_config_aws *aws_crt_signing_config_aws_new(void);
AWS_CRT_API void aws_crt_signing_config_aws_release(aws_crt_signing_config_aws *signing_config);

AWS_CRT_API void aws_crt_signing_config_aws_set_algorithm(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_signing_algorithm algorithm);
AWS_CRT_API void aws_crt_signing_config_aws_set_signature_type(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_signature_type sig_type);
AWS_CRT_API void aws_crt_signing_config_aws_set_credentials_provider(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_credentials_provider *credentials_provider);
AWS_CRT_API void aws_crt_signing_config_aws_set_region(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *region,
    size_t region_length);
AWS_CRT_API void aws_crt_signing_config_aws_set_service(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *service,
    size_t service_length);
AWS_CRT_API void aws_crt_signing_config_aws_set_use_double_uri_encode(
    aws_crt_signing_config_aws *signing_config,
    _Bool use_double_uri_encode);
AWS_CRT_API void aws_crt_signing_config_aws_set_should_normalize_uri_path(
    aws_crt_signing_config_aws *signing_config,
    _Bool should_normalize_uri_path);
AWS_CRT_API void aws_crt_signing_config_aws_set_omit_session_token(
    aws_crt_signing_config_aws *signing_config,
    _Bool omit_session_token);
AWS_CRT_API void aws_crt_signing_config_aws_set_signed_body_value(
    aws_crt_signing_config_aws *signing_config,
    const uint8_t *signed_body,
    size_t signed_body_length);
AWS_CRT_API void aws_crt_signing_config_aws_set_signed_body_header_type(
    aws_crt_signing_config_aws *signing_config,
    aws_crt_signed_body_header_type signed_body_header_type);
AWS_CRT_API void aws_crt_signing_config_aws_set_expiration_in_seconds(
    aws_crt_signing_config_aws *signing_config,
    uint64_t expiration_in_seconds);
AWS_CRT_API void aws_crt_signing_config_aws_set_date(
    aws_crt_signing_config_aws *signing_config,
    uint64_t seconds_since_epoch);

/* aws_signable */
typedef struct aws_signable aws_crt_signable;
AWS_CRT_API aws_crt_signable *aws_crt_signable_new_from_http_request(const aws_crt_http_message *http_request);
AWS_CRT_API aws_crt_signable *aws_crt_signable_new_from_chunk(
    aws_crt_input_stream *chunk_stream,
    const uint8_t *previous_signature,
    size_t previous_signature_length);
AWS_CRT_API aws_crt_signable *aws_crt_signable_new_from_canonical_request(
    const uint8_t *request,
    size_t request_length);
AWS_CRT_API void aws_crt_signable_release(aws_crt_signable *signable);

/* aws_signing_result */
typedef struct aws_signing_result aws_crt_signing_result;
AWS_CRT_API void aws_crt_signing_result_release(aws_crt_signing_result *result);
AWS_CRT_API int aws_crt_signing_result_apply_to_http_request(
    const aws_crt_signing_result *result,
    aws_crt_http_message *request);

/* aws_sign_request_aws */
typedef void(aws_crt_signing_complete_fn)(aws_crt_signing_result *result, int error_code, void *user_data);
AWS_CRT_API int aws_crt_sign_request_aws(
    aws_crt_signable *signable,
    const aws_crt_signing_config_aws *signing_config,
    aws_crt_signing_complete_fn *on_complete,
    void *user_data);

#endif /* AWS_CRT_API_H */

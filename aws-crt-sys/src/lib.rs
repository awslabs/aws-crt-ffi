/* automatically generated by rust-bindgen 0.59.1 */

#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]

pub type __uint8_t = ::std::os::raw::c_uchar;
pub type __uint16_t = ::std::os::raw::c_ushort;
pub type __uint32_t = ::std::os::raw::c_uint;
pub type __int64_t = ::std::os::raw::c_long;
pub type __uint64_t = ::std::os::raw::c_ulong;
extern "C" {
    pub fn aws_crt_init();
}
extern "C" {
    pub fn aws_crt_clean_up();
}
extern "C" {
    pub fn aws_crt_test_error(arg1: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_crypto_share();
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct aws_allocator {
    _unused: [u8; 0],
}
pub type aws_crt_allocator = aws_allocator;
extern "C" {
    pub fn aws_crt_default_allocator() -> *mut aws_crt_allocator;
}
extern "C" {
    pub fn aws_crt_mem_acquire(size: usize) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn aws_crt_mem_calloc(
        element_count: usize,
        element_size: usize,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn aws_crt_mem_release(mem: *mut ::std::os::raw::c_void);
}
extern "C" {
    pub fn aws_crt_mem_bytes() -> u64;
}
extern "C" {
    pub fn aws_crt_mem_count() -> u64;
}
extern "C" {
    pub fn aws_crt_mem_dump();
}
extern "C" {
    pub fn aws_crt_resource_set_user_data(
        resource: *mut ::std::os::raw::c_void,
        user_data: *mut ::std::os::raw::c_void,
        dtor: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
    );
}
extern "C" {
    pub fn aws_crt_resource_get_user_data(
        resource: *mut ::std::os::raw::c_void,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn aws_crt_resource_take_user_data(
        resource: *mut ::std::os::raw::c_void,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn aws_crt_last_error() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_error_str(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn aws_crt_error_name(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn aws_crt_error_debug_str(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn aws_crt_reset_error();
}
pub type aws_crt_log_callback = ::std::option::Option<
    unsafe extern "C" fn(
        message: *const ::std::os::raw::c_char,
        length: usize,
        user_data: *mut ::std::os::raw::c_void,
    ),
>;
extern "C" {
    pub fn aws_crt_log_to_stdout();
}
extern "C" {
    pub fn aws_crt_log_to_stderr();
}
extern "C" {
    pub fn aws_crt_log_to_callback(
        callback: *mut aws_crt_log_callback,
        user_data: *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn aws_crt_log_to_file(filename: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn aws_crt_log_stop();
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_NONE: _aws_crt_log_level = _aws_crt_log_level(0);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_FATAL: _aws_crt_log_level = _aws_crt_log_level(1);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_ERROR: _aws_crt_log_level = _aws_crt_log_level(2);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_WARN: _aws_crt_log_level = _aws_crt_log_level(3);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_INFO: _aws_crt_log_level = _aws_crt_log_level(4);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_DEBUG: _aws_crt_log_level = _aws_crt_log_level(5);
}
impl _aws_crt_log_level {
    pub const AWS_CRT_LOG_TRACE: _aws_crt_log_level = _aws_crt_log_level(6);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct _aws_crt_log_level(pub ::std::os::raw::c_uint);
pub use self::_aws_crt_log_level as aws_crt_log_level;
extern "C" {
    pub fn aws_crt_log_set_level(log_level: aws_crt_log_level);
}
extern "C" {
    pub fn aws_crt_log_message(level: aws_crt_log_level, message: *const u8, length: usize);
}
extern "C" {
    pub fn aws_crt_thread_join_all(timeout_ns: u64) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_event_loop_group {
    _unused: [u8; 0],
}
pub type aws_crt_event_loop_group = _aws_crt_event_loop_group;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_event_loop_group_options {
    _unused: [u8; 0],
}
pub type aws_crt_event_loop_group_options = _aws_crt_event_loop_group_options;
extern "C" {
    pub fn aws_crt_event_loop_group_options_new() -> *mut aws_crt_event_loop_group_options;
}
extern "C" {
    pub fn aws_crt_event_loop_group_options_release(options: *mut aws_crt_event_loop_group_options);
}
extern "C" {
    pub fn aws_crt_event_loop_group_options_set_max_threads(
        options: *mut aws_crt_event_loop_group_options,
        max_threads: u16,
    );
}
extern "C" {
    pub fn aws_crt_event_loop_group_new(
        options: *const aws_crt_event_loop_group_options,
    ) -> *mut aws_crt_event_loop_group;
}
extern "C" {
    pub fn aws_crt_event_loop_group_acquire(
        elg: *mut aws_crt_event_loop_group,
    ) -> *mut aws_crt_event_loop_group;
}
extern "C" {
    pub fn aws_crt_event_loop_group_release(elg: *mut aws_crt_event_loop_group);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_input_stream {
    _unused: [u8; 0],
}
pub type aws_crt_input_stream = _aws_crt_input_stream;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_input_stream_options {
    _unused: [u8; 0],
}
pub type aws_crt_input_stream_options = _aws_crt_input_stream_options;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_input_stream_status {
    pub is_end_of_stream: bool,
    pub is_valid: bool,
}
#[test]
fn bindgen_test_layout__aws_crt_input_stream_status() {
    assert_eq!(
        ::std::mem::size_of::<_aws_crt_input_stream_status>(),
        2usize,
        concat!("Size of: ", stringify!(_aws_crt_input_stream_status))
    );
    assert_eq!(
        ::std::mem::align_of::<_aws_crt_input_stream_status>(),
        1usize,
        concat!("Alignment of ", stringify!(_aws_crt_input_stream_status))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_aws_crt_input_stream_status>())).is_end_of_stream as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(_aws_crt_input_stream_status),
            "::",
            stringify!(is_end_of_stream)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<_aws_crt_input_stream_status>())).is_valid as *const _ as usize
        },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(_aws_crt_input_stream_status),
            "::",
            stringify!(is_valid)
        )
    );
}
pub type aws_crt_input_stream_status = _aws_crt_input_stream_status;
impl aws_crt_input_stream_seek_basis {
    pub const AWS_CRT_STREAM_SEEK_BASIS_BEGIN: aws_crt_input_stream_seek_basis =
        aws_crt_input_stream_seek_basis(0);
}
impl aws_crt_input_stream_seek_basis {
    pub const AWS_CRT_STREAM_SEEK_BASIS_END: aws_crt_input_stream_seek_basis =
        aws_crt_input_stream_seek_basis(2);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct aws_crt_input_stream_seek_basis(pub ::std::os::raw::c_uint);
pub type aws_crt_input_stream_seek_fn = ::std::option::Option<
    unsafe extern "C" fn(
        user_data: *mut ::std::os::raw::c_void,
        offset: i64,
        seek_basis: aws_crt_input_stream_seek_basis,
    ) -> ::std::os::raw::c_int,
>;
pub type aws_crt_input_stream_read_fn = ::std::option::Option<
    unsafe extern "C" fn(
        user_data: *mut ::std::os::raw::c_void,
        dest: *mut u8,
        dest_length: usize,
    ) -> ::std::os::raw::c_int,
>;
pub type aws_crt_input_stream_get_status_fn = ::std::option::Option<
    unsafe extern "C" fn(
        user_data: *mut ::std::os::raw::c_void,
        out_status: *mut aws_crt_input_stream_status,
    ) -> ::std::os::raw::c_int,
>;
pub type aws_crt_input_stream_get_length_fn = ::std::option::Option<
    unsafe extern "C" fn(
        user_data: *mut ::std::os::raw::c_void,
        out_length: *mut i64,
    ) -> ::std::os::raw::c_int,
>;
pub type aws_crt_input_stream_destroy_fn =
    ::std::option::Option<unsafe extern "C" fn(user_data: *mut ::std::os::raw::c_void)>;
extern "C" {
    pub fn aws_crt_input_stream_options_new() -> *mut aws_crt_input_stream_options;
}
extern "C" {
    pub fn aws_crt_input_stream_options_release(options: *mut aws_crt_input_stream_options);
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_user_data(
        options: *mut aws_crt_input_stream_options,
        user_data: *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_seek(
        options: *mut aws_crt_input_stream_options,
        seek_fn: aws_crt_input_stream_seek_fn,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_read(
        options: *mut aws_crt_input_stream_options,
        read_fn: aws_crt_input_stream_read_fn,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_get_status(
        options: *mut aws_crt_input_stream_options,
        get_status_fn: aws_crt_input_stream_get_status_fn,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_get_length(
        options: *mut aws_crt_input_stream_options,
        get_length_fn: aws_crt_input_stream_get_length_fn,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_options_set_destroy(
        options: *mut aws_crt_input_stream_options,
        destroy_fn: aws_crt_input_stream_destroy_fn,
    );
}
extern "C" {
    pub fn aws_crt_input_stream_new(
        options: *const aws_crt_input_stream_options,
    ) -> *mut aws_crt_input_stream;
}
extern "C" {
    pub fn aws_crt_input_stream_release(input_stream: *mut aws_crt_input_stream);
}
extern "C" {
    pub fn aws_crt_input_stream_seek(
        input_stream: *mut aws_crt_input_stream,
        offset: i64,
        seek_basis: aws_crt_input_stream_seek_basis,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_input_stream_read(
        stream: *mut aws_crt_input_stream,
        dest: *mut u8,
        dest_length: usize,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_input_stream_get_status(
        stream: *mut aws_crt_input_stream,
        status: *mut aws_crt_input_stream_status,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_input_stream_get_length(
        stream: *mut aws_crt_input_stream,
        length: *mut i64,
    ) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct aws_crt_buf {
    pub blob: *mut u8,
    pub length: usize,
}
#[test]
fn bindgen_test_layout_aws_crt_buf() {
    assert_eq!(
        ::std::mem::size_of::<aws_crt_buf>(),
        16usize,
        concat!("Size of: ", stringify!(aws_crt_buf))
    );
    assert_eq!(
        ::std::mem::align_of::<aws_crt_buf>(),
        8usize,
        concat!("Alignment of ", stringify!(aws_crt_buf))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<aws_crt_buf>())).blob as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(aws_crt_buf),
            "::",
            stringify!(blob)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<aws_crt_buf>())).length as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(aws_crt_buf),
            "::",
            stringify!(length)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_http_headers {
    _unused: [u8; 0],
}
pub type aws_crt_http_headers = _aws_crt_http_headers;
extern "C" {
    pub fn aws_crt_http_headers_new_from_blob(
        blob: *const u8,
        blob_length: usize,
    ) -> *mut aws_crt_http_headers;
}
extern "C" {
    pub fn aws_crt_http_headers_acquire(
        headers: *mut aws_crt_http_headers,
    ) -> *mut aws_crt_http_headers;
}
extern "C" {
    pub fn aws_crt_http_headers_release(headers: *mut aws_crt_http_headers);
}
extern "C" {
    pub fn aws_crt_http_headers_to_blob(
        headers: *const aws_crt_http_headers,
        out_blob: *mut aws_crt_buf,
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_http_message {
    _unused: [u8; 0],
}
pub type aws_crt_http_message = _aws_crt_http_message;
extern "C" {
    pub fn aws_crt_http_message_new_from_blob(
        blob: *const u8,
        blob_length: usize,
    ) -> *mut aws_crt_http_message;
}
extern "C" {
    pub fn aws_crt_http_message_set_body_stream(
        message: *mut aws_crt_http_message,
        body_stream: *mut aws_crt_input_stream,
    );
}
extern "C" {
    pub fn aws_crt_http_message_release(message: *mut aws_crt_http_message);
}
extern "C" {
    pub fn aws_crt_http_message_to_blob(
        message: *const aws_crt_http_message,
        out_blob: *mut aws_crt_buf,
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials {
    _unused: [u8; 0],
}
pub type aws_crt_credentials = _aws_crt_credentials;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_options = _aws_crt_credentials_options;
extern "C" {
    pub fn aws_crt_credentials_options_new() -> *mut aws_crt_credentials_options;
}
extern "C" {
    pub fn aws_crt_credentials_options_release(options: *mut aws_crt_credentials_options);
}
extern "C" {
    pub fn aws_crt_credentials_options_set_access_key_id(
        options: *mut aws_crt_credentials_options,
        access_key_id: *const u8,
        access_key_id_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_options_set_secret_access_key(
        options: *mut aws_crt_credentials_options,
        secret_access_key: *const u8,
        secret_access_key_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_options_set_session_token(
        options: *mut aws_crt_credentials_options,
        session_token: *const u8,
        session_token_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_options_set_expiration_timepoint_seconds(
        options: *mut aws_crt_credentials_options,
        expiration_timepoint_seconds: u64,
    );
}
extern "C" {
    pub fn aws_crt_credentials_new(
        options: *const aws_crt_credentials_options,
    ) -> *mut aws_crt_credentials;
}
extern "C" {
    pub fn aws_crt_credentials_acquire(
        credentials: *mut aws_crt_credentials,
    ) -> *mut aws_crt_credentials;
}
extern "C" {
    pub fn aws_crt_credentials_release(credentials: *mut aws_crt_credentials);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider = _aws_crt_credentials_provider;
extern "C" {
    pub fn aws_crt_credentials_provider_acquire(
        credentials_provider: *mut aws_crt_credentials_provider,
    ) -> *mut aws_crt_credentials_provider;
}
extern "C" {
    pub fn aws_crt_credentials_provider_release(
        credentials_provider: *mut aws_crt_credentials_provider,
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_static_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_static_options = _aws_crt_credentials_provider_static_options;
extern "C" {
    pub fn aws_crt_credentials_provider_static_options_new(
    ) -> *mut aws_crt_credentials_provider_static_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_static_options_release(
        options: *mut aws_crt_credentials_provider_static_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_static_options_set_access_key_id(
        options: *mut aws_crt_credentials_provider_static_options,
        access_key_id: *const u8,
        access_key_id_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_static_options_set_secret_access_key(
        options: *mut aws_crt_credentials_provider_static_options,
        secret_access_key: *const u8,
        secret_access_key_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_static_options_set_session_token(
        options: *mut aws_crt_credentials_provider_static_options,
        session_token: *const u8,
        session_token_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_static_new(
        options: *const aws_crt_credentials_provider_static_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_environment_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_environment_options =
    _aws_crt_credentials_provider_environment_options;
extern "C" {
    pub fn aws_crt_credentials_provider_environment_options_new(
    ) -> *mut aws_crt_credentials_provider_environment_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_environment_options_release(
        options: *mut aws_crt_credentials_provider_environment_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_environment_new(
        options: *const aws_crt_credentials_provider_environment_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_profile_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_profile_options =
    _aws_crt_credentials_provider_profile_options;
extern "C" {
    pub fn aws_crt_credentials_provider_profile_options_new(
    ) -> *mut aws_crt_credentials_provider_profile_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_profile_options_release(
        options: *mut aws_crt_credentials_provider_profile_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_profile_options_set_profile_name_override(
        options: *mut aws_crt_credentials_provider_profile_options,
        profile_name: *const u8,
        profile_name_len: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_profile_options_set_config_file_name_override(
        options: *mut aws_crt_credentials_provider_profile_options,
        config_file_name: *const u8,
        config_file_name_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_profile_options_set_credentials_file_name_override(
        options: *mut aws_crt_credentials_provider_profile_options,
        credentials_file_name: *const u8,
        credentials_file_name_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_profile_new(
        options: *const aws_crt_credentials_provider_profile_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_cached_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_cached_options = _aws_crt_credentials_provider_cached_options;
extern "C" {
    pub fn aws_crt_credentials_provider_cached_options_new(
    ) -> *mut aws_crt_credentials_provider_cached_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_cached_options_release(
        options: *mut aws_crt_credentials_provider_cached_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_cached_options_set_refresh_time_in_milliseconds(
        options: *mut aws_crt_credentials_provider_cached_options,
        refresh_time_in_milliseconds: u64,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_cached_new(
        options: *const aws_crt_credentials_provider_cached_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_imds_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_imds_options = _aws_crt_credentials_provider_imds_options;
impl aws_crt_imds_protocol_version {
    pub const AWS_CRT_IMDS_PROTOCOL_V2: aws_crt_imds_protocol_version =
        aws_crt_imds_protocol_version(0);
}
impl aws_crt_imds_protocol_version {
    pub const AWS_CRT_IMDS_PROTOCOL_V1: aws_crt_imds_protocol_version =
        aws_crt_imds_protocol_version(1);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct aws_crt_imds_protocol_version(pub ::std::os::raw::c_uint);
extern "C" {
    pub fn aws_crt_credentials_provider_imds_options_new(
    ) -> *mut aws_crt_credentials_provider_imds_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_imds_options_release(
        options: *mut aws_crt_credentials_provider_imds_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_imds_options_set_imds_version(
        options: *mut aws_crt_credentials_provider_imds_options,
        imds_version: aws_crt_imds_protocol_version,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_imds_new(
        options: *const aws_crt_credentials_provider_imds_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_ecs_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_ecs_options = _aws_crt_credentials_provider_ecs_options;
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_options_new(
    ) -> *mut aws_crt_credentials_provider_ecs_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_options_release(
        options: *mut aws_crt_credentials_provider_ecs_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_options_set_host(
        options: *mut aws_crt_credentials_provider_ecs_options,
        host: *const u8,
        host_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_options_set_path_and_query(
        options: *mut aws_crt_credentials_provider_ecs_options,
        path_and_query: *const u8,
        path_and_query_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_options_set_auth_token(
        options: *mut aws_crt_credentials_provider_ecs_options,
        auth_token: *const u8,
        auth_token_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_ecs_new(
        options: *const aws_crt_credentials_provider_ecs_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_x509_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_x509_options = _aws_crt_credentials_provider_x509_options;
extern "C" {
    pub fn aws_crt_credentials_provider_x509_options_new(
    ) -> *mut aws_crt_credentials_provider_x509_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_x509_options_release(
        options: *mut aws_crt_credentials_provider_x509_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_x509_options_set_thing_name(
        options: *mut aws_crt_credentials_provider_x509_options,
        thing_name: *const u8,
        thing_name_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_x509_options_set_role_alias(
        options: *mut aws_crt_credentials_provider_x509_options,
        role_alias: *const u8,
        role_alias_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_x509_options_set_endpoint(
        options: *mut aws_crt_credentials_provider_x509_options,
        endpoint: *const u8,
        endpoint_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_x509_new(
        options: *mut aws_crt_credentials_provider_x509_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_credentials_provider_sts_web_identity_options {
    _unused: [u8; 0],
}
pub type aws_crt_credentials_provider_sts_web_identity_options =
    _aws_crt_credentials_provider_sts_web_identity_options;
extern "C" {
    pub fn aws_crt_credentials_provider_sts_web_identity_options_new(
    ) -> *mut aws_crt_credentials_provider_sts_web_identity_options;
}
extern "C" {
    pub fn aws_crt_credentials_provider_sts_web_identity_options_release(
        options: *mut aws_crt_credentials_provider_sts_web_identity_options,
    );
}
extern "C" {
    pub fn aws_crt_credentials_provider_sts_web_identity_new(
        options: *const aws_crt_credentials_provider_sts_web_identity_options,
    ) -> *mut aws_crt_credentials_provider;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_signing_config {
    _unused: [u8; 0],
}
pub type aws_crt_signing_config = _aws_crt_signing_config;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_signing_config_aws {
    _unused: [u8; 0],
}
pub type aws_crt_signing_config_aws = _aws_crt_signing_config_aws;
impl aws_crt_signing_algorithm {
    pub const AWS_CRT_SIGNING_ALGORITHM_V4: aws_crt_signing_algorithm =
        aws_crt_signing_algorithm(0);
}
impl aws_crt_signing_algorithm {
    pub const AWS_CRT_SIGNING_ALGORITHM_V4_ASYMMETRIC: aws_crt_signing_algorithm =
        aws_crt_signing_algorithm(1);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct aws_crt_signing_algorithm(pub ::std::os::raw::c_uint);
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_HEADERS: aws_crt_signature_type =
        aws_crt_signature_type(0);
}
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_QUERY_PARAMS: aws_crt_signature_type =
        aws_crt_signature_type(1);
}
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_CHUNK: aws_crt_signature_type =
        aws_crt_signature_type(2);
}
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_HTTP_REQUEST_EVENT: aws_crt_signature_type =
        aws_crt_signature_type(3);
}
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_CANONICAL_REQUEST_HEADERS: aws_crt_signature_type =
        aws_crt_signature_type(4);
}
impl aws_crt_signature_type {
    pub const AWS_CRT_SIGNATURE_TYPE_CANONICAL_REQUEST_QUERY_PARAMS: aws_crt_signature_type =
        aws_crt_signature_type(5);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct aws_crt_signature_type(pub ::std::os::raw::c_uint);
impl aws_crt_signed_body_header_type {
    pub const AWS_CRT_SIGNED_BODY_HEADER_TYPE_NONE: aws_crt_signed_body_header_type =
        aws_crt_signed_body_header_type(0);
}
impl aws_crt_signed_body_header_type {
    pub const AWS_CRT_SIGNED_BODY_HEADER_TYPE_X_AMZ_CONTENT_SHA256:
        aws_crt_signed_body_header_type = aws_crt_signed_body_header_type(1);
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct aws_crt_signed_body_header_type(pub ::std::os::raw::c_uint);
pub type aws_crt_should_sign_header_fn = ::std::option::Option<
    unsafe extern "C" fn(
        header_name: *const ::std::os::raw::c_char,
        length: usize,
        user_data: *mut ::std::os::raw::c_void,
    ) -> bool,
>;
extern "C" {
    pub fn aws_crt_signing_config_aws_new() -> *mut aws_crt_signing_config_aws;
}
extern "C" {
    pub fn aws_crt_signing_config_aws_release(signing_config: *mut aws_crt_signing_config_aws);
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_algorithm(
        signing_config: *mut aws_crt_signing_config_aws,
        algorithm: aws_crt_signing_algorithm,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_signature_type(
        signing_config: *mut aws_crt_signing_config_aws,
        sig_type: aws_crt_signature_type,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_credentials_provider(
        signing_config: *mut aws_crt_signing_config_aws,
        credentials_provider: *mut aws_crt_credentials_provider,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_region(
        signing_config: *mut aws_crt_signing_config_aws,
        region: *const u8,
        region_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_service(
        signing_config: *mut aws_crt_signing_config_aws,
        service: *const u8,
        service_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_use_double_uri_encode(
        signing_config: *mut aws_crt_signing_config_aws,
        use_double_uri_encode: bool,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_should_normalize_uri_path(
        signing_config: *mut aws_crt_signing_config_aws,
        should_normalize_uri_path: bool,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_omit_session_token(
        signing_config: *mut aws_crt_signing_config_aws,
        omit_session_token: bool,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_signed_body_value(
        signing_config: *mut aws_crt_signing_config_aws,
        signed_body: *const u8,
        signed_body_length: usize,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_signed_body_header_type(
        signing_config: *mut aws_crt_signing_config_aws,
        signed_body_header_type: aws_crt_signed_body_header_type,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_expiration_in_seconds(
        signing_config: *mut aws_crt_signing_config_aws,
        expiration_in_seconds: u64,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_date(
        signing_config: *mut aws_crt_signing_config_aws,
        seconds_since_epoch: u64,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_set_should_sign_header_fn(
        signing_config: *mut aws_crt_signing_config_aws,
        should_sign_header_fn: aws_crt_should_sign_header_fn,
        user_data: *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn aws_crt_signing_config_aws_validate(
        signing_config: *mut aws_crt_signing_config_aws,
    ) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _aws_crt_signable {
    _unused: [u8; 0],
}
pub type aws_crt_signable = _aws_crt_signable;
extern "C" {
    pub fn aws_crt_signable_new_from_http_request(
        http_request: *const aws_crt_http_message,
    ) -> *mut aws_crt_signable;
}
extern "C" {
    pub fn aws_crt_signable_new_from_chunk(
        chunk_stream: *mut aws_crt_input_stream,
        previous_signature: *const u8,
        previous_signature_length: usize,
    ) -> *mut aws_crt_signable;
}
extern "C" {
    pub fn aws_crt_signable_new_from_canonical_request(
        request: *const u8,
        request_length: usize,
    ) -> *mut aws_crt_signable;
}
extern "C" {
    pub fn aws_crt_signable_release(signable: *mut aws_crt_signable);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct aws_signing_result {
    _unused: [u8; 0],
}
pub type aws_crt_signing_result = aws_signing_result;
extern "C" {
    pub fn aws_crt_signing_result_release(result: *mut aws_crt_signing_result);
}
extern "C" {
    pub fn aws_crt_signing_result_apply_to_http_request(
        result: *const aws_crt_signing_result,
        request: *mut aws_crt_http_message,
    ) -> ::std::os::raw::c_int;
}
pub type aws_crt_signing_complete_fn = ::std::option::Option<
    unsafe extern "C" fn(
        result: *mut aws_crt_signing_result,
        error_code: ::std::os::raw::c_int,
        user_data: *mut ::std::os::raw::c_void,
    ),
>;
extern "C" {
    pub fn aws_crt_sign_request_aws(
        signable: *mut aws_crt_signable,
        signing_config: *const aws_crt_signing_config_aws,
        on_complete: aws_crt_signing_complete_fn,
        user_data: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_test_verify_sigv4a_signing(
        signable: *const aws_crt_signable,
        config: *const aws_crt_signing_config,
        expected_canonical_request: *const ::std::os::raw::c_char,
        signature: *const ::std::os::raw::c_char,
        ecc_key_pub_x: *const ::std::os::raw::c_char,
        ecc_key_pub_y: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn aws_crt_crc32(input: *const u8, length: usize, previous: u32) -> u32;
}
extern "C" {
    pub fn aws_crt_crc32c(input: *const u8, length: usize, previous: u32) -> u32;
}

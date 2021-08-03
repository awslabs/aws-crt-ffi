/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use std::ffi::CStr;
    use std::env;

    // CRT tests must be run serially because they affect global state
    // As a result, we inject a mutex into each test using the CRT
    // and while we're at it, we automate setup and teardown
    static MUTEX: Lazy<Mutex<()>> = Lazy::new(Mutex::default);
    macro_rules! with_crt {
        ($test:block) => {
            let _guard = match MUTEX.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            env::set_var("AWS_CRT_MEMORY_TRACING", "2");
            unsafe {
                aws_crt_init();
                (|| $test)();
                // wait for 10 seconds for all threads to join or fail
                let join_result = aws_crt_thread_join_all(10 * 1000 * 1000 * 1000);
                assert!(join_result == 0);
                assert!(aws_crt_mem_bytes() == 0);
                aws_crt_clean_up();
            }
        }
    }

    use aws_crt_sys::*;
    use std::os::raw::c_void;

    #[test]
    fn test_crt_bootstrapping() {
        with_crt!({});
    }

    pub unsafe extern "C" fn test_log_callback(msg: *const i8, len: usize, user_data: *mut c_void) {
        let message = String::from_raw_parts(msg as *mut u8, len, len);
        assert!(message.contains("THIS IS A TEST"));
        assert!(!user_data.is_null())
    }

    #[test]
    fn test_crt_logging() {
        with_crt!({
            let msg = "THIS IS A TEST";
            aws_crt_log_to_callback(&mut Some(test_log_callback), msg.as_ptr() as *mut c_void);
            aws_crt_log_message(aws_crt_log_level::AWS_CRT_LOG_INFO, msg.as_ptr(), msg.len());
        });
    }

    #[test]
    fn test_elg_lifetime() {
        with_crt!({
            let options = aws_crt_event_loop_group_options_new();
            aws_crt_event_loop_group_options_set_max_threads(options, 1);
            let elg = aws_crt_event_loop_group_new(options);
            aws_crt_event_loop_group_release(elg);
            aws_crt_event_loop_group_options_release(options);
        });
    }

    #[test]
    fn test_error_codes() {
        with_crt!({
            assert!(0 == aws_crt_last_error());
            assert!("AWS_ERROR_SUCCESS" == CStr::from_ptr(aws_crt_error_name(0)).to_str().unwrap());
            assert!("Success." == CStr::from_ptr(aws_crt_error_str(0)).to_str().unwrap());
        });
    }

    #[test]
    fn test_crc32_on_zeroes() {
        with_crt!({
            let zeroes: Vec<u8> = vec![0; 32];
            let crc = aws_crt_crc32(zeroes.as_ptr(), zeroes.len(), 0);
            assert!(crc == 0x190A55AD);
        });
    }

    #[test]
    fn test_crc32_on_zeroes_bytewise() {
        with_crt!({
            let zeroes: Vec<u8> = vec![0; 32];
            let mut crc = 0;
            zeroes.iter().for_each(|z| {
                crc = aws_crt_crc32(z, 1, crc);
            });
            assert!(crc == 0x190A55AD);
        });
    }

    #[test]
    fn test_crc32c_on_zeroes() {
        with_crt!({
            let zeroes: Vec<u8> = vec![0; 32];
            let crc = aws_crt_crc32c(zeroes.as_ptr(), zeroes.len(), 0);
            assert!(crc == 0x8A9136AA);
        });
    }

    #[test]
    fn test_crc32c_on_zeroes_bytewise() {
        with_crt!({
            let zeroes: Vec<u8> = vec![0; 32];
            let mut crc = 0;
            zeroes.iter().for_each(|z| {
                crc = aws_crt_crc32c(z, 1, crc);
            });
            assert!(crc == 0x8A9136AA);
        });
    }

    #[test]
    fn test_empty_aws_credentials() {
        with_crt!({
            let options = aws_crt_credentials_options_new();
            // This should fail, since the credentials are empty and therefore invalid
            let creds = aws_crt_credentials_new(options);
            assert!(creds.is_null());
            aws_crt_credentials_options_release(options);
        });
    }

    fn get_test_credentials_options() -> *mut aws_crt_credentials_options {
        unsafe {
            let options = aws_crt_credentials_options_new();
            let access_key_id = "TESTAWSACCESSKEYID";
            let secret_access_key = "TESTSECRETaccesskeyThatDefinitelyDoesntWork";
            let session_token = "ThisIsMyTestSessionTokenIMadeItUpMyself";
            aws_crt_credentials_options_set_access_key_id(options, access_key_id.as_ptr(), access_key_id.len());
            aws_crt_credentials_options_set_secret_access_key(options, secret_access_key.as_ptr(), secret_access_key.len());
            aws_crt_credentials_options_set_session_token(options, session_token.as_ptr(), session_token.len());
            aws_crt_credentials_options_set_expiration_timepoint_seconds(options, 42);
            options
        }
    }

    #[test]
    fn test_credentials_lifetime() {
        with_crt!({
            let options = get_test_credentials_options();
            let creds = aws_crt_credentials_new(options);
            assert!(!creds.is_null());
            aws_crt_credentials_release(creds);
            aws_crt_credentials_options_release(options);
        });
    }

    #[test]
    fn test_signing_config_aws() {
        with_crt!({
            let access_key_id = "TESTAWSACCESSKEYID";
            let secret_access_key = "TESTSECRETaccesskeyThatDefinitelyDoesntWork";
            let session_token = "ThisIsMyTestSessionTokenIMadeItUpMyself";
            let cred_options = aws_crt_credentials_provider_static_options_new();
            aws_crt_credentials_provider_static_options_set_access_key_id(cred_options, access_key_id.as_ptr(), access_key_id.len());
            aws_crt_credentials_provider_static_options_set_secret_access_key(cred_options, secret_access_key.as_ptr(), secret_access_key.len());
            aws_crt_credentials_provider_static_options_set_session_token(cred_options, session_token.as_ptr(), session_token.len());
            let provider = aws_crt_credentials_provider_static_new(cred_options);
            let sc = aws_crt_signing_config_aws_new();
            aws_crt_signing_config_aws_set_credentials_provider(sc, provider);
            aws_crt_signing_config_aws_release(sc);
            aws_crt_credentials_provider_release(provider);
            aws_crt_credentials_provider_static_options_release(cred_options);
        });
    }
}

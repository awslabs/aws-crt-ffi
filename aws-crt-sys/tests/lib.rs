
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#[cfg(test)]
mod tests {
    use aws_crt_sys::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use std::ffi::CStr;

    // CRT tests must be run serially because they affect global state
    // As a result, we inject a mutex into each test using the CRT
    // and while we're at it, we automate setup and teardown
    static MUTEX : Lazy<Mutex<()>> = Lazy::new(Mutex::default);
    macro_rules! with_crt {
        ($test:expr) => {
            let _guard = match MUTEX.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            unsafe {
                aws_crt_init();
                ($test)();
                aws_crt_clean_up();
            }
        }
    }

    #[test]
    fn test_crt_bootstrapping() {
        with_crt!(|| {});
    }

    #[test]
    fn test_elg_lifetime() {
        with_crt!( || {
            let options = aws_crt_event_loop_group_options_new();
            let elg = aws_crt_event_loop_group_new(options);
            aws_crt_event_loop_group_release(elg);
        });
    }

    #[test]
    fn test_error_codes() {
        with_crt!(|| {
            assert!(0 == aws_crt_last_error());
            assert!("AWS_ERROR_SUCCESS" == CStr::from_ptr(aws_crt_error_name(0)).to_str().unwrap());
            assert!("Success." == CStr::from_ptr(aws_crt_error_str(0)).to_str().unwrap());
        });
    }
}


/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#[cfg(test)]
mod tests {
    use aws_crt_sys::{aws_crt_init, aws_crt_clean_up};

    #[test]
    fn test_crt_bootstrapping() {
        unsafe {
            aws_crt_init();
            aws_crt_clean_up();
        }
    }
}

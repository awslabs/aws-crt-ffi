/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/common/error.h>

int aws_crt_last_error(void) {
    return aws_last_error();
}

const char *aws_crt_error_str(int err) {
    return aws_error_str(err);
}

const char *aws_crt_error_name(int err) {
    return aws_error_name(err);
}

const char *aws_crt_error_debug_str(int err) {
    return aws_error_debug_str(err);
}

void aws_crt_reset_error(void) {
    aws_reset_error();
}

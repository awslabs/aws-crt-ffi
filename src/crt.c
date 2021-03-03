/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/auth/auth.h>
#include <aws/cal/cal.h>
#include <aws/common/ref_count.h>
#include <aws/compression/compression.h>
#include <aws/http/http.h>

struct aws_allocator *aws_crt_allocator(void) {
  return aws_default_allocator();
}

void aws_crt_init(void) {
  struct aws_allocator *allocator = aws_crt_allocator();
  aws_common_library_init(allocator);
  aws_io_library_init(allocator);
  aws_compression_library_init(allocator);
  aws_http_library_init(allocator);
  aws_cal_library_init(allocator);
  aws_auth_library_init(allocator);
}

void aws_crt_clean_up(void) {
  aws_auth_library_clean_up();
  aws_cal_library_clean_up();
  aws_http_library_clean_up();
  aws_compression_library_clean_up();
  aws_io_library_clean_up();
  aws_common_library_clean_up();
}

int aws_crt_test_error(int err) { return aws_raise_error(err); }

struct aws_crt_test_struct *aws_crt_test_pointer_error(void) {
  aws_raise_error(AWS_ERROR_OOM);
  return NULL;
}

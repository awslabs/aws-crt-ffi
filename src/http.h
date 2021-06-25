/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/http/request_response.h>

#include <aws/common/byte_buf.h>

/* Privately defined structures */
struct _aws_crt_http_headers {
    struct aws_http_headers *headers;
    struct aws_byte_buf encoded_headers;
};

struct _aws_crt_http_message {
    struct aws_http_message *message;
    struct aws_byte_buf encoded_message;
};

struct _aws_crt_buf {
    struct aws_http_headers *headers;
    struct aws_byte_buf encoded_headers;
};
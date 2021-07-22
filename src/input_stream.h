#ifndef AWS_CRT_INPUT_STREAM_H
#define AWS_CRT_INPUT_STREAM_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/stream.h>

struct _aws_crt_input_stream_options {
    aws_crt_resource resource;
    void *user_data;
    aws_crt_input_stream_seek_fn *seek;
    aws_crt_input_stream_read_fn *read;
    aws_crt_input_stream_get_status_fn *get_status;
    aws_crt_input_stream_get_length_fn *get_length;
    aws_crt_input_stream_destroy_fn *destroy;
};

/* external options/stream have the same members, so just re-use the structure */
typedef aws_crt_input_stream_options aws_external_input_stream;

struct _aws_crt_input_stream {
    aws_crt_resource resource;
    struct aws_input_stream stream;
    aws_external_input_stream impl;
};

#endif // AWS_CRT_INPUT_STREAM_H

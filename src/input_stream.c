/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/io/stream.h>

struct _aws_crt_input_stream_options {
    void *user_data;
    aws_crt_input_stream_seek_fn *seek;
    aws_crt_input_stream_read_fn *read;
    aws_crt_input_stream_get_status_fn *get_status;
    aws_crt_input_stream_get_length_fn *get_length;
    aws_crt_input_stream_destroy_fn *destroy;
};

/* external options/stream have the same members, so just re-use the structure */
typedef aws_crt_input_stream_options aws_external_input_stream;

aws_crt_input_stream_options *aws_crt_input_stream_options_new() {
    aws_crt_input_stream_options *options =
        aws_mem_calloc(aws_crt_allocator(), 1, sizeof(aws_crt_input_stream_options));
    AWS_FATAL_ASSERT(options != NULL);
    AWS_ZERO_STRUCT(*options);
    return options;
}

void aws_crt_input_stream_options_release(aws_crt_input_stream_options *options) {
    aws_mem_release(aws_crt_allocator(), options);
}

void aws_crt_input_stream_options_set_user_data(aws_crt_input_stream_options *options, void *user_data) {
    options->user_data = user_data;
}

void aws_crt_input_stream_options_set_seek(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_seek_fn *seek_fn) {
    options->seek = seek_fn;
}

void aws_crt_input_stream_options_set_read(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_read_fn *read_fn) {
    options->read = read_fn;
}

void aws_crt_input_stream_options_set_get_status(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_get_status_fn *get_status_fn) {
    options->get_status = get_status_fn;
}

void aws_crt_input_stream_options_set_get_length(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_get_length_fn *get_length_fn) {
    options->get_length = get_length_fn;
}

void aws_crt_input_stream_options_set_destroy(
    aws_crt_input_stream_options *options,
    aws_crt_input_stream_destroy_fn *destroy_fn) {
    options->destroy = destroy_fn;
}

static int s_external_input_stream_seek(
    struct aws_input_stream *stream,
    aws_off_t offset,
    enum aws_stream_seek_basis basis) {
    aws_external_input_stream *ext_stream = stream->impl;
    return ext_stream->seek(ext_stream->user_data, (int64_t)offset, (int)basis);
}

static int s_external_input_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    aws_external_input_stream *ext_stream = stream->impl;
    return ext_stream->read(ext_stream->user_data, dest->buffer, dest->len);
}

static int s_external_input_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    aws_external_input_stream *ext_stream = stream->impl;
    return ext_stream->get_status(ext_stream->user_data, status);
}

static int s_external_input_stream_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    aws_external_input_stream *ext_stream = stream->impl;
    return ext_stream->get_length(ext_stream->user_data, out_length);
}

static void s_external_input_stream_destroy(struct aws_input_stream *stream) {
    aws_external_input_stream *ext_stream = stream->impl;
    ext_stream->destroy(ext_stream->user_data);
    aws_mem_release(aws_crt_allocator(), stream);
}

static struct aws_input_stream_vtable s_external_input_stream_vtable = {
    .seek = s_external_input_stream_seek,
    .read = s_external_input_stream_read,
    .get_status = s_external_input_stream_get_status,
    .get_length = s_external_input_stream_get_length,
    .destroy = s_external_input_stream_destroy,
};

aws_crt_input_stream *aws_crt_input_stream_new(aws_crt_input_stream_options *options) {
    aws_crt_input_stream *stream = NULL;
    aws_external_input_stream *impl = NULL;
    aws_mem_acquire_many(
        aws_crt_allocator(), 2, &options, sizeof(aws_crt_input_stream), &impl, sizeof(aws_external_input_stream));
    AWS_FATAL_ASSERT(stream != NULL && impl != NULL);
    AWS_ZERO_STRUCT(*stream);
    AWS_ZERO_STRUCT(*impl);

    *impl = *options;
    stream->allocator = aws_crt_allocator();
    stream->impl = impl;
    stream->vtable = &s_external_input_stream_vtable;
    return stream;
}

void aws_crt_input_stream_release(aws_crt_input_stream *stream) {
    aws_input_stream_destroy(stream);
}

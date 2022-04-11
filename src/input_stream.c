/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "crt.h"

#include "input_stream.h"

aws_crt_input_stream_options *aws_crt_input_stream_options_new() {
    aws_crt_input_stream_options *options = aws_crt_resource_new(sizeof(aws_crt_input_stream_options));
    return options;
}

void aws_crt_input_stream_options_release(aws_crt_input_stream_options *options) {
    aws_crt_resource_release(&options->resource);
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
    aws_crt_input_stream *impl = stream->impl;
    aws_external_input_stream ext_stream = impl->impl;
    return ext_stream.seek(ext_stream.user_data, (int64_t)offset, (aws_crt_input_stream_seek_basis)basis);
}

static int s_external_input_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    aws_crt_input_stream *impl = stream->impl;
    aws_external_input_stream ext_stream = impl->impl;
    return ext_stream.read(ext_stream.user_data, dest->buffer, dest->capacity);
}

static int s_external_input_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    aws_crt_input_stream *impl = stream->impl;
    aws_external_input_stream ext_stream = impl->impl;
    return ext_stream.get_status(ext_stream.user_data, (aws_crt_input_stream_status *)status);
}

static int s_external_input_stream_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    aws_crt_input_stream *impl = stream->impl;
    aws_external_input_stream ext_stream = impl->impl;
    return ext_stream.get_length(ext_stream.user_data, out_length);
}

static void s_external_input_stream_acquire(struct aws_input_stream *stream) {
    aws_crt_input_stream *impl = stream->impl;
    aws_crt_resource_acquire(&impl->resource);
}

static void s_external_input_stream_release(struct aws_input_stream *stream) {
    aws_crt_input_stream *impl = stream->impl;
    aws_crt_resource_release(&impl->resource);
}

static struct aws_input_stream_vtable s_external_input_stream_vtable = {
    .seek = s_external_input_stream_seek,
    .read = s_external_input_stream_read,
    .get_status = s_external_input_stream_get_status,
    .get_length = s_external_input_stream_get_length,
    .acquire = s_external_input_stream_acquire,
    .release = s_external_input_stream_release,
};

static void s_external_input_stream_destroy(void *user_data) {
    aws_external_input_stream *ext_stream = user_data;
    ext_stream->destroy(ext_stream->user_data);
}

aws_crt_input_stream *aws_crt_input_stream_new(const aws_crt_input_stream_options *options) {
    aws_crt_input_stream *stream = aws_crt_resource_new(sizeof(aws_crt_input_stream));
    AWS_ZERO_STRUCT(stream->stream);
    AWS_ZERO_STRUCT(stream->impl);

    stream->impl = *options;
    stream->stream.impl = &stream;
    stream->stream.vtable = &s_external_input_stream_vtable;

    aws_crt_resource_set_user_data(&stream->resource, &stream->impl, s_external_input_stream_destroy);

    return stream;
}

void aws_crt_input_stream_release(aws_crt_input_stream *stream) {
    aws_input_stream_release(&stream->stream);
    aws_crt_resource_release(&stream->resource);
}

int aws_crt_input_stream_seek(aws_crt_input_stream *stream, int64_t offset, aws_crt_input_stream_seek_basis basis) {
    return aws_input_stream_seek(&stream->stream, offset, (int)basis);
}

int aws_crt_input_stream_read(aws_crt_input_stream *stream, uint8_t *dest, size_t dest_length) {
    struct aws_byte_buf buf = aws_byte_buf_from_empty_array(dest, dest_length);
    return aws_input_stream_read(&stream->stream, &buf);
}

int aws_crt_input_stream_get_status(aws_crt_input_stream *stream, aws_crt_input_stream_status *status) {
    return aws_input_stream_get_status(&stream->stream, (struct aws_stream_status *)status);
}

int aws_crt_input_stream_get_length(aws_crt_input_stream *stream, int64_t *out_length) {
    return aws_input_stream_get_length(&stream->stream, out_length);
}

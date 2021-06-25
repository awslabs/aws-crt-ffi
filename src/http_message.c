/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include "http.h"

aws_crt_http_headers *aws_crt_http_headers_new_from_blob(const uint8_t *blob, size_t blob_length) {
    aws_crt_http_headers *headers = aws_mem_calloc(aws_crt_default_allocator(), 1, sizeof(aws_crt_http_headers));
    headers->headers = aws_http_headers_new(aws_crt_default_allocator());
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(blob, blob_length);
    while (cursor.len) {
        uint32_t entry_len = 0;
        /* Read header name: length|name */
        if (!aws_byte_cursor_read_be32(&cursor, &entry_len)) {
            goto bad_format;
        }
        struct aws_byte_cursor header_name = aws_byte_cursor_advance(&cursor, entry_len);

        /* Read header value: length|value */
        if (!aws_byte_cursor_read_be32(&cursor, &entry_len)) {
            goto bad_format;
        }
        struct aws_byte_cursor header_value = aws_byte_cursor_advance(&cursor, entry_len);

        struct aws_http_header header = {
            .name = header_name,
            .value = header_value,
        };

        aws_http_headers_add_header(headers->headers, &header);
    }
    return headers;

bad_format:
    aws_http_headers_release(headers->headers);
    aws_mem_release(aws_crt_default_allocator(), headers);
    aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    return NULL;
}

aws_crt_http_headers *aws_crt_http_headers_acquire(aws_crt_http_headers *headers) {
    aws_http_headers_acquire(headers->headers);
    return headers;
}

void aws_crt_http_headers_release(aws_crt_http_headers *headers) {
    aws_http_headers_release(headers->headers);
    aws_byte_buf_clean_up(&headers->encoded_headers);
    aws_mem_release(aws_crt_default_allocator(), headers);
}

void aws_crt_http_headers_to_blob(const aws_crt_http_headers *headers, aws_crt_buf *out_blob) {
    aws_crt_http_headers *mutable_headers = (aws_crt_http_headers *)headers;
    aws_byte_buf_clean_up(&mutable_headers->encoded_headers);
    aws_byte_buf_init(&mutable_headers->encoded_headers, aws_crt_default_allocator(), 256);
    const size_t header_count = aws_http_headers_count(headers->headers);
    for (size_t idx = 0; idx < header_count; ++idx) {
        struct aws_http_header header;
        aws_http_headers_get_index(headers->headers, idx, &header);
        aws_byte_buf_reserve_relative(
            &mutable_headers->encoded_headers,
            sizeof(uint32_t) + sizeof(uint32_t) + header.name.len + header.value.len);

        aws_byte_buf_write_be32(&mutable_headers->encoded_headers, (uint32_t)header.name.len);
        aws_byte_buf_write_from_whole_cursor(&mutable_headers->encoded_headers, header.name);
        aws_byte_buf_write_be32(&mutable_headers->encoded_headers, (uint32_t)header.value.len);
        aws_byte_buf_write_from_whole_cursor(&mutable_headers->encoded_headers, header.value);
    }
    out_blob->blob = headers->encoded_headers.buffer;
    out_blob->length = headers->encoded_headers.len;
}

aws_crt_http_message *aws_crt_http_message_new_from_blob(const uint8_t *blob, size_t blob_length) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(blob, blob_length);

    uint32_t entry_len = 0;
    if (!aws_byte_cursor_read_be32(&cursor, &entry_len)) {
        goto bad_format;
    }
    struct aws_byte_cursor method = aws_byte_cursor_advance(&cursor, entry_len);

    if (!aws_byte_cursor_read_be32(&cursor, &entry_len)) {
        goto bad_format;
    }
    struct aws_byte_cursor path = aws_byte_cursor_advance(&cursor, entry_len);

    aws_crt_http_headers *headers = aws_crt_http_headers_new_from_blob(cursor.ptr, cursor.len);
    if (!headers) {
        goto bad_format;
    }

    aws_crt_http_message *message = aws_mem_calloc(aws_crt_default_allocator(), 1, sizeof(aws_crt_http_message));
    message->message = aws_http_message_new_request_with_headers(aws_crt_default_allocator(), headers->headers);
    aws_http_message_set_request_method(message->message, method);
    aws_http_message_set_request_path(message->message, path);

    return message;

bad_format:
    aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    return NULL;
}

void aws_crt_http_message_set_body_stream(aws_crt_http_message *message, aws_crt_input_stream *body_stream) {
    aws_http_message_set_body_stream(message->message, body_stream);
}

void aws_crt_http_message_release(aws_crt_http_message *message) {
    aws_http_message_release(message->message);
    aws_byte_buf_clean_up(&message->encoded_message);
    aws_mem_release(aws_crt_default_allocator(), message);
}

void aws_crt_http_message_to_blob(const aws_crt_http_message *message, aws_crt_buf *out_blob) {
    aws_crt_http_message *mutable_message = (aws_crt_http_message *)message;

    struct aws_byte_cursor method;
    aws_http_message_get_request_method(message->message, &method);

    struct aws_byte_cursor path;
    aws_http_message_get_request_path(message->message, &path);

    struct aws_http_headers *http_headers = aws_http_message_get_headers(message->message);
    struct aws_byte_cursor header_blob;
    aws_crt_http_headers headers = {
        .headers = http_headers,
    };

    struct aws_crt_buf new_blob = {.blob = header_blob.ptr, .length = header_blob.len};
    aws_crt_http_headers_to_blob(&headers, &new_blob);

    aws_byte_buf_clean_up(&mutable_message->encoded_message);
    aws_byte_buf_init(
        &mutable_message->encoded_message,
        aws_crt_default_allocator(),
        sizeof(uint32_t) + sizeof(uint32_t) + method.len + path.len + header_blob.len);
    aws_byte_buf_write_be32(&mutable_message->encoded_message, (uint32_t)method.len);
    aws_byte_buf_write_from_whole_cursor(&mutable_message->encoded_message, method);
    aws_byte_buf_write_be32(&mutable_message->encoded_message, (uint32_t)path.len);
    aws_byte_buf_write_from_whole_cursor(&mutable_message->encoded_message, path);
    aws_byte_buf_write_from_whole_cursor(&mutable_message->encoded_message, header_blob);

    out_blob->blob = message->encoded_message.buffer;
    out_blob->length = message->encoded_message.len;
}

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "crt.h"
#include <aws/cal/hash.h>

aws_crt_hash *aws_crt_sha1_new(void) {
    return aws_sha1_new(aws_crt_default_allocator());
}

aws_crt_hash *aws_crt_sha256_new(void) {
    return aws_sha256_new(aws_crt_default_allocator());
}

aws_crt_hash *aws_crt_md5_new(void) {
    return aws_md5_new(aws_crt_default_allocator());
}

int aws_crt_hash_update(aws_crt_hash *hash, uint8_t *buffer, uint32_t buffer_size) {
    struct aws_byte_cursor buffer_cursor;
    AWS_ZERO_STRUCT(buffer_cursor);
    buffer_cursor.ptr = buffer;
    buffer_cursor.len = buffer_size;
    return aws_hash_update(hash, &buffer_cursor);
}

uint8_t *aws_crt_hash_digest(aws_crt_hash *hash, size_t truncate_to) {
    size_t digest_size = hash->digest_size;
    if (truncate_to != 0 && digest_size > truncate_to) {
        digest_size = truncate_to;
    }
    uint8_t *output = aws_mem_calloc(aws_crt_default_allocator(), digest_size, sizeof(uint8_t));
    struct aws_byte_buf digest_buf = aws_byte_buf_from_array(output, digest_size);
    digest_buf.len = 0;
    aws_hash_finalize(hash, &digest_buf, truncate_to);
    return output;
}

void aws_crt_hash_destroy(aws_crt_hash *hash) {
    aws_hash_destroy(hash);
}

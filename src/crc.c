/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "crt.h"
#include "limits.h"
#include <aws/checksums/crc.h>

uint32_t crc_common(
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t),
    const uint8_t *buffer,
    size_t length,
    uint32_t previous) {

    uint32_t val = previous;
    while (length > INT_MAX) {
        val = checksum_fn(buffer, INT_MAX, val);
        buffer += (size_t)INT_MAX;
        length -= (size_t)INT_MAX;
    }
    val = checksum_fn(buffer, (int)length, val);
    return val;
}

uint32_t aws_crt_crc32(const uint8_t *input, size_t length, uint32_t previous) {
    return crc_common(aws_checksums_crc32, input, length, previous);
}

uint32_t aws_crt_crc32c(const uint8_t *input, size_t length, uint32_t previous) {
    return crc_common(aws_checksums_crc32, input, length, previous);
}

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"
#include "aws/checksums/crc.h"

uint32_t aws_crt_crc32(const uint8_t *input, int length, uint32_t previous) {
    return aws_checksums_crc32(input, length, previous);
}

uint32_t aws_crt_crc32c(const uint8_t *input, int length, uint32_t previous) {
    return aws_checksums_crc32c(input, length, previous);
}

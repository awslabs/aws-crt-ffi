/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "crt.h"
#include "limits.h"
#include <aws/checksums/crc.h>

uint32_t aws_crt_crc32(const uint8_t *input, size_t length, uint32_t previous) {
    return aws_checksums_crc32_ex(input, length, previous);
}

uint32_t aws_crt_crc32c(const uint8_t *input, size_t length, uint32_t previous) {
    return aws_checksums_crc32c_ex(input, length, previous);
}


uint64_t aws_crt_crc64nvme(const uint8_t *input, size_t length, uint64_t previous) {
    return aws_checksums_crc64nvme_ex(input, length, previous);
}

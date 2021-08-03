/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "crt.h"

#include <aws/common/log_channel.h>
#include <aws/common/log_formatter.h>
#include <aws/common/log_writer.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>

static struct aws_log_subject_info s_log_subject_infos[] = {
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_CRT, "crt", "CRT host language messages"),
};

static struct aws_log_subject_info_list log_subject_list = {
    .subject_list = s_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_log_subject_infos),
};

static struct aws_logger crt_logger;
static struct logger_impl {
    enum aws_log_level level;
    struct aws_log_channel *channel;
    struct aws_log_formatter *formatter;
    struct aws_log_writer writer;
    aws_crt_log_callback log_write;
    void *user_data;
} crt_logger_impl;

static enum aws_log_level crt_logger_get_level(struct aws_logger *logger, aws_log_subject_t ignored) {
    (void)ignored;
    struct logger_impl *impl = logger->p_impl;
    return impl->level;
}

static int crt_logger_set_level(struct aws_logger *logger, enum aws_log_level level) {
    struct logger_impl *impl = logger->p_impl;
    impl->level = level;
    return AWS_OP_SUCCESS;
}

static void crt_logger_impl_clean_up(struct logger_impl *impl) {
    if (impl->channel) {
        aws_mem_release(aws_default_allocator(), impl->channel);
    }
    if (impl->formatter) {
        aws_mem_release(aws_default_allocator(), impl->formatter);
    }
    AWS_ZERO_STRUCT(*impl);
}

static void crt_logger_clean_up(struct aws_logger *logger) {
    struct logger_impl *impl = logger->p_impl;
    crt_logger_impl_clean_up(impl);
}

static int crt_logger_log(
    struct aws_logger *logger,
    enum aws_log_level log_level,
    aws_log_subject_t subject,
    const char *format,
    ...) {
    va_list format_args;
    va_start(format_args, format);

    struct logger_impl *impl = logger->p_impl;
    struct aws_string *output = NULL;

    AWS_ASSERT(impl->formatter->vtable->format != NULL);
    int result = (impl->formatter->vtable->format)(impl->formatter, &output, log_level, subject, format, format_args);

    va_end(format_args);

    if (result != AWS_OP_SUCCESS || output == NULL) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(impl->channel->vtable->send != NULL);
    if ((impl->channel->vtable->send)(impl->channel, output)) {
        /*
         * failure to send implies failure to transfer ownership
         */
        aws_string_destroy(output);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static struct aws_logger_vtable crt_logger_vtable = {
    .get_log_level = crt_logger_get_level,
    .set_log_level = crt_logger_set_level,
    .log = crt_logger_log,
    .clean_up = crt_logger_clean_up,
};

bool aws_crt_log_installed(void) {
    return aws_logger_get() == &crt_logger;
}

void aws_crt_log_init(void) {
    aws_register_log_subject_info_list(&log_subject_list);
}

void aws_crt_log_set_level(aws_crt_log_level log_level) {
    aws_logger_set_log_level(&crt_logger, (enum aws_log_level)log_level);
}

void aws_crt_log_to_stdout(void) {
    struct aws_logger_standard_options options = {
        .file = stdout,
    };
    aws_logger_init_standard(&crt_logger, aws_default_allocator(), &options);
}

void aws_crt_log_to_stderr(void) {
    struct aws_logger_standard_options options = {
        .file = stderr,
    };
    aws_logger_init_standard(&crt_logger, aws_default_allocator(), &options);
}

void aws_crt_log_to_file(const char *filename) {
    struct aws_logger_standard_options options = {
        .filename = filename,
    };
    aws_logger_init_standard(&crt_logger, aws_default_allocator(), &options);
}

void aws_crt_log_stop(void) {
    if (aws_crt_log_installed()) {
        aws_logger_set(NULL);
        crt_logger_clean_up(&crt_logger);
    }
}

void aws_crt_log_message(aws_crt_log_level level, const uint8_t *message, size_t length) {
    AWS_LOGF((enum aws_log_level)level, AWS_LS_CRT, "%*s", (int)length, message);
}

static int crt_log_writer_write(struct aws_log_writer *writer, const struct aws_string *output) {
    struct logger_impl *impl = writer->impl;
    impl->log_write((const char *)aws_string_bytes(output), output->len, impl->user_data);
    return AWS_OP_SUCCESS;
}

static void crt_log_writer_clean_up(struct aws_log_writer *writer) {
    struct logger_impl *impl = writer->impl;
    aws_mem_release(aws_default_allocator(), impl->channel);
    aws_mem_release(aws_default_allocator(), impl->formatter);
}

static struct aws_log_writer_vtable crt_log_writer_vtable = {
    .write = crt_log_writer_write,
    .clean_up = crt_log_writer_clean_up,
};

void aws_crt_log_to_callback(aws_crt_log_callback *callback, void *user_data) {
    if (callback == NULL) {
        aws_crt_log_stop();
        return;
    }

    crt_logger_impl.channel = aws_mem_calloc(aws_default_allocator(), 1, sizeof(struct aws_logger_pipeline));
    if (crt_logger_impl.channel == NULL) {
        goto cleanup;
    }

    crt_logger_impl.formatter = aws_mem_acquire(aws_default_allocator(), sizeof(struct aws_log_formatter));
    if (crt_logger_impl.formatter == NULL) {
        goto cleanup;
    }
    struct aws_log_formatter_standard_options formatter_options = {.date_format = AWS_DATE_FORMAT_ISO_8601};
    if (aws_log_formatter_init_default(crt_logger_impl.formatter, aws_default_allocator(), &formatter_options)) {
        goto cleanup;
    }

    *(void **)(&crt_logger_impl.log_write) = callback;
    crt_logger_impl.user_data = user_data;
    crt_logger_impl.writer.vtable = &crt_log_writer_vtable;
    crt_logger_impl.writer.allocator = aws_default_allocator();
    crt_logger_impl.writer.impl = &crt_logger_impl;

    if (aws_log_channel_init_background(crt_logger_impl.channel, aws_default_allocator(), &crt_logger_impl.writer)) {
        goto cleanup;
    }

    crt_logger.allocator = aws_default_allocator();
    crt_logger.vtable = &crt_logger_vtable;
    crt_logger.p_impl = &crt_logger_impl;
    aws_logger_set(&crt_logger);

    return;

cleanup:
    crt_logger_impl_clean_up(&crt_logger_impl);
}

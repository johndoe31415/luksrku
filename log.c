/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2016 Johannes Bauer

	This file is part of luksrku.

	luksrku is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	luksrku is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with luksrku; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <openssl/err.h>

#include "log.h"

static enum loglvl_t current_loglvl = LOGLEVEL_DEFAULT;
static const char *loglvl_names[] = {
	[LLVL_FATAL] = "FATAL",
	[LLVL_ERROR] = "ERROR",
	[LLVL_WARNING] = "WARNING",
	[LLVL_INFO] = "INFO",
	[LLVL_DEBUG] = "DEBUG",
};

void log_setlvl(enum loglvl_t level) {
	current_loglvl = level;
}

static void log_prefix(enum loglvl_t level) {
	fprintf(stderr, "[%c]: ", loglvl_names[level][0]);
}

static void log_suffix(void) {
	fprintf(stderr, "\n");
}

bool should_log(enum loglvl_t level) {
	return level <= current_loglvl;
}

void log_msg(enum loglvl_t level, const char *msg, ...) {
	if (!should_log(level)) {
		/* Suppress message */
		return;
	}

	log_prefix(level);
	va_list vargs;
	va_start(vargs, msg);
	vfprintf(stderr, msg, vargs);
	va_end(vargs);

	log_suffix();
}

void log_libc(enum loglvl_t level, const char *msg, ...) {
	if (!should_log(level)) {
		/* Suppress message */
		return;
	}

	int saved_errno = errno;
	log_prefix(level);
	va_list vargs;
	va_start(vargs, msg);
	vfprintf(stderr, msg, vargs);
	va_end(vargs);
	fprintf(stderr, ": %s (%d)", strerror(saved_errno), saved_errno);
	log_suffix();
}

static int log_openssl_error_callback(const char *msg, size_t len, void *vlvlptr) {
	enum loglvl_t* levelptr = (enum loglvl_t*)vlvlptr;
	log_msg(*levelptr, msg);
	return 0;
}

void log_openssl(enum loglvl_t level, const char *msg, ...) {
	if (!should_log(level)) {
		/* Suppress message */
		return;
	}

	log_prefix(level);
	fprintf(stderr, "OpenSSL error: ");
	va_list vargs;
	va_start(vargs, msg);
	vfprintf(stderr, msg, vargs);
	va_end(vargs);
	log_suffix();

	ERR_print_errors_cb(log_openssl_error_callback, &level);

#if 0
	log_msg(level, "");
	log_msg(level, "OpenSSL error message:");
	ERR_print_errors_fp(stderr);
	log_msg(level, "----------------------");
#endif
}

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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "thread.h"
#include "log.h"

struct pthread_trampoline_data_t {
	void (*thread_function)(void *ctx);
	uint8_t ctx[];
};

static void* pthread_trampoline(void *vctx) {
	struct pthread_trampoline_data_t *tdata = (struct pthread_trampoline_data_t*)vctx;
	tdata->thread_function(tdata->ctx);
	free(tdata);
	return NULL;
}

bool pthread_create_detached_thread(void (*thread_function)(void *ctx), const void *ctx, unsigned int ctx_length) {
	struct pthread_trampoline_data_t *tdata = calloc(1, sizeof(struct pthread_trampoline_data_t) + ctx_length);
	if (!tdata) {
		log_libc(LLVL_FATAL, "Failed to allocate trampoline data using calloc(3)");
		return false;
	}
	tdata->thread_function = thread_function;
	memcpy(tdata->ctx, ctx, ctx_length);

	pthread_attr_t attrs;
	if (pthread_attr_init(&attrs)) {
		log_libc(LLVL_FATAL, "Unable to pthread_attr_init(3)");
		free(tdata);
		return false;
	}

	if (pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED)) {
		log_libc(LLVL_FATAL, "Unable to pthread_attr_setdetachstate(3)");
		free(tdata);
		return false;
	}

	pthread_t thread;
	if (pthread_create(&thread, &attrs, pthread_trampoline, tdata)) {
		log_libc(LLVL_FATAL, "Unable to pthread_create(3) a client thread");
		free(tdata);
		return false;
	}
	return true;
}

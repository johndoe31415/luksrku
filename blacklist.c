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
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include "blacklist.h"
#include "global.h"

static struct blacklist_entry_t blacklist[BLACKLIST_ENTRY_COUNT];

static double gettime(void) {
	struct timeval tv;
	if (gettimeofday(&tv, NULL)) {
		return 0;
	}
	double now = tv.tv_sec + (tv.tv_usec * 1e-6);
	return now;
}

static bool blacklist_entry_expired(int index) {
	double now = gettime();
	return now > blacklist[index].entered + BLACKLIST_ENTRY_TIMEOUT_SECS;
}

void blacklist_ip(uint32_t ip) {
	for (int i = 0; i < BLACKLIST_ENTRY_COUNT; i++) {
		if (blacklist_entry_expired(i)) {
			blacklist[i].ip = ip;
			blacklist[i].entered = gettime();
			return;
		}
	}
}

bool is_ip_blacklisted(uint32_t ip) {
	for (int i = 0; i < BLACKLIST_ENTRY_COUNT; i++) {
		if ((ip == blacklist[i].ip) && (!blacklist_entry_expired(i))) {
			return true;
		}
	}
	return false;
}


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


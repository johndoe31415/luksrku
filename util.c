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
#include <openssl/evp.h>

#include "util.h"
#include "log.h"
#include "global.h"

char* query_passphrase(const char *prompt, unsigned int max_length) {
	char *passphrase = calloc(1, max_length + 1);
	if (!passphrase) {
		log_libc(LLVL_ERROR, "malloc(3) of passphrase memory");
		return NULL;
	}

	if (EVP_read_pw_string(passphrase, max_length, prompt, 0) != 0) {
		log_openssl(LLVL_ERROR, "EVP_read_pw_string failed");
		free(passphrase);
		return NULL;
	}

	return passphrase;
}

void dump_hex_long(FILE *f, const void *vdata, unsigned int length) {
	const uint8_t *data = (const uint8_t*)vdata;
	for (unsigned int i = 0; i < length; i += 32) {
		fprintf(f, "%4x ", i);
		for (unsigned int j = i; j < i + 32; j++) {
			fprintf(f, "%02x", data[j]);
		}
		fprintf(f, "\n");
	}
}

void dump_hex(FILE *f, const void *vdata, unsigned int length) {
	const uint8_t *data = (const uint8_t*)vdata;
	for (unsigned int i = 0; i < length; i++) {
		fprintf(f, "%02x", data[i]);
	}
}

bool is_hex(const char *str, int length) {
	for (int i = 0; i < length; i++) {
		if (((str[i] >= '0') && (str[i] <= '9')) ||
			 ((str[i] >= 'a') && (str[i] <= 'f')) ||
			 ((str[i] >= 'A') && (str[i] <= 'F'))) {
			continue;
		}
		return false;
	}
	return true;
}

static int parse_nibble(char nibble) {
	if ((nibble >= '0') && (nibble <= '9')) {
		return nibble - '0';
	} else if ((nibble >= 'a') && (nibble <= 'f')) {
		return nibble - 'a' + 10;
	} else if ((nibble >= 'A') && (nibble <= 'F')) {
		return nibble - 'A' + 10;
	}
	return -1;
}

static int parse_hexchar(const char *str) {
	int high = parse_nibble(str[0]);
	int low = parse_nibble(str[1]);
	if ((high == -1) || (low == -1)) {
		return -1;
	}
	return (high << 4) | low;
}

int parse_hexstr(const char *hexstr, uint8_t *data, int maxlen) {
	int length = 0;
	for (int i = 0; i < maxlen; i++) {
		if (*hexstr == 0) {
			break;
		}

		int next_char = parse_hexchar(hexstr);
		if (next_char == -1) {
			return -1;
		}
		data[length++] = next_char;
		hexstr += 2;
	}
	return length;
}

bool truncate_crlf(char *string) {
	int length = strlen(string);
	bool truncated = false;
	if (length && (string[length - 1] == '\n')) {
		truncated = true;
		string[--length] = 0;
	}
	if (length && (string[length - 1] == '\r')) {
		truncated = true;
		string[--length] = 0;
	}
	return truncated;
}

bool buffer_randomize(uint8_t *buffer, unsigned int length) {
	FILE *f = fopen("/dev/urandom", "r");
	if (!f) {
		log_libc(LLVL_FATAL, "Failed to access /dev/urandom");
		return false;
	}
	if (fread(buffer, length, 1, f) != 1) {
		log_libc(LLVL_FATAL, "Error reading randomness from /dev/urandom");
		fclose(f);
		return false;
	}
	fclose(f);
	return true;
}

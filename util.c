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

char* query_passphrase(const char *prompt) {
	char *passphrase = calloc(1, MAX_PASSPHRASE_LENGTH);
	if (!passphrase) {
		log_libc(LLVL_ERROR, "malloc(3) of passphrase memory");
		return NULL;
	}

	if (EVP_read_pw_string(passphrase, MAX_PASSPHRASE_LENGTH - 1, prompt, 0) != 0) {
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

bool is_valid_uuid(const char *ascii_uuid) {
	// e43fff25-5a01-40e8-b437-80b9d56c19ff
	// '-' at offsets 8 13 18 23
	if (!ascii_uuid) {
		return false;
	}
	if (strlen(ascii_uuid) != 36) {
		return false;
	}
	if ((ascii_uuid[8] != '-') || (ascii_uuid[13] != '-') || (ascii_uuid[18] != '-') || (ascii_uuid[23] != '-')) {
		return false;
	}
	if (!is_hex(ascii_uuid + 0, 8) || !is_hex(ascii_uuid + 9, 4) || !is_hex(ascii_uuid + 14, 4) || !is_hex(ascii_uuid + 19, 4) || !is_hex(ascii_uuid + 24, 12)) {
		return false;
	}
	return true;
}

bool parse_uuid(uint8_t *uuid, const char *ascii_uuid) {
	if (!is_valid_uuid(ascii_uuid)) {
		return false;
	}
	parse_hexstr(ascii_uuid + 0, uuid + 0, 4);
	parse_hexstr(ascii_uuid + 9, uuid + 4, 2);
	parse_hexstr(ascii_uuid + 14, uuid + 6, 2);
	parse_hexstr(ascii_uuid + 19, uuid + 8, 2);
	parse_hexstr(ascii_uuid + 24, uuid + 10, 6);
	return true;
}

void sprintf_uuid(char *buffer, const uint8_t *uuid) {
	buffer[0] = 0;
	for (int i = 0; i < 16; i++) {
		if ((i == 4) || (i == 6) || (i == 8) || (i == 10)) {
			buffer += sprintf(buffer, "-");
		}
		buffer += sprintf(buffer, "%02x", uuid[i]);
	}
}

void dump_uuid(FILE *f, const uint8_t *uuid) {
	char ascii_uuid[40];
	sprintf_uuid(ascii_uuid, uuid);
	fprintf(f, "%s", ascii_uuid);
}


/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2019 Johannes Bauer

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
#include <string.h>
#include "uuid.h"
#include "util.h"

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

bool uuid_randomize(uint8_t uuid[static 16]) {
	if (!buffer_randomize(uuid, 16)) {
		return false;
	}
	uuid[6] = (uuid[6] & (~0xf0)) | 0x40;
	uuid[8] = (uuid[8] & (~0xc0)) | 0x80;
	return true;
}

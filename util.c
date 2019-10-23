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

bool query_passphrase(const char *prompt, char *passphrase, unsigned int passphrase_maxsize) {
	if (passphrase_maxsize == 0) {
		return false;
	}
	if (EVP_read_pw_string(passphrase, passphrase_maxsize - 1, prompt, 0) != 0) {
		log_openssl(LLVL_ERROR, "EVP_read_pw_string failed");
		OPENSSL_cleanse(passphrase, passphrase_maxsize);
		return false;
	}

	return true;
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

void dump_hex(FILE *f, const void *vdata, unsigned int length, bool use_ascii) {
	const uint8_t *data = (const uint8_t*)vdata;
	for (unsigned int i = 0; i < length; i++) {
		uint8_t character = data[i];
		if (use_ascii && (character > 32) && (character < 127)) {
			fprintf(f, "%c ", character);
		} else {
			fprintf(f, "%02x ", character);
		}
	}
}

void dump_hexline(FILE *f, const char *prefix, const void *vdata, unsigned int length, bool use_ascii) {
	if (prefix) {
		fprintf(f, "%s", prefix);
	}
	dump_hex(f, vdata, length, use_ascii);
	fprintf(f, "\n");
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

bool is_zero(const void *data, unsigned int length) {
	const uint8_t *bytedata = (const uint8_t*)data;
	for (unsigned int i = 0; i < length; i++) {
		if (bytedata[i]) {
			return false;
		}
	}
	return true;
}

bool array_remove(void *base, unsigned int element_size, unsigned int element_count, unsigned int remove_element_index) {
	if (remove_element_index >= element_count) {
		return false;
	}
	uint8_t *bytebase = (uint8_t*)base;
	const unsigned int destination_offset = remove_element_index * element_size;
	const unsigned int source_offset = (remove_element_index + 1) * element_size;
	const unsigned int copy_length = ((element_count - 1) - remove_element_index) * element_size;
	if (copy_length) {
		memcpy(bytebase + destination_offset, bytebase + source_offset, copy_length);
	}

	/* Then, wipe the last element */
	const unsigned int last_element_offset = element_size * (element_count - 1);
	memset(bytebase + last_element_offset, 0, element_size);
	return true;
}

static uint8_t get_array_value(const uint8_t *array, unsigned int array_length, unsigned int array_index) {
	if (array_index < array_length) {
		return array[array_index];
	} else {
		return 0;
	}
}

bool ascii_encode(char *dest, unsigned int dest_buffer_size, const uint8_t *source_data, unsigned int source_data_length) {
	const unsigned int require_dest_size = ((source_data_length + 2) / 3) * 4 + 1;
	if (dest_buffer_size < require_dest_size) {
		log_msg(LLVL_FATAL, "Encoding of %d bytes takes a %d byte buffer, but only %d bytes provided.", source_data_length, require_dest_size, dest_buffer_size);
		return false;
	}

	const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for (unsigned int i = 0; i < source_data_length; i += 3) {
		uint32_t word = ((get_array_value(source_data, source_data_length, i + 0) << 16) | (get_array_value(source_data, source_data_length, i + 1) << 8) | (get_array_value(source_data, source_data_length, i + 2) << 0));
		for (int shift = 18; shift >= 0; shift -= 6) {
			*dest++ = alphabet[(word >> shift) & 0x3f];
		}
	}
	*dest = 0;
	return true;
}

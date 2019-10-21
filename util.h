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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define PRINTF_FORMAT_IP(saddrptr)		(saddrptr->sin_addr.s_addr >> 0) & 0xff, (saddrptr->sin_addr.s_addr >> 8) & 0xff, (saddrptr->sin_addr.s_addr >> 16) & 0xff, (saddrptr->sin_addr.s_addr >> 24) & 0xff

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool query_passphrase(const char *prompt, char *passphrase, unsigned int passphrase_maxsize);
void dump_hex_long(FILE *f, const void *vdata, unsigned int length);
void dump_hex(FILE *f, const void *vdata, unsigned int length, bool use_ascii);
void dump_hexline(FILE *f, const char *prefix, const void *vdata, unsigned int length, bool use_ascii);
bool is_hex(const char *str, int length);
int parse_hexstr(const char *hexstr, uint8_t *data, int maxlen);
bool truncate_crlf(char *string);
bool buffer_randomize(uint8_t *buffer, unsigned int length);
bool is_zero(const void *data, unsigned int length);
bool array_remove(void *base, unsigned int element_size, unsigned int element_count, unsigned int remove_element_index);
bool ascii_encode(char *dest, unsigned int dest_buffer_size, const uint8_t *source_data, unsigned int source_data_length);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

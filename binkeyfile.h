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

#ifndef __BINKEYFILE_H__
#define __BINKEYFILE_H__

#include <stdint.h>
#include <stdbool.h>

#define BINKEYFILE_SALT_SIZE			16
#define BINKEYFILE_KEY_SIZE				32
#define BINKEYFILE_AUTH_TAG_SIZE		16
#define BINKEYFILE_IV_SIZE				16

struct key_t {
	const char *passphrase;
	uint8_t salt[BINKEYFILE_SALT_SIZE];
	uint8_t key[BINKEYFILE_KEY_SIZE];
};

struct binkeyfile_t {
	bool empty_passphrase;
	uint8_t salt[BINKEYFILE_SALT_SIZE];
	uint8_t iv[BINKEYFILE_IV_SIZE];
	uint8_t auth_tag[BINKEYFILE_AUTH_TAG_SIZE];
	uint8_t ciphertext[];
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool read_binary_keyfile(const char *filename, struct keydb_t *keydb);
bool write_binary_keyfile(const char *filename, const struct keydb_t *keydb, const char *passphrase);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

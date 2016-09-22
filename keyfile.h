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

#ifndef __KEYFILE_H__
#define __KEYFILE_H__

#include <stdint.h>
#include <stdbool.h>

#include "global.h"

struct diskentry_t {
	bool occupied;											/* Is this a valid entry (with a valid UUID) */
	uint8_t disk_uuid[16];									/* Hex UUID of crypt_LUKS device */
	char devmapper_name[MAX_DEVMAPPER_NAME_LENGTH + 1];		/* dmsetup name when unlocked. Zero-terminated string. */
	uint32_t passphrase_length;								/* LUKS passphrase size in bytes. Zero if no passphrase set. */
	uint8_t passphrase[MAX_PASSPHRASE_LENGTH];				/* LUKS passphrase used to unlock disk */
};

struct keyentry_t {
	uint8_t host_uuid[16];									/* Host UUID */
	uint8_t psk[PSK_SIZE_BYTES];							/* Raw byte data */
	struct diskentry_t disk_keys[MAX_DISKS_PER_HOST];
};

struct keydb_t {
	int entrycnt;
	struct keyentry_t *entries;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct keyentry_t *last_keyentry(struct keydb_t *keydb);
bool add_keyslot(struct keydb_t *keydb);
const struct keyentry_t *keydb_find_entry_by_host_uuid(const struct keydb_t *keydb, const uint8_t *server_uuid);
struct keyentry_t* keydb_getentry(struct keydb_t *keydb, int keyid);
void keydb_dump(const struct keydb_t *keydb);
unsigned int keydb_disk_key_count(const struct keydb_t *keydb);
void keydb_free(struct keydb_t *keydb);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

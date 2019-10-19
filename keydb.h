/*
	luksrku - Tool to remotely unlock LUKS volumes using TLS.
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

#ifndef __KEYDB_H__
#define __KEYDB_H__

#include <stdint.h>
#include <stdbool.h>

#include "file_encryption.h"
#include "global.h"

#define KEYDB_VERSION							2

struct volume_entry_t {
	uint8_t volume_uuid[16];									/* UUID of crypt_LUKS volume */
	char volume_name[MAX_DESCRIPTION_LENGTH + 1];				/* Descriptive name of volume */
	char devmapper_name[MAX_DEVMAPPER_NAME_LENGTH + 1];			/* dmsetup name when unlocked. Zero-terminated string. */
	uint8_t luks_passphrase[PASSPHRASE_SIZE_BYTES];				/* LUKS passphrase used to unlock volume; raw byte data */
};

struct host_entry_t {
	uint8_t host_uuid[16];										/* Host UUID */
	char host_name[MAX_DESCRIPTION_LENGTH + 1];					/* Descriptive name of host */
	uint8_t tls_psk[PSK_SIZE_BYTES];							/* Raw byte data of TLS-PSK that is used */
	unsigned int volume_count;									/* Number of volumes of this host */
	struct volume_entry_t volumes[MAX_VOLUMES_PER_HOST];		/* Volumes of this host */
};

struct keydb_t {
	unsigned int keydb_version;
	bool server_database;
	int host_count;
	struct host_entry_t hosts[];
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct keydb_t* keydb_new(void);
void keydb_free(struct keydb_t *keydb);
struct keydb_t* keydb_add_host(struct keydb_t *keydb, const char *hostname);
bool keydb_write(const struct keydb_t *keydb, const char *filename, const char *passphrase);
struct keydb_t* keydb_read(const char *filename);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

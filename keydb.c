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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "keydb.h"
#include "util.h"

unsigned int keydb_getsize(const struct keydb_t *keydb) {
	return sizeof(struct keydb_t) + (keydb->host_count * sizeof(struct host_entry_t));
}

void keydb_init(struct keydb_t *keydb) {
	memset(keydb, 0, sizeof(struct keydb_t));
	keydb->keydb_version = KEYDB_VERSION;
	keydb->server_database = true;
}

void keydb_free(struct keydb_t *keydb) {
	memset(keydb, 0, keydb_getsize(keydb));
	free(keydb);
}

void keydb_write(const struct keydb_t *keydb, const char *filename, const char *passphrase, enum kdf_t kdf) {

}

struct keydb_t* keydb_read(const char *filename) {
	return NULL;
}

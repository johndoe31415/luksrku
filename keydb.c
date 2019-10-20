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
#include <openssl/crypto.h>

#include "keydb.h"
#include "util.h"
#include "log.h"

static unsigned int keydb_getsize_hostcount(unsigned int host_count) {
	return sizeof(struct keydb_t) + (host_count * sizeof(struct host_entry_t));
}

static unsigned int keydb_getsize(const struct keydb_t *keydb) {
	return keydb_getsize_hostcount(keydb->host_count);
}

struct keydb_t* keydb_new(void) {
	struct keydb_t *keydb = calloc(sizeof(struct keydb_t), 1);
	keydb->keydb_version = KEYDB_VERSION;
	keydb->server_database = true;
	return keydb;
}

void keydb_free(struct keydb_t *keydb) {
	memset(keydb, 0, keydb_getsize(keydb));
	free(keydb);
}

struct keydb_t* keydb_add_host(struct keydb_t *keydb, const char *hostname) {
	struct keydb_t *new_keydb = realloc(keydb, keydb_getsize_hostcount(keydb->host_count + 1));
	if (!new_keydb) {
		return NULL;
	}

	memset(&new_keydb->hosts[new_keydb->host_count], 0, sizeof(struct host_entry_t));
	new_keydb->host_count++;
	return new_keydb;
}

bool keydb_write(const struct keydb_t *keydb, const char *filename, const char *passphrase) {
	enum kdf_t kdf;
	if ((!passphrase) || (strlen(passphrase) == 0)) {
		/* For empty password, we can also use garbage KDF */
		kdf = KDF_PBKDF2_SHA256_1000;
	} else {
		kdf = KDF_SCRYPT_N17_r8_p1;
	}
	return write_encrypted_file(filename, keydb, keydb_getsize(keydb), passphrase, kdf);
}

struct keydb_t* keydb_read(const char *filename) {
	struct decrypted_file_t decrypted_file = read_encrypted_file(filename);
	if (!decrypted_file.success) {
		return NULL;
	}

	struct keydb_t *keydb = (struct keydb_t*)decrypted_file.data;
	if (keydb->keydb_version != KEYDB_VERSION) {
		log_msg(LLVL_ERROR, "keydb in %s could be read, but is of version %u (we expected %u).", keydb->keydb_version, KEYDB_VERSION);
		OPENSSL_cleanse(decrypted_file.data, decrypted_file.data_length);
		free(decrypted_file.data);
		return NULL;
	}

	if (decrypted_file.data_length != keydb_getsize(keydb)) {
		log_msg(LLVL_ERROR, "keydb in %s could be read, but was %u bytes long (we expected %u).", decrypted_file.data_length, keydb_getsize(keydb));
		OPENSSL_cleanse(decrypted_file.data, decrypted_file.data_length);
		free(decrypted_file.data);
		return NULL;
	}

	return keydb;
}

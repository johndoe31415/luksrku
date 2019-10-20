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
#include <strings.h>
#include <stdbool.h>
#include <openssl/crypto.h>

#include "keydb.h"
#include "util.h"
#include "uuid.h"
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

bool keydb_add_host(struct keydb_t **keydb, const char *host_name) {
	struct keydb_t *old_keydb = *keydb;
	if (keydb_get_host_by_name(old_keydb, host_name)) {
		log_msg(LLVL_ERROR, "Host name \"%s\" already present in key database.", host_name);
		return false;
	}

	struct keydb_t *new_keydb = realloc(old_keydb, keydb_getsize_hostcount(old_keydb->host_count + 1));
	if (!new_keydb) {
		return false;
	}
	*keydb = new_keydb;

	struct host_entry_t *host = &new_keydb->hosts[new_keydb->host_count];
	memset(host, 0, sizeof(struct host_entry_t));
	if (!uuid_randomize(host->host_uuid)) {
		/* We keep the reallocation but do not increase the host count */
		return false;
	}
	strncpy(host->host_name, host_name, sizeof(host->host_name) - 1);
	if (!buffer_randomize(host->tls_psk, sizeof(host->tls_psk))) {
		/* We keep the reallocation but do not increase the host count */
		return false;
	}

	new_keydb->host_count++;
	return true;
}

bool keydb_add_volume(struct host_entry_t *host, const char *devmapper_name, const uint8_t volume_uuid[static 16]) {
	if (host->volume_count == MAX_VOLUMES_PER_HOST) {
		log_msg(LLVL_ERROR, "Host \"%s\" already has maximum number of volumes (%d).", host->host_name, MAX_VOLUMES_PER_HOST);
		return false;
	}
	if (keydb_get_volume_by_name(host, devmapper_name)) {
		log_msg(LLVL_ERROR, "Volume name \"%s\" already present for host \"%s\" entry.", devmapper_name, host->host_name);
		return false;
	}

	struct volume_entry_t *volume = &host->volumes[host->volume_count];
	memcpy(volume->volume_uuid, volume_uuid, 16);
	strncpy(volume->devmapper_name, devmapper_name, sizeof(volume->devmapper_name) - 1);
	if (!buffer_randomize(volume->luks_passphrase, sizeof(volume->luks_passphrase))) {
		log_msg(LLVL_ERROR, "Failed to produce %d bytes of entropy for LUKS passphrase.", sizeof(volume->luks_passphrase));
		return false;
	}
	host->volume_count++;
	return true;
}

int keydb_get_volume_index_by_name(struct host_entry_t *host, const char *devmapper_name) {
	for (unsigned int i = 0; i < host->volume_count; i++) {
		struct volume_entry_t *volume = &host->volumes[i];
		if (!strcasecmp(volume->devmapper_name, devmapper_name)) {
			return i;
		}
	}
	return -1;
}

struct volume_entry_t *keydb_get_volume_by_name(struct host_entry_t *host, const char *devmapper_name) {
	const int index = keydb_get_volume_index_by_name(host, devmapper_name);
	return (index >= 0) ? &host->volumes[index] : NULL;
}

int keydb_get_host_index_by_name(struct keydb_t *keydb, const char *host_name) {
	for (unsigned int i = 0; i < keydb->host_count; i++) {
		struct host_entry_t *host = &keydb->hosts[i];
		if (!strcasecmp(host->host_name, host_name)) {
			return i;
		}
	}
	return -1;
}

bool keydb_get_volume_luks_passphrase(const struct volume_entry_t *volume, char *dest) {
	return ascii_encode(dest, volume->luks_passphrase, sizeof(volume->luks_passphrase));
}

struct host_entry_t *keydb_get_host_by_name(struct keydb_t *keydb, const char *host_name) {
	const int index = keydb_get_host_index_by_name(keydb, host_name);
	return (index >= 0) ? &keydb->hosts[index] : NULL;
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

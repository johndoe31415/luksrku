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

static unsigned int keydb_getsize_v3_hostcount(unsigned int host_count) {
	return sizeof(struct keydb_v3_t) + (host_count * sizeof(struct host_entry_v3_t));
}

static unsigned int keydb_getsize_v3(const struct keydb_v3_t *keydb) {
	return keydb_getsize_v3_hostcount(keydb->host_count);
}

static unsigned int keydb_getsize_v2_hostcount(unsigned int host_count) {
	return sizeof(struct keydb_v2_t) + (host_count * sizeof(struct host_entry_v2_t));
}

static unsigned int keydb_getsize_v2(const struct keydb_v2_t *keydb) {
	return keydb_getsize_v2_hostcount(keydb->host_count);
}

static unsigned int keydb_getsize_hostcount(unsigned int host_count) {
	return keydb_getsize_v3_hostcount(host_count);
}

static unsigned int keydb_getsize(const keydb_t *keydb) {
	return keydb_getsize_v3(keydb);
}

keydb_t* keydb_new(void) {
	keydb_t *keydb = calloc(1, sizeof(keydb_t));
	keydb->common.keydb_version = KEYDB_CURRENT_VERSION;
	keydb->server_database = true;
	return keydb;
}

keydb_t* keydb_export_public(host_entry_t *host) {
	keydb_t *public_db = keydb_new();
	if (!public_db) {
		return NULL;
	}
	public_db->server_database = false;

	if (!keydb_add_host(&public_db, host->host_name)) {
		keydb_free(public_db);
		return NULL;
	}

	/* Copy over whole entry */
	host_entry_t *public_host = &public_db->hosts[0];
	*public_host = *host;

	/* But remove all LUKS passphrases of course, this is for the luksrku client */
	for (unsigned int i = 0; i < host->volume_count; i++) {
		volume_entry_t *volume = &public_host->volumes[i];
		memset(volume->luks_passphrase_raw, 0, sizeof(volume->luks_passphrase_raw));
	}

	return public_db;
}

void keydb_free(keydb_t *keydb) {
	if (keydb) {
		OPENSSL_cleanse(keydb, keydb_getsize(keydb));
		free(keydb);
	}
}

volume_entry_t* keydb_get_volume_by_name(host_entry_t *host, const char *devmapper_name) {
	for (unsigned int i = 0; i < host->volume_count; i++) {
		volume_entry_t *volume = &host->volumes[i];
		if (!strncasecmp(volume->devmapper_name, devmapper_name, sizeof(volume->devmapper_name) - 1)) {
			return volume;
		}
	}
	return NULL;
}

host_entry_t* keydb_get_host_by_name(keydb_t *keydb, const char *host_name) {
	for (unsigned int i = 0; i < keydb->host_count; i++) {
		host_entry_t *host = &keydb->hosts[i];
		if (!strncasecmp(host->host_name, host_name, sizeof(host->host_name) - 1)) {
			return host;
		}
	}
	return NULL;
}

const volume_entry_t* keydb_get_volume_by_uuid(const host_entry_t *host, const uint8_t uuid[static 16]) {
	for (unsigned int i = 0; i < host->volume_count; i++) {
		const volume_entry_t *volume = &host->volumes[i];
		if (!memcmp(volume->volume_uuid, uuid, 16)) {
			return volume;
		}
	}
	return NULL;
}

int keydb_get_host_index(const keydb_t *keydb, const host_entry_t *host) {
	int index = host - keydb->hosts;
	if (index < 0) {
		return -1;
	} else if ((unsigned int)index >= keydb ->host_count) {
		return -1;
	}
	return index;
}

int keydb_get_volume_index(const host_entry_t *host, const volume_entry_t *volume) {
	int index = volume - host->volumes;
	if (index < 0) {
		return -1;
	} else if ((unsigned int)index >= host->volume_count) {
		return -1;
	}
	return index;
}

const host_entry_t* keydb_get_host_by_uuid(const keydb_t *keydb, const uint8_t uuid[static 16]) {
	for (unsigned int i = 0; i < keydb->host_count; i++) {
		const host_entry_t *host = &keydb->hosts[i];
		if (!memcmp(host->host_uuid, uuid, 16)) {
			return host;
		}
	}
	return NULL;
}

bool keydb_add_host(keydb_t **keydb, const char *host_name) {
	if (strlen(host_name) > MAX_HOST_NAME_LENGTH - 1) {
		log_msg(LLVL_ERROR, "Host name \"%s\" exceeds maximum length of %d characters.", host_name, MAX_HOST_NAME_LENGTH - 1);
		return false;
	}

	keydb_t *old_keydb = *keydb;
	if (keydb_get_host_by_name(old_keydb, host_name)) {
		log_msg(LLVL_ERROR, "Host name \"%s\" already present in key database.", host_name);
		return false;
	}

	keydb_t *new_keydb = realloc(old_keydb, keydb_getsize_hostcount(old_keydb->host_count + 1));
	if (!new_keydb) {
		return false;
	}
	*keydb = new_keydb;

	host_entry_t *host = &new_keydb->hosts[new_keydb->host_count];
	memset(host, 0, sizeof(host_entry_t));
	if (!uuid_randomize(host->host_uuid)) {
		/* We keep the reallocation but do not increase the host count */
		return false;
	}
	strncpy(host->host_name, host_name, sizeof(host->host_name) - 1);
	if (!keydb_rekey_host(host)) {
		/* We keep the reallocation but do not increase the host count */
		return false;
	}

	new_keydb->host_count++;
	return true;
}

bool keydb_del_host_by_name(keydb_t **keydb, const char *host_name) {
	keydb_t *old_keydb = *keydb;
	host_entry_t *host = keydb_get_host_by_name(old_keydb, host_name);
	if (!host) {
		log_msg(LLVL_ERROR, "No such host: \"%s\"", host_name);
		return false;
	}

	int host_index = keydb_get_host_index(old_keydb, host);
	if (host_index < 0) {
		log_msg(LLVL_FATAL, "Fatal error determining host index for hostname \"%s\".", host_name);
		return false;
	}

	/* We keep the memory for now and do not realloc */
	array_remove(old_keydb->hosts, sizeof(host_entry_t), old_keydb->host_count, host_index);
	old_keydb->host_count--;
	return true;
}

bool keydb_rekey_host(host_entry_t *host) {
	return buffer_randomize(host->tls_psk, sizeof(host->tls_psk));
}

volume_entry_t* keydb_add_volume(host_entry_t *host, const char *devmapper_name, const uint8_t volume_uuid[static 16]) {
	if (strlen(devmapper_name) > MAX_DEVMAPPER_NAME_LENGTH - 1) {
		log_msg(LLVL_ERROR, "Device mapper name \"%s\" exceeds maximum length of %d characters.", devmapper_name, MAX_DEVMAPPER_NAME_LENGTH - 1);
		return false;
	}

	if (host->volume_count >= MAX_VOLUMES_PER_HOST) {
		log_msg(LLVL_ERROR, "Host \"%s\" already has maximum number of volumes (%d).", host->host_name, MAX_VOLUMES_PER_HOST);
		return NULL;
	}
	if (keydb_get_volume_by_name(host, devmapper_name)) {
		log_msg(LLVL_ERROR, "Volume name \"%s\" already present for host \"%s\" entry.", devmapper_name, host->host_name);
		return NULL;
	}

	volume_entry_t *volume = &host->volumes[host->volume_count];
	memcpy(volume->volume_uuid, volume_uuid, 16);
	strncpy(volume->devmapper_name, devmapper_name, sizeof(volume->devmapper_name) - 1);
	if (!buffer_randomize(volume->luks_passphrase_raw, sizeof(volume->luks_passphrase_raw))) {
		log_msg(LLVL_ERROR, "Failed to produce %ld bytes of entropy for LUKS passphrase.", sizeof(volume->luks_passphrase_raw));
		return NULL;
	}
	host->volume_count++;
	return volume;
}

bool keydb_del_volume(host_entry_t *host, const char *devmapper_name) {
	volume_entry_t *volume = keydb_get_volume_by_name(host, devmapper_name);
	if (!volume) {
		log_msg(LLVL_ERROR, "No such volume \"%s\" for host \"%s\".", devmapper_name, host->host_name);
		return false;
	}
	int index = keydb_get_volume_index(host, volume);
	if (index < 0) {
		log_msg(LLVL_FATAL, "Fatal error determining volume index of \"%s\" for host \"%s\".", devmapper_name, host->host_name);
		return false;
	}
	if (!array_remove(host->volumes, sizeof(volume_entry_t), host->volume_count, index)) {
		log_msg(LLVL_ERROR, "Failed to remove \"%s\" of host \"%s\".", devmapper_name, host->host_name);
		return false;
	}
	host->volume_count--;
	return true;
}

bool keydb_rekey_volume(volume_entry_t *volume) {
	return buffer_randomize(volume->luks_passphrase_raw, sizeof(volume->luks_passphrase_raw));
}

bool keydb_volume_passphrase_present(const volume_entry_t *volume) {
	for (unsigned int i = 0; i < sizeof(volume->luks_passphrase_raw); i++) {
		if (volume->luks_passphrase_raw[i]) {
			return true;
		}
	}
	return false;
}

bool keydb_get_volume_luks_passphrase(const volume_entry_t *volume, char *dest, unsigned int dest_buffer_size) {
	return ascii_encode(dest, dest_buffer_size, volume->luks_passphrase_raw, sizeof(volume->luks_passphrase_raw));
}

bool keydb_write(const keydb_t *keydb, const char *filename, const char *passphrase) {
	enum kdf_t kdf;
	if ((!passphrase) || (strlen(passphrase) == 0)) {
		/* For empty password, we can also use garbage KDF */
		kdf = KDF_PBKDF2_SHA256_1000;
	} else {
		kdf = ENCRYPTED_FILE_DEFAULT_KDF;
	}
	return write_encrypted_file(filename, keydb, keydb_getsize(keydb), passphrase, kdf);
}

static bool passphrase_callback(char *buffer, unsigned int bufsize) {
	return query_passphrase("Database passphrase: ", buffer, bufsize);
}

static bool keydb_migrate_v2_to_v3(void **keydb_data, unsigned int *keydb_data_size) {
	log_msg(LLVL_INFO, "Migrating keydb version 2 to version 3");
	struct keydb_v2_t *old_db = *((struct keydb_v2_t **)keydb_data);
	unsigned int new_db_size = keydb_getsize_v3_hostcount(old_db->host_count);
	struct keydb_v3_t *new_db = calloc(1, new_db_size);
	if (!new_db) {
		log_msg(LLVL_ERROR, "keydb migration failed to allocate %d bytes of memory", new_db_size);
		return false;
	}

	*new_db = (struct keydb_v3_t) {
		.common.keydb_version = 3,
		.server_database = old_db->server_database,
		.host_count = old_db->host_count,
	};
	for (unsigned int i = 0; i < new_db->host_count; i++) {
		/* Do not copy over host_flags or volumes */
		memcpy(&new_db->hosts[i], &old_db->hosts[i], sizeof(old_db->hosts[i]) - sizeof(old_db->hosts[i].volumes));
		for (unsigned int j = 0; j < new_db->hosts[i].volume_count; j++) {
			/* Do not copy over volume_flags */
			memcpy(&new_db->hosts[i].volumes[j], &old_db->hosts[i].volumes[j], sizeof(old_db->hosts[i].volumes[j]));
		}
	}

	OPENSSL_cleanse(old_db, *keydb_data_size);
	free(old_db);

	*keydb_data = new_db;
	*keydb_data_size = new_db_size;
	return true;
}

static keydb_t* keydb_migrate(void **keydb_data, unsigned int *keydb_data_size) {
	struct keydb_common_header_t *header;

	header = *((struct keydb_common_header_t**)keydb_data);
	if (header->keydb_version == 2) {
		if (*keydb_data_size != keydb_getsize_v2(*keydb_data)) {
			log_msg(LLVL_ERROR, "keydb version 2 has wrong size (%u bytes, but expected %u bytes).", *keydb_data_size, keydb_getsize_v2(*keydb_data));
			return NULL;
		}
		if (!keydb_migrate_v2_to_v3(keydb_data, keydb_data_size)) {
			log_msg(LLVL_ERROR, "keydb version 2 to 3 migration failed.");
			return NULL;
		}
	}

	header = *((struct keydb_common_header_t**)keydb_data);
	if (header->keydb_version == 3) {
		if (*keydb_data_size != keydb_getsize_v3(*keydb_data)) {
			log_msg(LLVL_ERROR, "keydb version 3 has wrong size (%u bytes, but expected %u bytes).", *keydb_data_size, keydb_getsize_v3(*keydb_data));
			return NULL;
		}
	}

	header = *((struct keydb_common_header_t**)keydb_data);
	if (header->keydb_version != KEYDB_CURRENT_VERSION) {
		log_msg(LLVL_ERROR, "keydb could be read, but is of version %u (we expected %u).", header->keydb_version, KEYDB_CURRENT_VERSION);
		return NULL;
	}
	return *((keydb_t**)keydb_data);

}

keydb_t* keydb_read(const char *filename) {
	struct decrypted_file_t decrypted_file = read_encrypted_file(filename, passphrase_callback);
	if (!decrypted_file.success) {
		return NULL;
	}

	keydb_t *keydb = keydb_migrate(&decrypted_file.data, &decrypted_file.data_length);
	if (!keydb) {
		OPENSSL_cleanse(decrypted_file.data, decrypted_file.data_length);
		free(decrypted_file.data);
		return NULL;
	}
	return keydb;
}

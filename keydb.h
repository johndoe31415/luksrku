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

#define ALIGNED		__attribute__ ((aligned(4)))

enum volume_flag_t {
	VOLUME_FLAG_ALLOW_DISCARD = (1 << 0),
};

/* Unused so far */
enum host_flag_t {
	HOST_FLAG_UNUSED = 0,
};

struct keydb_common_header_t {
	unsigned int keydb_version;
} ALIGNED;

struct volume_entry_v2_t {
	uint8_t volume_uuid[16];										/* UUID of crypt_LUKS volume */
	char devmapper_name[MAX_DEVMAPPER_NAME_LENGTH];					/* dmsetup name when unlocked. Zero-terminated string. */
	uint8_t luks_passphrase_raw[LUKS_PASSPHRASE_RAW_SIZE_BYTES];	/* LUKS passphrase used to unlock volume; raw byte data */
} ALIGNED;

struct host_entry_v2_t {
	uint8_t host_uuid[16];											/* Host UUID */
	char host_name[MAX_HOST_NAME_LENGTH];							/* Descriptive name of host */
	uint8_t tls_psk[PSK_SIZE_BYTES];								/* Raw byte data of TLS-PSK that is used */
	unsigned int volume_count;										/* Number of volumes of this host */
	struct volume_entry_v2_t volumes[MAX_VOLUMES_PER_HOST];			/* Volumes of this host */
} ALIGNED;

struct keydb_v2_t {
	struct keydb_common_header_t common;
	bool server_database;
	unsigned int host_count;
	struct host_entry_v2_t hosts[];
} ALIGNED;

struct volume_entry_v3_t {
	uint8_t volume_uuid[16];										/* UUID of crypt_LUKS volume */
	char devmapper_name[MAX_DEVMAPPER_NAME_LENGTH];					/* dmsetup name when unlocked. Zero-terminated string. */
	uint8_t luks_passphrase_raw[LUKS_PASSPHRASE_RAW_SIZE_BYTES];	/* LUKS passphrase used to unlock volume; raw byte data */
	unsigned int volume_flags;										/* Bitset of enum volume_flag_t */
} ALIGNED;

struct host_entry_v3_t {
	uint8_t host_uuid[16];											/* Host UUID */
	char host_name[MAX_HOST_NAME_LENGTH];							/* Descriptive name of host */
	uint8_t tls_psk[PSK_SIZE_BYTES];								/* Raw byte data of TLS-PSK that is used */
	unsigned int volume_count;										/* Number of volumes of this host */
	unsigned int host_flags;										/* Bitset of enum host_flag_t */
	struct volume_entry_v3_t volumes[MAX_VOLUMES_PER_HOST];			/* Volumes of this host */
} ALIGNED;

struct keydb_v3_t {
	struct keydb_common_header_t common;
	bool server_database;
	unsigned int host_count;
	struct host_entry_v3_t hosts[];
} ALIGNED;


#define KEYDB_CURRENT_VERSION						3
typedef struct volume_entry_v3_t volume_entry_t;
typedef struct host_entry_v3_t host_entry_t;
typedef struct keydb_v3_t keydb_t;


/*************** AUTO GENERATED SECTION FOLLOWS ***************/
keydb_t* keydb_new(void);
keydb_t* keydb_export_public(host_entry_t *host);
void keydb_free(keydb_t *keydb);
volume_entry_t* keydb_get_volume_by_name(host_entry_t *host, const char *devmapper_name);
host_entry_t* keydb_get_host_by_name(keydb_t *keydb, const char *host_name);
const volume_entry_t* keydb_get_volume_by_uuid(const host_entry_t *host, const uint8_t uuid[static 16]);
int keydb_get_host_index(const keydb_t *keydb, const host_entry_t *host);
int keydb_get_volume_index(const host_entry_t *host, const volume_entry_t *volume);
const host_entry_t* keydb_get_host_by_uuid(const keydb_t *keydb, const uint8_t uuid[static 16]);
bool keydb_add_host(keydb_t **keydb, const char *host_name);
bool keydb_del_host_by_name(keydb_t **keydb, const char *host_name);
bool keydb_rekey_host(host_entry_t *host);
volume_entry_t* keydb_add_volume(host_entry_t *host, const char *devmapper_name, const uint8_t volume_uuid[static 16]);
bool keydb_del_volume(host_entry_t *host, const char *devmapper_name);
bool keydb_rekey_volume(volume_entry_t *volume);
bool keydb_get_volume_luks_passphrase(const volume_entry_t *volume, char *dest, unsigned int dest_buffer_size);
bool keydb_write(const keydb_t *keydb, const char *filename, const char *passphrase);
keydb_t* keydb_read(const char *filename);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

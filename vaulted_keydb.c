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

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "vaulted_keydb.h"
#include "log.h"

static struct tls_psk_vault_entry_t *vaulted_keydb_get_tls_psk_for_hostindex(struct vaulted_keydb_t *vkeydb, unsigned int host_index) {
	return ((struct tls_psk_vault_entry_t*)vkeydb->tls_psk_vault->data) + host_index;
}

static struct luks_passphrase_vault_entry_t *vaulted_keydb_get_luks_passphrase_for_hostindex(struct vaulted_keydb_t *vkeydb, unsigned int host_index) {
	return ((struct luks_passphrase_vault_entry_t*)vkeydb->luks_passphrase_vault->data) + host_index;
}

static void copy_data_into_vault(struct vaulted_keydb_t *dest, struct keydb_t *src) {
	for (unsigned int i = 0; i < src->host_count; i++) {
		struct host_entry_t *host = &src->hosts[i];

		/* Copy over TLS-PSK and remove original */
		struct tls_psk_vault_entry_t *dest_tls_psk = vaulted_keydb_get_tls_psk_for_hostindex(dest, i);
		memcpy(&dest_tls_psk->tls_psk, host->tls_psk, PSK_SIZE_BYTES);
		OPENSSL_cleanse(host->tls_psk, PSK_SIZE_BYTES);

		/* Copy over all LUKS keys and remove originals */
		struct luks_passphrase_vault_entry_t *dest_luks_passphrase = vaulted_keydb_get_luks_passphrase_for_hostindex(dest, i);
		for (unsigned int j = 0; j < host->volume_count; j++) {
			struct volume_entry_t *volume = &host->volumes[j];
			memcpy(&dest_luks_passphrase->volumes[j].luks_passphrase_raw, volume->luks_passphrase_raw, LUKS_PASSPHRASE_RAW_SIZE_BYTES);
			OPENSSL_cleanse(volume->luks_passphrase_raw, LUKS_PASSPHRASE_RAW_SIZE_BYTES);
		}
	}
}

static void erase_key_data_from_keydb(struct keydb_t *keydb) {
	for (unsigned int i = 0; i < keydb->host_count; i++) {
		struct host_entry_t *host = &keydb->hosts[i];
		OPENSSL_cleanse(host->tls_psk, PSK_SIZE_BYTES);
		for (unsigned int j = 0; j < host->volume_count; j++) {
			struct volume_entry_t *volume = &host->volumes[j];
			OPENSSL_cleanse(volume->luks_passphrase_raw, LUKS_PASSPHRASE_RAW_SIZE_BYTES);
		}
	}
}

struct vaulted_keydb_t *vaulted_keydb_new(struct keydb_t *keydb) {
	struct vaulted_keydb_t *vaulted_keydb = calloc(1, sizeof(struct vaulted_keydb_t));
	if (!vaulted_keydb) {
		log_msg(LLVL_FATAL, "Unable to calloc(3) vaulted keydb");
		return NULL;
	}

	vaulted_keydb->keydb = keydb;

	vaulted_keydb->tls_psk_vault = vault_init(sizeof(struct tls_psk_vault_entry_t) * keydb->host_count, 0.1);
	if (!vaulted_keydb->tls_psk_vault) {
		log_msg(LLVL_FATAL, "Unable to create TLS-PSK vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	vaulted_keydb->luks_passphrase_vault = vault_init(sizeof(struct luks_passphrase_vault_entry_t) * keydb->host_count, 0.1);
	if (!vaulted_keydb->luks_passphrase_vault) {
		log_msg(LLVL_FATAL, "Unable to create LUKS passphrase vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	/* Now copy over data from the original KeyDB */
	copy_data_into_vault(vaulted_keydb, keydb);

	/* Then erase original key data */
	erase_key_data_from_keydb(keydb);

	/* Finally, close the vaults */
	if (!vault_close(vaulted_keydb->tls_psk_vault)) {
		log_msg(LLVL_FATAL, "Failed to close TLS-PSK vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	if (!vault_close(vaulted_keydb->luks_passphrase_vault)) {
		log_msg(LLVL_FATAL, "Failed to close LUKS passhrase vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	return vaulted_keydb;
}

void vaulted_keydb_free(struct vaulted_keydb_t *vaulted_keydb) {
	vault_free(vaulted_keydb->luks_passphrase_vault);
	vault_free(vaulted_keydb->tls_psk_vault);
	free(vaulted_keydb);
}

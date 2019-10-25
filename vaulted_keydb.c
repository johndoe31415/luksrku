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

static void move_data_into_vault(struct vaulted_keydb_t *dest, struct keydb_t *src) {
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

bool vaulted_keydb_get_tls_psk(struct vaulted_keydb_t *vaulted_keydb, uint8_t dest[PSK_SIZE_BYTES], const struct host_entry_t *host) {
	int host_index = keydb_get_host_index(vaulted_keydb->keydb, host);
	if (host_index < 0) {
		log_msg(LLVL_FATAL, "Unable to retrieve host index for vaulted key db entry.");
		return false;
	}

	/* Get a pointer into the vaulted structure */
	struct tls_psk_vault_entry_t *entry = vaulted_keydb_get_tls_psk_for_hostindex(vaulted_keydb, host_index);

	/* Then decrypt vault */
	if (!vault_open(vaulted_keydb->tls_psk_vault)) {
		log_msg(LLVL_FATAL, "Unable to open TLS-PSK vault of vaulted key db entry.");
		return false;
	}

	/* Copy out the data we need */
	memcpy(dest, &entry->tls_psk, PSK_SIZE_BYTES);

	/* And close it back up */
	if (!vault_close(vaulted_keydb->tls_psk_vault)) {
		OPENSSL_cleanse(dest, PSK_SIZE_BYTES);
		log_msg(LLVL_FATAL, "Unable to close TLS-PSK vault of vaulted key db entry.");
		return false;
	}

	return true;
}

bool vaulted_keydb_get_volume_luks_passphase_raw(struct vaulted_keydb_t *vaulted_keydb, uint8_t dest[LUKS_PASSPHRASE_RAW_SIZE_BYTES], const struct host_entry_t *host, const struct volume_entry_t *volume) {
	int host_index = keydb_get_host_index(vaulted_keydb->keydb, host);
	if (host_index < 0) {
		log_msg(LLVL_FATAL, "Unable to retrieve host index for vaulted key db entry.");
		return false;
	}

	int volume_index = keydb_get_volume_index(host, volume);
	if (volume_index < 0) {
		log_msg(LLVL_FATAL, "Unable to retrieve volume index for vaulted key db entry.");
		return false;
	}

	/* Get a pointer into the vaulted structure */
	struct luks_passphrase_vault_entry_t *entry = vaulted_keydb_get_luks_passphrase_for_hostindex(vaulted_keydb, host_index);

	/* Then decrypt vault */
	if (!vault_open(vaulted_keydb->luks_passphrase_vault)) {
		log_msg(LLVL_FATAL, "Unable to open LUKS passphrase vault of vaulted key db entry.");
		return false;
	}

	/* Copy out the data we need */
	memcpy(dest, &entry->volumes[volume_index].luks_passphrase_raw, LUKS_PASSPHRASE_RAW_SIZE_BYTES);

	/* And close it back up */
	if (!vault_close(vaulted_keydb->luks_passphrase_vault)) {
		OPENSSL_cleanse(dest, PSK_SIZE_BYTES);
		log_msg(LLVL_FATAL, "Unable to close LUKS passphrase vault of vaulted key db entry.");
		return false;
	}
	return true;
}

struct vaulted_keydb_t *vaulted_keydb_new(struct keydb_t *keydb) {
	struct vaulted_keydb_t *vaulted_keydb = calloc(1, sizeof(struct vaulted_keydb_t));
	if (!vaulted_keydb) {
		log_msg(LLVL_FATAL, "Unable to calloc(3) vaulted keydb");
		return NULL;
	}

	vaulted_keydb->keydb = keydb;

	vaulted_keydb->tls_psk_vault = vault_init(sizeof(struct tls_psk_vault_entry_t) * keydb->host_count, 0.025);
	if (!vaulted_keydb->tls_psk_vault) {
		log_msg(LLVL_FATAL, "Unable to create TLS-PSK vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	vaulted_keydb->luks_passphrase_vault = vault_init(sizeof(struct luks_passphrase_vault_entry_t) * keydb->host_count, 0.025);
	if (!vaulted_keydb->luks_passphrase_vault) {
		log_msg(LLVL_FATAL, "Unable to create LUKS passphrase vault");
		vaulted_keydb_free(vaulted_keydb);
		return NULL;
	}

	/* Now move data from the original keydb into the vaulted keydb (erase
	 * original keys) */
	move_data_into_vault(vaulted_keydb, keydb);

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

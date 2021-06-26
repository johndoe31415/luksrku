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

#ifndef __VAULTED_KEYDB_H__
#define __VAULTED_KEYDB_H__

#include "keydb.h"
#include "vault.h"

struct tls_psk_vault_entry_t {
	uint8_t tls_psk[PSK_SIZE_BYTES];
};

struct luks_passphrase_vault_entry_t {
	struct {
		uint8_t luks_passphrase_raw[LUKS_PASSPHRASE_RAW_SIZE_BYTES];
	} volumes[MAX_VOLUMES_PER_HOST];
};

struct vaulted_keydb_t {
	keydb_t *keydb;
	struct vault_t *tls_psk_vault;
	struct vault_t *luks_passphrase_vault;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool vaulted_keydb_get_tls_psk(struct vaulted_keydb_t *vaulted_keydb, uint8_t dest[PSK_SIZE_BYTES], const host_entry_t *host);
bool vaulted_keydb_get_volume_luks_passphases_raw(struct vaulted_keydb_t *vaulted_keydb, void (*copy_callback)(void *ctx, unsigned int volume_index, const void *source), void *copy_ctx, const host_entry_t *host);
struct vaulted_keydb_t *vaulted_keydb_new(keydb_t *keydb);
void vaulted_keydb_free(struct vaulted_keydb_t *vaulted_keydb);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

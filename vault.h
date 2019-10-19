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

#ifndef __VAULT_H__
#define __VAULT_H__

#include <stdbool.h>
#include <stdint.h>

struct vault_t {
	bool is_open;
	void *data;
	unsigned int data_length;
	uint8_t *key;
	unsigned int key_length;
	uint8_t auth_tag[16];
	uint64_t iv;
	unsigned int iteration_cnt;
};

#define DEFAULT_KEY_LENGTH_BYTES		(1024 * 1024)

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct vault_t* vault_init(unsigned int data_length, double target_derivation_time);
bool vault_open(struct vault_t *vault);
bool vault_close(struct vault_t *vault);
void vault_free(struct vault_t *vault);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

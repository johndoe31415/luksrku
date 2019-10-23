/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2016 Johannes Bauer

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

#ifndef __MSG_H__
#define __MSG_H__

#include <stdint.h>
#include "global.h"

struct announcement_t {
	uint8_t magic[16];
	uint8_t host_uuid[16];
} __attribute__ ((packed));

struct msg_t {
	uint8_t volume_uuid[16];
	uint8_t luks_passphrase_raw[LUKS_PASSPHRASE_RAW_SIZE_BYTES];
} __attribute__ ((packed));

staticassert(sizeof(struct msg_t) == 16 + LUKS_PASSPHRASE_RAW_SIZE_BYTES);

#endif

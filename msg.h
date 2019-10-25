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

/* Magic is the prefix of announcement packages. It is the MD5SUM over the
 * string "luksrku v2". This only changes when the protocol that is spoken
 * changes. */
#define UDP_MESSAGE_MAGIC_SIZE								16
#define UDP_MESSAGE_MAGIC									(const uint8_t[UDP_MESSAGE_MAGIC_SIZE]){ 0x46, 0xf2, 0xf6, 0xc6, 0x63, 0x12, 0x2e, 0x00, 0xa0, 0x8a, 0xae, 0x42, 0x0c, 0x51, 0xf5, 0x65 }

struct udp_query_t {
	uint8_t magic[UDP_MESSAGE_MAGIC_SIZE];
	uint8_t host_uuid[16];
} __attribute__ ((packed));

struct udp_response_t {
	uint8_t magic[UDP_MESSAGE_MAGIC_SIZE];
} __attribute__ ((packed));

struct msg_t {
	uint8_t volume_uuid[16];
	uint8_t luks_passphrase_raw[LUKS_PASSPHRASE_RAW_SIZE_BYTES];
} __attribute__ ((packed));

staticassert(sizeof(struct msg_t) == 16 + LUKS_PASSPHRASE_RAW_SIZE_BYTES);

#endif

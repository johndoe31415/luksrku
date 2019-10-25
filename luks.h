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

#ifndef __LUKS_H__
#define __LUKS_H__

#include <stdbool.h>
#include <stdint.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool is_luks_device_opened(const char *mapping_name);
bool open_luks_device(const uint8_t *encrypted_device_uuid, const char *mapping_name, const char *passphrase, unsigned int passphrase_length);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

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

#ifndef __UUID_H__
#define __UUID_H__

#include <stdint.h>
#include <stdbool.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool is_valid_uuid(const char *ascii_uuid);
bool parse_uuid(uint8_t *uuid, const char *ascii_uuid);
void sprintf_uuid(char *buffer, const uint8_t *uuid);
void dump_uuid(FILE *f, const uint8_t *uuid);
bool uuid_randomize(uint8_t uuid[static 16]);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

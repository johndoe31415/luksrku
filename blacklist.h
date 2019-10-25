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

#ifndef __BLACKLIST_H__
#define __BLACKLIST_H__

#include <stdint.h>
#include <stdbool.h>

#define BLACKLIST_ENTRY_COUNT								32
#define BLACKLIST_ENTRY_TIMEOUT_SECS						15

struct blacklist_entry_t {
	uint32_t ip;
	double entered;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void blacklist_ip(uint32_t ip);
bool is_ip_blacklisted(uint32_t ip);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

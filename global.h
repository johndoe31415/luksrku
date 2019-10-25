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

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

/* Size in bytes of the PSK that is used for TLS */
#define PSK_SIZE_BYTES										32

/* How many volumes every host may contain */
#define MAX_VOLUMES_PER_HOST								8

/* How long in characters a host name may be */
#define MAX_HOST_NAME_LENGTH								64

/* How long in characters a cryptsetup device name mapping may be */
#define MAX_DEVMAPPER_NAME_LENGTH							64

/* How long a passphrase is (this is raw binary, not text) */
#define LUKS_PASSPHRASE_RAW_SIZE_BYTES						32

/* How long a passphrase is in it's encoded form, storing it as a character array */
#define LUKS_PASSPHRASE_TEXT_SIZE_BYTES							((((LUKS_PASSPHRASE_RAW_SIZE_BYTES + 2) / 3) * 4) + 1)

/* Number of characters a user-defined passphrase may be long */
#define MAX_PASSPHRASE_LENGTH								256

/* Number of characters a database filename can be long */
#define MAX_FILENAME_LENGTH									256

/* In what interval the server should broadcast that it's waiting for unlocking */
#define WAITING_MESSAGE_BROADCAST_INTERVAL_MILLISECONDS		1000

#define staticassert(cond)		_Static_assert((cond), #cond)

#endif

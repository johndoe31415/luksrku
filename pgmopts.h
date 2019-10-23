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

#ifndef __PGMOPTS_H__
#define __PGMOPTS_H__

#include <stdbool.h>

enum pgmopts_pgm_t {
	PGM_EDIT,
	PGM_SERVER,
	PGM_CLIENT,
};

struct pgmopts_edit_t {
	const char *filename;
	unsigned int verbosity;
};

struct pgmopts_server_t {
	unsigned int verbosity;
};

struct pgmopts_client_t {
	unsigned int verbosity;
};

struct pgmopts_t {
	enum pgmopts_pgm_t pgm;
	union {
		struct pgmopts_edit_t edit;
		struct pgmopts_server_t server;
		struct pgmopts_client_t client;
	};
};

extern const struct pgmopts_t *pgmopts;

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void parse_pgmopts_or_quit(int argc, char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

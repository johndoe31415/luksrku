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

#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#include <stdbool.h>

enum mode_t {
	UNDEFINED = 0,
	SERVER_MODE,
	CLIENT_MODE
};

struct options_t {
	enum mode_t mode;
	int port;
	bool verbose;
	const char *keydbfile;
	int unlock_cnt;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
enum longopts_t;
void print_syntax(const char *pgmname);
bool parse_cmdline_arguments(struct options_t *options, int argc, char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

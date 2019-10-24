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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl.h"
#include "log.h"
#include "pgmopts.h"
#include "editor.h"
#include "openssl.h"
#include "server.h"
#include "client.h"

#if OPENSSL_VERSION_NUMBER < 0x010100000
#error "luksrku requires at least OpenSSL v1.1 to work."
#endif

static int main_edit(const struct pgmopts_edit_t *opts) {
	log_setlvl(LOGLEVEL_DEFAULT + opts->verbosity);
	return editor_start(opts) ? 0 : 1;
}

static int main_server(const struct pgmopts_server_t *opts) {
	log_setlvl(LOGLEVEL_DEFAULT + opts->verbosity);
	return keyserver_start(opts) ? 0 : 1;
}

static int main_client(const struct pgmopts_client_t *opts) {
	log_setlvl(LOGLEVEL_DEFAULT + opts->verbosity);
	return keyclient_start(opts) ? 0 : 1;
}

int main(int argc, char **argv) {
#ifdef DEBUG
	fprintf(stderr, "WARNING: This has been compiled in DEBUG mode and uses reduced security.\n");
#endif
	parse_pgmopts_or_quit(argc, argv);

	if (!openssl_init()) {
		log_msg(LLVL_FATAL, "Could not initialize OpenSSL.");
		exit(EXIT_FAILURE);
	}

	switch (pgmopts->pgm) {
		case PGM_EDIT:
			return main_edit(&pgmopts->edit);

		case PGM_SERVER:
			return main_server(&pgmopts->server);

		case PGM_CLIENT:
			return main_client(&pgmopts->client);
	}
	return 0;
}

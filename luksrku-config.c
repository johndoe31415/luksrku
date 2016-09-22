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
#include <strings.h>

#include "keyfile.h"
#include "parse-keyfile.h"
#include "binkeyfile.h"
#include "util.h"

int main(int argc, char **argv) {
#ifdef DEBUG
	fprintf(stderr, "WARNING: This has been compiled in DEBUG mode and uses reduced security.\n");
#endif

	if (argc != 4) {
		fprintf(stderr, "%s [server|client] [Infile] [Outfile]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	bool server = !strcasecmp(argv[1], "server");
	bool client = !strcasecmp(argv[1], "client");
	if (!server && !client) {
		fprintf(stderr, "First parameter must be either 'client' or 'server'.\n");
		exit(EXIT_FAILURE);
	}

	const char *infile = argv[2];
	const char *outfile = argv[3];

	struct keydb_t keydb;
	if (!parse_keyfile(infile, &keydb, server)) {
		fprintf(stderr, "Failed to parse key file %s. Aborting.\n", infile);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Successfully read key file with %d entries.\n", keydb.entrycnt);

	char *passphrase = NULL;
	if (client) {
		passphrase = query_passphrase("Passphrase to encrypt keyfile: ");
		if (!passphrase) {
			fprintf(stderr, "Failed to get passphrase.\n");
			exit(EXIT_FAILURE);
		}
	}
	if (!write_binary_keyfile(outfile, &keydb, passphrase)) {
		fprintf(stderr, "Failed to write binary key file %s. Aborting.\n", outfile);
		exit(EXIT_FAILURE);
	}
	free(passphrase);

	return 0;
}

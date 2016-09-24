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
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "cmdline.h"

enum longopts_t {
	LONGOPT_VERBOSE,
	LONGOPT_MODE_SERVER,
	LONGOPT_MODE_CLIENT,
	LONGOPT_PORT,
	LONGOPT_KEYDB,
	LONGOPT_UNLOCK_CNT
};

void print_syntax(const char *pgmname) {
	fprintf(stderr, "%s (-c, --client-mode) (-s, --server-mode) (-k, --keydb=FILE) (-u, --unlock=CNT)\n", pgmname);
	fprintf(stderr, "    (-p, --port=PORT) (-v, --verbose)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  -c, --client-mode Specifies client mode, i.e., that this host will unlock the LUKS disk\n");
	fprintf(stderr, "                    of a different machine.\n");
	fprintf(stderr, "  -s, --server-mode Specifies server mode, i.e., that this host will announce its\n");
	fprintf(stderr, "                    presence via UDP broadcasts and then receive the LUKS credentials\n");
	fprintf(stderr, "                    from a peer.\n");
	fprintf(stderr, "  -k, --keydb=FILE  Gives the binary key database file which will be used. In server\n");
	fprintf(stderr, "                    mode, this contains only one entry (specifying the UUID of the host,\n");
	fprintf(stderr, "                    the PSK and the UUIDs and names of the disks to be unlocked), while\n");
	fprintf(stderr, "                    in client mode this may contain multiple entries (to unlock many\n");
	fprintf(stderr, "                    different peers) and also contains the LUKS credentials for the\n");
	fprintf(stderr, "                    respective disks.\n");
	fprintf(stderr, "  -u, --unlock=CNT  Specifies the maximum number of unlocking actions that are taken. In\n");
	fprintf(stderr, "                    client mode, this defaults to 1. In server mode, it defaults to\n");
	fprintf(stderr, "                    infinite (or until all disks have successfully been unlocked). Zero\n");
	fprintf(stderr, "                    means infinite.\n");
	fprintf(stderr, "  -p, --port=PORT   Specifies the port on which is listened for UDP broadcasts and also\n");
	fprintf(stderr, "                    the port on which TCP requests are sent out (the two are always\n");
	fprintf(stderr, "                    identical). Default port ist 23170.\n");
	fprintf(stderr, "  -v, --verbose     Increase logging verbosity.\n");
	fprintf(stderr, "\n");
}

static void set_default_arguments(struct options_t *options) {
	memset(options, 0, sizeof(struct options_t));
	
	/* Default port :-) echo -n LUKS | md5sum | cut -c -5 */ 
	options->port = 23170;

	/* Default, overwritten later by fill_default_arguments() */
	options->unlock_cnt = -1;
}

static void fill_default_arguments(struct options_t *options) {
	/* Set default unlock count */ 
	if (options->unlock_cnt == -1) {
		if (options->mode == CLIENT_MODE) {
			options->unlock_cnt = 1;
		} else if (options->mode == SERVER_MODE) {
			options->unlock_cnt = 0;
		}
	}
}

static bool check_arguments(const struct options_t *options) {
	if (options->mode == UNDEFINED) {
		fprintf(stderr, "Must specify client or server mode.\n");
		return false;
	}
	
	if (options->keydbfile == NULL) {
		fprintf(stderr, "Must specify a key database file.\n");
		return false;
	}

	if ((options->port < 1) || (options->port > 65535)) {
		fprintf(stderr, "Valid port range is 1-65535.\n");
		return false;
	}

	if (options->unlock_cnt < 0) {
		fprintf(stderr, "Unlock count must be a positive integer.\n");
		return false;
	}
	return true;
}

bool parse_cmdline_arguments(struct options_t *options, int argc, char **argv) {
	set_default_arguments(options);

	struct option long_options[] = {
		{ "verbose",		no_argument,		0, LONGOPT_VERBOSE },
		{ "server-mode",	no_argument,		0, LONGOPT_MODE_SERVER },
		{ "client-mode",	no_argument,		0, LONGOPT_MODE_CLIENT },
		{ "port",			required_argument,	0, LONGOPT_PORT },
		{ "keydb",			required_argument,	0, LONGOPT_KEYDB },
		{ "unlock",			required_argument,  0, LONGOPT_UNLOCK_CNT },
		{ 0 }
	};

	bool success = true;
	bool parse = true;
	do {
		int c = getopt_long(argc, argv, "vscp:k:u:", long_options, NULL);
		switch (c) {
			case LONGOPT_VERBOSE:
			case 'v':
				options->verbose = true;
				break;
			
			case LONGOPT_MODE_SERVER:
			case 's':
				options->mode = SERVER_MODE;
				break;
			
			case LONGOPT_MODE_CLIENT:
			case 'c':
				options->mode = CLIENT_MODE;
				break;
			
			case LONGOPT_PORT:
			case 'p':
				options->port = atoi(optarg);
				break;
			
			case LONGOPT_KEYDB:
			case 'k':
				options->keydbfile = optarg;
				break;
			
			case LONGOPT_UNLOCK_CNT:
			case 'u':
				options->unlock_cnt = atoi(optarg);
				break;

			case -1:
				/* Out of arguments */
				parse = false;
				break;

			case '?':
				/* Syntax error */
				parse = false;
				success = false;
				break;

			default:
				fprintf(stderr, "Programming error: unexpected getopt return value %d.\n", c);
				parse = false;
				success = false;
				break;
		}
	} while (parse);

	fill_default_arguments(options);
	return success && check_arguments(options);
}

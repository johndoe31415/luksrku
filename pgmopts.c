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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "pgmopts.h"
#include "argparse_edit.h"
#include "argparse_server.h"

static struct pgmopts_t pgmopts_rw = {
};
const struct pgmopts_t *pgmopts = &pgmopts_rw;

static void show_syntax(const char *errmsg, int argc, char **argv) {
	if (errmsg) {
		fprintf(stderr, "error: %s\n", errmsg);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "Available commands:\n");
	fprintf(stderr, "    %s edit     Interactively edit a key database\n", argv[0]);
	fprintf(stderr, "    %s server   Start a key server process\n", argv[0]);
	fprintf(stderr, "    %s client   Unlock LUKS volumes by querying a key server\n", argv[0]);
	fprintf(stderr, "\n");
	fprintf(stderr, "For futher help: %s (command) --help\n", argv[0]);
}

static bool edit_callback(enum argparse_edit_option_t option, const char *value, argparse_edit_errmsg_callback_t errmsg_callback) {
	pgmopts_rw.edit = (struct pgmopts_edit_t){
		.verbosity = ARGPARSE_EDIT_DEFAULT_VERBOSE,
	};
	switch (option) {
		case ARG_EDIT_FILENAME:
			pgmopts_rw.edit.filename = value;
			break;

		case ARG_EDIT_VERBOSE:
			pgmopts_rw.edit.verbosity++;
			break;
	}
	return true;
}

static bool server_callback(enum argparse_server_option_t option, const char *value, argparse_server_errmsg_callback_t errmsg_callback) {
	pgmopts_rw.server = (struct pgmopts_server_t){
		.port = ARGPARSE_SERVER_DEFAULT_PORT,
		.verbosity = ARGPARSE_SERVER_DEFAULT_VERBOSE,
		.answer_udp_queries = true,
	};
	switch (option) {
		case ARG_SERVER_FILENAME:
			pgmopts_rw.server.filename = value;
			break;

		case ARG_SERVER_PORT:
			pgmopts_rw.server.port = atoi(value);
			break;

		case ARG_SERVER_SILENT:
			pgmopts_rw.server.answer_udp_queries = false;
			break;

		case ARG_SERVER_VERBOSE:
			pgmopts_rw.server.verbosity++;
			break;
	}
	return true;
}

static void parse_pgmopts_edit(int argc, char **argv) {
	argparse_edit_parse_or_quit(argc - 1, argv + 1, edit_callback, NULL);
}

static void parse_pgmopts_server(int argc, char **argv) {
	argparse_server_parse_or_quit(argc - 1, argv + 1, server_callback, NULL);
}

void parse_pgmopts_or_quit(int argc, char **argv) {
	if (argc < 2) {
		show_syntax("no command supplied", argc, argv);
		exit(EXIT_FAILURE);
	}

	const char *command = argv[1];
	if (!strcasecmp(command, "edit")) {
		pgmopts_rw.pgm = PGM_EDIT;
		parse_pgmopts_edit(argc, argv);
	} else if (!strcasecmp(command, "server")) {
		pgmopts_rw.pgm = PGM_SERVER;
		parse_pgmopts_server(argc, argv);
	} else {
		show_syntax("unsupported command supplied", argc, argv);
		exit(EXIT_FAILURE);
	}
}

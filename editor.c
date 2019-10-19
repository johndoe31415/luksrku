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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include "editor.h"
#include "util.h"
#include "keydb.h"

#define MAX_COMMAND_ALIAS_COUNT			2

enum cmd_returncode_t {
	COMMAND_SUCCESS,
	COMMAND_FAILURE,
	COMMAND_TOO_FEW_PARAMETERS,
	COMMAND_TOO_MANY_PARAMETERS,
};

struct editor_context_t {
	bool running;
	struct keydb_t *keydb;
};

struct editor_command_t {
	const char *cmdnames[MAX_COMMAND_ALIAS_COUNT];
	unsigned int min_params;
	unsigned int max_params;
	const char *param_names;
	const char *description;
	enum cmd_returncode_t (*callback)(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
};

static enum cmd_returncode_t cmd_help(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_new(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_list(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_add_host(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_add_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_rekey_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_showkey_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_open(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);
static enum cmd_returncode_t cmd_save(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params);

static const struct editor_command_t commands[] = {
	{
		.cmdnames = { "help", "?" },
		.callback = cmd_help,
		.description = "Shows a help page describing all available commands",
	},
	{
		.cmdnames = { "new" },
		.callback = cmd_new,
		.description = "Create a new database file",
	},
	{
		.cmdnames = { "list" },
		.callback = cmd_list,
		.description = "List contents of database file",
	},
	{
		.cmdnames = { "add_host" },
		.callback = cmd_add_host,
		.param_names = "[hostname]",
		.min_params = 1,
		.max_params = 1,
		.description = "Add a new host to the database file",
	},
	{
		.cmdnames = { "del_host" },
		.callback = cmd_add_host,
		.param_names = "[hostname]",
		.min_params = 1,
		.max_params = 1,
		.description = "Removes a host from the database file",
	},
	{
		.cmdnames = { "add_volume" },
		.callback = cmd_add_volume,
		.param_names = "[hostname] [volumename] [volume-UUID]",
		.min_params = 3,
		.max_params = 3,
		.description = "Add a new volume to the hostname",
	},
	{
		.cmdnames = { "rekey_volume" },
		.callback = cmd_rekey_volume,
		.param_names = "[hostname] [volumename]",
		.min_params = 2,
		.max_params = 2,
		.description = "Re-keys a volume of a given hostname",
	},
	{
		.cmdnames = { "showkey_volume" },
		.callback = cmd_showkey_volume,
		.param_names = "[hostname] [volumename]",
		.min_params = 2,
		.max_params = 2,
		.description = "Shows the key of a volume of a hostname",
	},
	{
		.cmdnames = { "open", "load" },
		.callback = cmd_open,
		.param_names = "[filename]",
		.min_params = 1,
		.max_params = 1,
		.description = "Opens a database file",
	},
	{
		.cmdnames = { "save" },
		.callback = cmd_save,
		.param_names = "([filename])",
		.min_params = 0,
		.max_params = 1,
		.description = "Saves a database file",
	},
	{ { 0 } }
};

static void format_command(char dest[static 128], const struct editor_command_t *cmd, const char *command_name) {
	const char *used_command_name = command_name ? command_name : cmd->cmdnames[0];
	snprintf(dest, 128, "%s%s%s", used_command_name, cmd->param_names ? " " : "", cmd->param_names ? cmd->param_names : "");
}

static enum cmd_returncode_t cmd_help(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	printf("List of commands:\n");
	const struct editor_command_t *cmd = commands;
	while (cmd->cmdnames[0]) {
		char formatted_cmd[128];
		format_command(formatted_cmd, cmd, NULL);
		if (strlen(formatted_cmd) <= 40) {
			printf("    %-40s %s\n", formatted_cmd, cmd->description);
		} else {
			printf("    %s\n    %-40s %s\n", formatted_cmd, "", cmd->description);
		}
		cmd++;
	}
	return COMMAND_SUCCESS;
}

static enum cmd_returncode_t cmd_new(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	if (ctx->keydb) {
		keydb_free(ctx->keydb);
	}
	ctx->keydb = keydb_new();
	return (ctx->keydb != NULL) ? COMMAND_SUCCESS : COMMAND_FAILURE;
}

static enum cmd_returncode_t cmd_list(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	return COMMAND_SUCCESS;
}

static enum cmd_returncode_t cmd_add_host(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	if (!ctx->keydb) {
		ctx->keydb = keydb_new();
		if (!ctx->keydb) {
			return COMMAND_FAILURE;
		}
	}
	struct keydb_t *new_keydb = keydb_add_host(ctx->keydb, params[0]);
	if (new_keydb) {
		ctx->keydb = new_keydb;
	}
	return new_keydb ? COMMAND_SUCCESS : COMMAND_FAILURE;
}

static enum cmd_returncode_t cmd_add_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	return COMMAND_SUCCESS;
}

static enum cmd_returncode_t cmd_rekey_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	return COMMAND_SUCCESS;
}

static enum cmd_returncode_t cmd_showkey_volume(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	return COMMAND_SUCCESS;
}

static enum cmd_returncode_t cmd_open(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	if (ctx->keydb) {
		keydb_free(ctx->keydb);
	}
	ctx->keydb = keydb_read(params[0]);
	return (ctx->keydb != NULL) ? COMMAND_SUCCESS : COMMAND_FAILURE;
}

static enum cmd_returncode_t cmd_save(struct editor_context_t *ctx, const char *cmdname, unsigned int param_cnt, char **params) {
	if (!ctx->keydb) {
		fprintf(stderr, "No key database loaded.\n");
		return COMMAND_FAILURE;
	}
	bool success = keydb_write(ctx->keydb, params[0], "foobar");
	return success ? COMMAND_SUCCESS : COMMAND_FAILURE;
}

static const struct editor_command_t *find_command(const char *command_name) {
	const struct editor_command_t *cmd = commands;
	while (cmd->cmdnames[0]) {
		for (unsigned int cmd_index = 0; cmd_index < MAX_COMMAND_ALIAS_COUNT; cmd_index++) {
			const char *cmdname = cmd->cmdnames[cmd_index];
			if (!cmdname) {
				break;
			}
			if (!strcasecmp(cmdname, command_name)) {
				return cmd;
			}
		}
		cmd++;
	}
	return NULL;
}

static enum cmd_returncode_t execute_command(const struct editor_command_t *cmd, struct editor_context_t *ctx, unsigned int token_count, char **tokens) {
	/* Found correct command */
	const unsigned int parameter_count = token_count - 1;
	if (parameter_count < cmd->min_params) {
		return COMMAND_TOO_FEW_PARAMETERS;
	} else if (parameter_count > cmd->max_params) {
		return COMMAND_TOO_MANY_PARAMETERS;
	} else {
		return cmd->callback(ctx, tokens[0], parameter_count, tokens + 1);
	}
}

void editor_start(void) {
	struct editor_context_t editor_context = {
		.running = true,
	};

	while (editor_context.running) {
		char command_buffer[256];
		printf("> ");
		if (!fgets(command_buffer, sizeof(command_buffer) - 1, stdin)) {
			break;
		}
		if (!truncate_crlf(command_buffer)) {
			/* Incomplete read? */
			break;
		}

		const unsigned int max_token_count = 16;
		unsigned int token_count = 0;
		char *tokens[max_token_count];
		char *strtok_inptr = command_buffer;
		char *strtok_saveptr = NULL;
		while (token_count < max_token_count) {
			char *next_token = strtok_r(strtok_inptr, " \t", &strtok_saveptr);
			if (!next_token) {
				break;
			}
			tokens[token_count] = next_token;
			token_count++;
			strtok_inptr = NULL;
		}

		if (token_count == 0) {
			continue;
		}

		const char *command_name = tokens[0];
		const struct editor_command_t *command = find_command(command_name);
		if (!command) {
			printf("No such command: \"%s\" -- type \"help\" to get a list of valid commands\n", command_name);
			continue;
		}

		enum cmd_returncode_t returncode = execute_command(command, &editor_context, token_count, tokens);
		if (returncode == COMMAND_FAILURE) {
			printf("Execution failed: %s\n", command_name);
		} else if ((returncode == COMMAND_TOO_FEW_PARAMETERS) || (returncode == COMMAND_TOO_MANY_PARAMETERS)) {
			char formatted_cmd[128];
			format_command(formatted_cmd, command, command_name);
			if (command->min_params == command->max_params) {
				printf("Wrong number of parameters: \"%s\" requires %d parameters -- %s\n", command_name, command->min_params, formatted_cmd);
			} else if (returncode == COMMAND_TOO_FEW_PARAMETERS) {
				printf("Too few parameters: \"%s\" requires at least %d parameters -- %s\n", command_name, command->min_params, formatted_cmd);
			} else if (returncode == COMMAND_TOO_MANY_PARAMETERS) {
				printf("Too many parameters: \"%s\" requires at most %d parameters -- %s\n", command_name, command->max_params, formatted_cmd);
			}
		}
	}

	if (editor_context.keydb) {
		keydb_free(editor_context.keydb);
	}
}

#ifndef __TEST_EDITOR__
// gcc -D_POSIX_SOURCE -Wall -std=c11 -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Wimplicit-fallthrough -Wshadow -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak -o editor editor.c util.c log.c keydb.c file_encryption.c -lasan -lubsan -lcrypto && ./editor


int main(int argc, char **argv) {
	editor_start();
	return 0;
}

#endif

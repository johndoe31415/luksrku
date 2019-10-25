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
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "exec.h"
#include "log.h"

void argv_dump(const char **argv) {
	int i = 0;
	while (argv[i]) {
		printf("   %2d: '%s'\n", i, argv[i]);
		i++;
	}
}

static int arg_count(const char **argv) {
	int count = 0;
	while (*argv) {
		count++;
		argv++;
	}
	return count;
}

static void argv_free(char** argv) {
	char **cur = argv;
	while (*cur) {
		free(*cur);
		cur++;
	}
	free(argv);
}

static char **argv_dup(const char **argv) {
	int argc = arg_count(argv);
	char **result = calloc(1, sizeof(char*) * (argc + 1));
	if (!result) {
		log_libc(LLVL_ERROR, "malloc(3) failed in argv_dup");
		return NULL;
	}

	result[argc - 1] = NULL;
	for (int i = 0; i < argc; i++) {
		result[i] = strdup(argv[i]);
		if (!result[i]) {
			log_libc(LLVL_ERROR, "strdup(3) failed in argv_dup");
			argv_free(result);
			return NULL;
		}
	}
	return result;
}

struct exec_result_t exec_command(const struct exec_cmd_t *command) {
	char **argvcopy = argv_dup(command->argv);
	if (!argvcopy) {
		return (struct exec_result_t) { .success = false };
	}

	int pipefd[2];
	if (pipe(pipefd) == -1) {
		log_libc(LLVL_ERROR, "Creation of pipe(2) failed trying to execute %s", argvcopy[0]);
		argv_free(argvcopy);
		return (struct exec_result_t) { .success = false };
	}
	const int pipe_read_end = pipefd[0];
	const int pipe_write_end = pipefd[1];

	pid_t pid = fork();
	if (pid == -1) {
		perror("fork");
		argv_free(argvcopy);
		return (struct exec_result_t) { .success = false };
	}
	if (pid == 0) {
		/* Child */

		close(pipe_write_end);
		if (dup2(pipe_read_end, STDIN_FILENO) == -1) {
			log_libc(LLVL_ERROR, "Could not dup2(2) stdin while trying to execute %s", argvcopy[0]);
			exit(EXIT_FAILURE);
		}

		if (!command->show_output) {
			/* Shut up the child if user did not request debug output */
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
		}
		execvp(argvcopy[0], argvcopy);
		log_libc(LLVL_ERROR, "Execution of %s in forked child process failed execvp(3)", argvcopy[0]);

		/* Exec failed, terminate child with EXIT_FAILURE (parent will catch
		 * this as the return code) */
		exit(EXIT_FAILURE);
	}

	/* Parent process */
	struct exec_result_t runresult = {
		.success = true,
	};
	close(pipe_read_end);

	if (command->stdin_data && command->stdin_length) {
		unsigned int offset = 0;
		unsigned int remaining_bytes = command->stdin_length;
		const uint8_t *byte_buffer = (const uint8_t*)command->stdin_data;
		while (remaining_bytes) {
			ssize_t written = write(pipe_write_end, byte_buffer + offset, remaining_bytes);
			if (written <= 0) {
				log_libc(LLVL_ERROR, "writing to pipe returned %d", written);
				runresult.success = false;
			}
			offset += written;
			remaining_bytes -= written;
		}
	}
	close(pipe_write_end);

	int status;
	if (waitpid(pid, &status, 0) == (pid_t)-1) {
		log_libc(LLVL_ERROR, "exec_command %s failed executing waitpid(2)", argvcopy[0]);
		runresult.success = false;
	} else {
		runresult.returncode = WEXITSTATUS(status);
	}
	argv_free(argvcopy);
	log_msg(LLVL_DEBUG, "Subprocess (PID %d): %s exited with returncode %d", pid, command->argv[0], runresult.returncode);
	return runresult;
}



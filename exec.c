#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
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

struct runresult_t exec_command(const char **argv) {
	struct runresult_t runresult;
	char **argvcopy = argv_dup(argv);

	memset(&runresult, 0, sizeof(runresult));

	pid_t pid = fork();
	if (pid == -1) {
		perror("fork");
		runresult.success = false;
		argv_free(argvcopy);
		return runresult;
	}
	if (pid == 0) {
		/* Child */
		const bool silent = true;
		if (silent) {
			/* Shut up the child if user did not request debug output */
			close(1);
			close(2);
		}
		execvp(argvcopy[0], argvcopy);
		log_libc(LLVL_ERROR, "Execution of %s in forked child process failed execvp(3)", argvcopy[0]);

		/* Exec failed, terminate chExec failed, terminate child process
		 * (parent will catch this as the return code) */
		exit(EXIT_FAILURE);
	}

	int status;
	if (waitpid(pid, &status, 0) == (pid_t)-1) {
		log_libc(LLVL_ERROR, "exec_command %s failed executing waitpid(2)", argvcopy[0]);
		runresult.success = false;
		runresult.returncode = -1;
	} else {
		runresult.success = true;
		runresult.returncode = WEXITSTATUS(status);
	}
	argv_free(argvcopy);
	log_msg(LLVL_DEBUG, "Subprocess (PID %d): %s %s returned %d", pid, argv[0], runresult.success ? "successfully" : "unsuccessfully", runresult.returncode);
	return runresult;
}



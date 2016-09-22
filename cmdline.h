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
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void print_syntax(void);
bool parse_cmdline_arguments(struct options_t *options, int argc, char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

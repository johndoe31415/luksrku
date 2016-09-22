#ifndef __EXEC_H__
#define __EXEC_H__

#include <stdbool.h>

struct runresult_t {
	bool success;
	int returncode;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void argv_dump(const char **argv);
struct runresult_t exec_command(const char **argv);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

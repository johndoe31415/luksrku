#ifndef __BLACKLIST_H__
#define __BLACKLIST_H__

#include <stdint.h>
#include <stdbool.h>

struct blacklist_entry_t {
	uint32_t ip;
	double entered;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void blacklist_ip(uint32_t ip);
bool is_ip_blacklisted(uint32_t ip);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

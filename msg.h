#ifndef __MSG_H__
#define __MSG_H__

#include <stdint.h>
#include "global.h"

struct announcement_t {
	uint8_t magic[16];
	uint8_t host_uuid[16];
} __attribute__ ((packed));

struct msg_t {
	uint8_t disk_uuid[16];
	uint32_t passphrase_length;
	uint8_t passphrase[MAX_PASSPHRASE_LENGTH];
} __attribute__ ((packed));

staticassert(sizeof(struct msg_t) == 16 + 4 + MAX_PASSPHRASE_LENGTH);

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void msg_to_nbo(struct msg_t *msg);
void msg_to_hbo(struct msg_t *msg);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

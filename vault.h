#ifndef __VAULT_H__
#define __VAULT_H__

#include <stdbool.h>
#include <stdint.h>

struct vault_t {
	bool is_open;
	void *data;
	unsigned int data_length;
	bool free_data;
	uint8_t *key;
	unsigned int key_length;
	uint8_t auth_tag[16];
	uint64_t iv;
};

#define DEFAULT_KEY_LENGTH_BYTES		(1024 * 1024)
#define VAULT_PBKDF2_ITERATIONS			50000

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct vault_t * vault_init(void *inner_data, unsigned int data_length);
bool vault_open(struct vault_t *vault);
bool vault_close(struct vault_t *vault);
void vault_free(struct vault_t *vault);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

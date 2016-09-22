#ifndef __BINKEYFILE_H__
#define __BINKEYFILE_H__

#include <stdint.h>
#include <stdbool.h>

#define BINKEYFILE_SALT_SIZE			16
#define BINKEYFILE_KEY_SIZE				32
#define BINKEYFILE_AUTH_TAG_SIZE		16
#define BINKEYFILE_IV_SIZE				16

struct key_t {
	const char *passphrase;
	uint8_t salt[BINKEYFILE_SALT_SIZE];
	uint8_t key[BINKEYFILE_KEY_SIZE];
};

struct binkeyfile_t {
	bool empty_passphrase;
	uint8_t salt[BINKEYFILE_SALT_SIZE];
	uint8_t iv[BINKEYFILE_IV_SIZE];
	uint8_t auth_tag[BINKEYFILE_AUTH_TAG_SIZE];
	uint8_t ciphertext[];
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool read_binary_keyfile(const char *filename, struct keydb_t *keydb);
bool write_binary_keyfile(const char *filename, const struct keydb_t *keydb, const char *passphrase);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

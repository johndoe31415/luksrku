#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "vault.h"

struct vault_t * vault_init(void *inner_data, unsigned int data_length) {
	struct vault_t *vault;

	vault = calloc(1, sizeof(struct vault_t));
	if (!vault) {
		return NULL;
	}

	vault->key = malloc(DEFAULT_KEY_LENGTH_BYTES);
	vault->key_length = DEFAULT_KEY_LENGTH_BYTES;
	if (!vault->key) {
		vault_free(vault);
		return NULL;
	}

	if (inner_data) {
		vault->data = inner_data;
		vault->free_data = false;
	} else {
		vault->free_data = true;
		vault->data = malloc(data_length);
		if (!vault->data) {
			vault_free(vault);
			return NULL;
		}
	}
	vault->is_open = true;
	vault->data_length = data_length;

	return vault;
}

static void vault_destroy_content(struct vault_t *vault) {
	if (vault->data) {
		OPENSSL_cleanse(vault->data, vault->data_length);
	}
	if (vault->key) {
		OPENSSL_cleanse(vault->key, vault->key_length);
	}
}

static bool vault_derive_key(const struct vault_t *vault, uint8_t key[static 32]) {
	/* Derive the AES key from it */
	if (PKCS5_PBKDF2_HMAC((char*)vault->key, vault->key_length, NULL, 0, VAULT_PBKDF2_ITERATIONS, EVP_sha256(), 32, key) != 1) {
		return false;
	}
	return true;
}

bool vault_open(struct vault_t *vault) {
	if (vault->is_open) {
		return true;
	}

	uint8_t key[32];
	if (!vault_derive_key(vault, key)) {
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return false;
	}

	bool success = true;
	do {
		if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
			success = false;
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(uint64_t), NULL) != 1) {
			success = false;
			break;
		}

		if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, (unsigned char*)&vault->iv) != 1) {
			success = false;
			break;
		}

		int len = 0;
		if (EVP_DecryptUpdate(ctx, vault->data, &len, vault->data, vault->data_length) != 1) {
			success = false;
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, vault->auth_tag) != 1) {
			success = false;
			break;
		}

		if (EVP_DecryptFinal_ex(ctx, vault->data + len, &len) != 1) {
			success = false;
			break;
		}

	} while (false);

	if (success) {
		vault->is_open = true;
		OPENSSL_cleanse(vault->key, vault->key_length);
		OPENSSL_cleanse(vault->auth_tag, 16);
	} else {
		/* Vault may be in an inconsistent state. Destroy contents. */
		vault_destroy_content(vault);
	}

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(key, sizeof(key));
	return success;
}

bool vault_close(struct vault_t *vault) {
	if (!vault->is_open) {
		return true;
	}

	/* Generate a new key source */
	if (RAND_bytes(vault->key, vault->key_length) != 1) {
		return false;
	}

	uint8_t key[32];
	if (!vault_derive_key(vault, key)) {
		return false;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return false;
	}

	/* IV doesn't really make sense here because we never reuse the key, but we
	 * still do it for good measure (in case someone copies & pastes our code
	 * into a different application). */
	bool success = true;
	do {
		vault->iv++;
		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
			success = false;
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(uint64_t), NULL) != 1) {
			success = false;
			break;
		}

		if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, (unsigned char*)&vault->iv) != 1) {
			success = false;
			break;
		}

		int len = 0;
		if (EVP_EncryptUpdate(ctx, vault->data, &len, vault->data, vault->data_length) != 1) {
			success = false;
			break;
		}

		if (EVP_EncryptFinal_ex(ctx, vault->data + len, &len) != 1) {
			success = false;
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, vault->auth_tag) != 1) {
			success = false;
			break;
		}
	} while (false);

	if (success) {
		vault->is_open = false;
	} else {
		/* Vault may be in an inconsistent state. Destroy contents. */
		vault_destroy_content(vault);
	}

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(key, sizeof(key));
	return success;
}

void vault_free(struct vault_t *vault) {
	vault_destroy_content(vault);
	if (vault->free_data) {
		free(vault->data);
	}
	free(vault->key);
	free(vault);
}

#ifndef __TEST_VAULT__

static void dump(const uint8_t *data, unsigned int length) {
	for (unsigned int i = 0; i < length; i++) {
		fprintf(stderr, "%02x ", data[i]);
	}
	fprintf(stderr, "\n");
}

int main(void) {
	/* gcc -Wall -std=c11 -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Wimplicit-fallthrough -Wshadow -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak -o vault vault.c -lasan -lubsan -lcrypto
	 */
	uint8_t data[64];
	dump(data, sizeof(data));
	struct vault_t *vault = vault_init(data, sizeof(data));
	if (!vault_close(vault)) {
		fprintf(stderr, "vault close failed.\n");
		abort();
	}
	dump(data, sizeof(data));
	if (!vault_open(vault)) {
		fprintf(stderr, "vault open failed.\n");
		abort();
	}
	dump(data, sizeof(data));
	vault_free(vault);
	return 0;
}
#endif

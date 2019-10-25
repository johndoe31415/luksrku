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
#include <sys/time.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>
#include "vault.h"
#include "util.h"
#include "log.h"

static bool vault_derive_key(const struct vault_t *vault, uint8_t key[static 32]) {
	/* Derive the AES key from it */
	if (PKCS5_PBKDF2_HMAC((char*)vault->key, vault->key_length, NULL, 0, vault->iteration_cnt, EVP_sha256(), 32, key) != 1) {
		return false;
	}
	return true;
}

static double vault_measure_key_derivation_time(struct vault_t *vault, unsigned int new_iteration_count) {
	uint8_t dkey[32];
	double t0, t1;
	vault->iteration_cnt = new_iteration_count;
	t0 = now();
	vault_derive_key(vault, dkey);
	t1 = now();
	OPENSSL_cleanse(dkey, sizeof(dkey));
	return t1 - t0;
}

static void vault_calibrate_derivation_time(struct vault_t *vault, double target_derivation_time) {
	unsigned int iteration_cnt = 1;
	while (iteration_cnt < 100000000) {
		double current_time = vault_measure_key_derivation_time(vault, iteration_cnt);
//		fprintf(stderr, "%d: %f %f\n", iteration_cnt, current_time, target_derivation_time);
		if (current_time * 10 < target_derivation_time) {
			iteration_cnt *= 2;
		} else if (current_time * 1.1 < target_derivation_time) {
			iteration_cnt = iteration_cnt * target_derivation_time / current_time;
		} else {
			break;
		}
	}
}

struct vault_t* vault_init(unsigned int data_length, double target_derivation_time) {
	struct vault_t *vault;

	vault = calloc(1, sizeof(struct vault_t));
	if (!vault) {
		return NULL;
	}

	if (pthread_mutex_init(&vault->mutex, NULL)) {
		log_libc(LLVL_FATAL, "Unable to initialize vault mutex.");
		free(vault);
		return NULL;
	}
	vault->key = malloc(DEFAULT_KEY_LENGTH_BYTES);
	vault->key_length = DEFAULT_KEY_LENGTH_BYTES;
	if (!vault->key) {
		vault_free(vault);
		return NULL;
	}

	vault->data = calloc(data_length, 1);
	if (!vault->data) {
		vault_free(vault);
		return NULL;
	}
	vault->reference_count = 1;
	vault->data_length = data_length;
	vault_calibrate_derivation_time(vault, target_derivation_time);

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

static bool vault_decrypt(struct vault_t *vault) {
	uint8_t dkey[32];
	if (!vault_derive_key(vault, dkey)) {
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

		if (EVP_DecryptInit_ex(ctx, NULL, NULL, dkey, (unsigned char*)&vault->iv) != 1) {
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

		if (EVP_DecryptFinal_ex(ctx, (uint8_t*)vault->data + len, &len) != 1) {
			success = false;
			break;
		}

	} while (false);

	if (success) {
		OPENSSL_cleanse(vault->key, vault->key_length);
		OPENSSL_cleanse(vault->auth_tag, 16);
	} else {
		/* Vault may be in an inconsistent state. Destroy contents. */
		vault_destroy_content(vault);
	}

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(dkey, sizeof(dkey));
	return success;
}

bool vault_open(struct vault_t *vault) {
	bool success = true;
	pthread_mutex_lock(&vault->mutex);
	vault->reference_count++;
	if (vault->reference_count == 1) {
		/* Vault was closed, we need to decrypt it. */
		success = vault_decrypt(vault);
	}
	pthread_mutex_unlock(&vault->mutex);
	return success;
}

static bool vault_encrypt(struct vault_t *vault) {
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

		if (EVP_EncryptFinal_ex(ctx, (uint8_t*)vault->data + len, &len) != 1) {
			success = false;
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, vault->auth_tag) != 1) {
			success = false;
			break;
		}
	} while (false);

	if (!success) {
		/* Vault may be in an inconsistent state. Destroy contents. */
		vault_destroy_content(vault);
	}

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_cleanse(key, sizeof(key));
	return success;
}

bool vault_close(struct vault_t *vault) {
	bool success = true;
	pthread_mutex_lock(&vault->mutex);
	vault->reference_count--;
	if (vault->reference_count == 0) {
		/* Vault is now closed, we need to encrypt it. */
		success = vault_encrypt(vault);
	}
	pthread_mutex_unlock(&vault->mutex);
	return success;
}


void vault_free(struct vault_t *vault) {
	if (!vault) {
		return;
	}
	vault_destroy_content(vault);
	free(vault->data);
	free(vault->key);
	free(vault);
}

#ifdef __TEST_VAULT__

static void dump(const uint8_t *data, unsigned int length) {
	for (unsigned int i = 0; i < length; i++) {
		fprintf(stderr, "%02x ", data[i]);
	}
	fprintf(stderr, "\n");
}

int main(void) {
	/* gcc -D__TEST_VAULT__ -Wall -std=c11 -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Wimplicit-fallthrough -Wshadow -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak -pthread -o vault vault.c util.c log.c -lcrypto
	 */
	struct vault_t *vault = vault_init(64, 0.1);
	dump(vault->data, vault->data_length);
	for (int i = 0; i < 10; i++) {
		if (!vault_close(vault)) {
			fprintf(stderr, "vault close failed.\n");
			abort();
		}
		dump(vault->data, vault->data_length);
		if (!vault_open(vault)) {
			fprintf(stderr, "vault open failed.\n");
			abort();
		}
		dump(vault->data, vault->data_length);
	}
	vault_free(vault);
	return 0;
}
#endif

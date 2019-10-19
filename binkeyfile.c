/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2016 Johannes Bauer

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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "openssl.h"
#include "keyfile.h"
#include "binkeyfile.h"
#include "log.h"
#include "util.h"
#include "global.h"

#ifdef DEBUG
static void dump_key(const struct key_t *key) {
	fprintf(stderr, "Dumping key:\n");
	fprintf(stderr, "   Passphrase : %s\n", key->passphrase);
	fprintf(stderr, "   Salt       : ");
	dump_hex(stderr, key->salt, BINKEYFILE_SALT_SIZE);
	fprintf(stderr, "\n");
	fprintf(stderr, "   Derived key: ");
	dump_hex(stderr, key->key, BINKEYFILE_KEY_SIZE);
	fprintf(stderr, "\n");
}
#endif


/* Derives a previous key with known salt. Passphrase and salt must be set. */
static bool derive_previous_key(struct key_t *key) {
	const unsigned int maxalloc_mib = 8 + ((128 * SCRYPT_N * SCRYPT_r * SCRYPT_p + (1024 * 1024 - 1)) / 1024 / 1024);
	log_msg(LLVL_DEBUG, "Deriving scrypt key with N = %u, r = %u, p = %u, i.e., ~%u MiB of memory", SCRYPT_N, SCRYPT_r, SCRYPT_p, maxalloc_mib);

	const char *passphrase = (key->passphrase == NULL) ? "" : key->passphrase;
	int pwlen = strlen(passphrase);
	int result = EVP_PBE_scrypt(passphrase, pwlen, (unsigned char*)key->salt, BINKEYFILE_SALT_SIZE, SCRYPT_N, SCRYPT_r, SCRYPT_p, maxalloc_mib * 1024 * 1024, key->key, BINKEYFILE_KEY_SIZE);
	if (result != 1) {
		log_msg(LLVL_FATAL, "Fatal: key derivation using scrypt failed");
		return false;
	}
#ifdef DEBUG
	dump_key(key);
#endif
	return true;
}

static bool encrypt_aes256_gcm(const void *plaintext, unsigned int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
	bool success = true;
	log_msg(LLVL_DEBUG, "Encrypting %u bytes of plaintext using AES256-GCM", plaintext_len);

	EVP_CIPHER_CTX *ctx = NULL;
	do {
		/* Create and initialise the context */
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			log_openssl(LLVL_FATAL, "Cannot create EVP_CIPHER_CTX for encryption");
			success = false;
			break;
		}
		if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
			log_openssl(LLVL_FATAL, "Error in EVP_EncryptInit_ex");
			success = false;
			break;
		}

		/* Set IV length to 128 bit */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
			log_openssl(LLVL_FATAL, "Error setting IV length for encryption");
			success = false;
			break;
		}

		/* Initialise key and IV */
		if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
			log_openssl(LLVL_FATAL, "Error setting encryption key and IV");
			success = false;
			break;
		}

		/* Provide the message to be encrypted, and obtain the encrypted output. */
		int ciphertext_len = 0;
		if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)) {
			log_openssl(LLVL_FATAL, "Error encrypting data");
			success = false;
			break;
		}
		if (ciphertext_len != (int)plaintext_len) {
			log_openssl(LLVL_FATAL, "Unexpected deviation from plaintext length (%d bytes) to ciphertext length (%d bytes) during encryption", plaintext_len, ciphertext_len);
			success = false;
			break;
		}

		/* Finalise the encryption. Normally ciphertext bytes may be written at
		 * this stage, but this does not occur in GCM mode. */
		int padding_len = 0;
		if (!EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &padding_len)) {
			log_openssl(LLVL_FATAL, "Encryption of tail failed.");
			success = false;
			break;
		}
		if (padding_len != 0) {
			log_openssl(LLVL_FATAL, "Unexpected deviation from expected padding length (got %d bytes) during encryption", padding_len);
			success = false;
			break;
		}

		/* Get the authentication tag */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
			log_openssl(LLVL_FATAL, "Failed to retrieve authentication tag");
			success = false;
			break;
		}
	} while (false);

	/* Clean up */
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return success;
}

static bool decrypt_aes256_gcm(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *iv, void *plaintext) {
	bool success = true;
	log_msg(LLVL_DEBUG, "Decrypting %u bytes of ciphertext using AES256-GCM", ciphertext_len);

	EVP_CIPHER_CTX *ctx = NULL;
	do {
		/* Create and initialise the context */
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			log_openssl(LLVL_FATAL, "Cannot create EVP_CIPHER_CTX for decryption");
			success = false;
			break;
		}

		if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
			log_openssl(LLVL_FATAL, "Error in EVP_DecryptInit_ex");
			success = false;
			break;
		}

		/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
			log_openssl(LLVL_FATAL, "Error setting IV length for decryption");
			success = false;
			break;
		}

		/* Initialise key and IV */
		if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
			log_openssl(LLVL_FATAL, "Error setting decryption key and IV");
			success = false;
			break;
		}

		/* Provide the message to be decrypted, and obtain the plaintext output.
		 * EVP_DecryptUpdate can be called multiple times if necessary
		 */
		int plaintext_len = 0;
		if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len)) {
			log_openssl(LLVL_FATAL, "Error decrypting data");
			success = false;
			break;
		}
		if (plaintext_len != (int)ciphertext_len) {
			log_openssl(LLVL_FATAL, "Unexpected deviation from plaintext length (%d bytes) to ciphertext length (%d bytes) during decryption", plaintext_len, ciphertext_len);
			success = false;
			break;
		}

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
			log_openssl(LLVL_FATAL, "Error setting authentication tag length");
			success = false;
			break;
		}

		/* Finalise the decryption. A positive return value indicates success,
		 * anything else is a failure - the plaintext is not trustworthy. */
		int padding_len = 0;
		if (EVP_DecryptFinal_ex(ctx, (uint8_t*)plaintext + plaintext_len, &padding_len) <= 0) {
			log_openssl(LLVL_FATAL, "Decryption of tail failed.");
			success = false;
			break;
		}
		if (padding_len != 0) {
			log_openssl(LLVL_FATAL, "Unexpected deviation from expected padding length (got %d bytes) during decryption", padding_len);
			success = false;
			break;
		}
	} while (false);

	/* Clean up */
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return success;
}

/* Generates a random salt and derives a new key. Passphrase must be set. */
static bool derive_new_key(struct key_t *key) {
	if (!RAND_bytes(key->salt, BINKEYFILE_SALT_SIZE)) {
		log_msg(LLVL_FATAL, "Cannot get salt entropy from RAND_bytes()");
		return false;
	}
	return derive_previous_key(key);
}

bool read_binary_keyfile(const char *filename, struct keydb_t *keydb) {
	bool success = true;
	struct binkeyfile_t *binkeyfile = NULL;
	struct keyentry_t *plaintext = NULL;

	unsigned int binkeyfile_size = 0;
	unsigned int plaintext_size = 0;
	do {
		memset(keydb, 0, sizeof(struct keydb_t));

		/* Stat the file first to find out the size */
		struct stat statbuf;
		if (stat(filename, &statbuf) == -1) {
			log_libc(LLVL_ERROR, "stat of %s failed", filename);
			success = false;
			break;
		}

		/* Check if this is long enough to be a key file */
		binkeyfile_size = statbuf.st_size;
		if (binkeyfile_size < sizeof(struct binkeyfile_t)) {
			log_msg(LLVL_ERROR, "Keyfile size of %s is too small to be valid (%d bytes).", filename, statbuf.st_size);
			success = false;
			break;
		}

		/* Check if the payload is a multiple of the keyent_t structure */
		const unsigned int ciphertext_size = binkeyfile_size - sizeof(struct binkeyfile_t);
		if ((ciphertext_size % sizeof(struct keyentry_t)) != 0) {
			log_msg(LLVL_ERROR, "Keyfile size of %s has impossible/invalid file size (%d bytes not a multiple of %lu bytes).", filename, statbuf.st_size, sizeof(struct keyentry_t));
			success = false;
			break;
		}

		/* Now allocate memory for plain- and ciphertext */
		plaintext_size = ciphertext_size;
		binkeyfile = calloc(1, binkeyfile_size);
		plaintext = calloc(1, plaintext_size);

		/* And read the file in */
		FILE *f = fopen(filename, "r");
		if (!f) {
			log_libc(LLVL_ERROR, "fopen");
			success = false;
			break;
		}
		if (fread(binkeyfile, binkeyfile_size, 1, f) != 1) {
			log_libc(LLVL_ERROR, "fread");
			success = false;
			break;
		}
		fclose(f);

		/* Copy the file's salt into the key structure so we can derive the
		 * proper decryption key */
		struct key_t key;
		memset(&key, 0, sizeof(struct key_t));
		memcpy(key.salt, binkeyfile->salt, BINKEYFILE_IV_SIZE);

		/* Get the passphrase from the user (if it is protected with one) */
		char *user_passphrase = NULL;
		if (binkeyfile->empty_passphrase) {
			key.passphrase = "";
		} else {
			user_passphrase = query_passphrase("Keyfile password: ");
			if (!user_passphrase) {
				log_msg(LLVL_FATAL, "Failed to query passphrase.");
				success = false;
				break;
			}
			key.passphrase = user_passphrase;
		}

		/* Then derive the key */
		if (!derive_previous_key(&key)) {
			log_msg(LLVL_FATAL, "Key derivation failed.");
			success = false;
			break;
		}

		/* If we used a passphrase, free it again */
		if (user_passphrase) {
			key.passphrase = NULL;
			memset(user_passphrase, 0, MAX_PASSPHRASE_LENGTH);
			free(user_passphrase);
		}

		/* Then do the decryption and check if authentication is OK */
		bool decryption_successful = decrypt_aes256_gcm(binkeyfile->ciphertext, ciphertext_size, binkeyfile->auth_tag, key.key, binkeyfile->iv, plaintext);
		if (!decryption_successful) {
			log_msg(LLVL_FATAL, "Decryption error. Wrong passphrase or given file corrupt.");
			success = false;
			break;
		}

		/* Finally copy the decrypted linear file over to the keydb_t structure
		 **/
		for (unsigned int i = 0; i < plaintext_size / sizeof(struct keyentry_t); i++) {
			if (!add_keyslot(keydb)) {
				log_msg(LLVL_FATAL, "Failed to add keyslot.");
				success = false;
				break;
			}
			memcpy(last_keyentry(keydb), &plaintext[i], sizeof(struct keyentry_t));
		}
	} while (false);

	if (plaintext) {
		memset(plaintext, 0, plaintext_size);
		free(plaintext);
	}
	if (binkeyfile) {
		memset(binkeyfile, 0, binkeyfile_size);
		free(binkeyfile);
	}
	return success;
}

bool write_binary_keyfile(const char *filename, const struct keydb_t *keydb, const char *passphrase) {
	struct key_t key;
	memset(&key, 0, sizeof(struct key_t));
	key.passphrase = passphrase;
	if (!derive_new_key(&key)) {
		log_msg(LLVL_FATAL, "Key derivation failed.");
		return false;
	}

	/* Allocate memory for plain- and ciphertext */
	const unsigned int payload_size = keydb->entrycnt * sizeof(struct keyentry_t);
	const unsigned int binkeyfile_size = sizeof(struct binkeyfile_t) + payload_size;
	struct keyentry_t *plaintext = calloc(1, payload_size);
	struct binkeyfile_t *binkeyfile = calloc(1, binkeyfile_size);
	if (!plaintext || !binkeyfile) {
		log_libc(LLVL_FATAL, "malloc(3) plaintext or binkeyfile failed");
		return false;
	}

	/* Randomize encrypting IV and copy over key salt */
	if (RAND_bytes(binkeyfile->iv, BINKEYFILE_IV_SIZE) != 1) {
		log_openssl(LLVL_FATAL, "Failed to get entropy from RAND_bytes for IV");
		return false;

	}
	memcpy(binkeyfile->salt, key.salt, BINKEYFILE_SALT_SIZE);
	binkeyfile->empty_passphrase = (passphrase == NULL) || (strlen(passphrase) == 0);

	/* Copy plaintext into linear data array to prepare for encryption */
	for (int i = 0; i < keydb->entrycnt; i++) {
		memcpy(&plaintext[i], &keydb->entries[i], sizeof(struct keyentry_t));
	}

	/* Encrypt */
	if (!encrypt_aes256_gcm(plaintext, payload_size, key.key, binkeyfile->iv, binkeyfile->ciphertext, binkeyfile->auth_tag)) {
		log_libc(LLVL_FATAL, "encryption failed");
		return false;
	}

	/* Write encrypted data to file */
	FILE *f = fopen(filename, "w");
	bool success = true;
	if (f) {
		if (fwrite(binkeyfile, binkeyfile_size, 1, f) != 1) {
			log_libc(LLVL_ERROR, "fwrite(3) into %s failed", filename);
			success = false;
		}
		fclose(f);
	} else {
		log_libc(LLVL_ERROR, "fopen(3) of %s failed", filename);
		success = false;
		return false;
	}

	/* Destroy plaintext copy before freeing memory */
	memset(plaintext, 0, payload_size);
	free(plaintext);
	return success;
}


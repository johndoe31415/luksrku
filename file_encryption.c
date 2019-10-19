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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "openssl.h"
#include "file_encryption.h"
#include "log.h"
#include "util.h"
#include "global.h"

struct key_t {
	const char *passphrase;
	enum kdf_t kdf;
	uint8_t salt[ENCRYPTED_FILE_SALT_SIZE];
	uint8_t key[ENCRYPTED_FILE_KEY_SIZE];
};

#ifdef DEBUG
static void dump_key(const struct key_t *key) {
	fprintf(stderr, "Dumping key:\n");
	fprintf(stderr, "   Passphrase : %s\n", key->passphrase);
	fprintf(stderr, "   Salt       : ");
	dump_hex(stderr, key->salt, ENCRYPTED_FILE_SALT_SIZE);
	fprintf(stderr, "\n");
	fprintf(stderr, "   Derived key: ");
	dump_hex(stderr, key->key, ENCRYPTED_FILE_KEY_SIZE);
	fprintf(stderr, "\n");
}
#endif


/* Derives a previous key with known salt. Passphrase and salt must be set. */
static bool derive_previous_key(struct key_t *key) {
	const char *passphrase = (key->passphrase == NULL) ? "" : key->passphrase;
	const unsigned int pwlen = strlen(passphrase);

	if ((key->kdf >= KDF_SCRYPT_MIN) && (key->kdf <= KDF_SCRYPT_MAX)) {
		unsigned int N, r, p;
		switch (key->kdf) {
			case KDF_SCRYPT_N17_r8_p1:
				N = 1 << 17;
				r = 8;
				p = 1;
				break;

			case KDF_SCRYPT_N18_r8_p1:
				N = 1 << 18;
				r = 8;
				p = 1;
				break;

			default:
				log_msg(LLVL_FATAL, "Fatal: unknown scrypt key derivation function (0x%x)", key->kdf);
				return false;
		}

		const unsigned int maxalloc_mib = 8 + ((128 * N * r * p + (1024 * 1024 - 1)) / 1024 / 1024);
		log_msg(LLVL_DEBUG, "Deriving scrypt key with N = %u, r = %u, p = %u, i.e., ~%u MiB of memory", N, r, p, maxalloc_mib);

		int result = EVP_PBE_scrypt(passphrase, pwlen, (const unsigned char*)key->salt, ENCRYPTED_FILE_SALT_SIZE, N, r, p, maxalloc_mib * 1024 * 1024, key->key, ENCRYPTED_FILE_KEY_SIZE);
		if (result != 1) {
			log_msg(LLVL_FATAL, "Fatal: key derivation using scrypt failed");
			return false;
		}
	} else if ((key->kdf >= KDF_PBKDF2_MIN) && (key->kdf <= KDF_PBKDF2_MAX)) {
		unsigned int iterations;
		switch (key->kdf) {
			case KDF_PBKDF2_SHA256_1000:
				iterations = 1000;
				break;

			default:
				log_msg(LLVL_FATAL, "Fatal: unknown PBKDF2 key derivation function (0x%x)", key->kdf);
				return false;
		}

		int result = PKCS5_PBKDF2_HMAC(passphrase, pwlen, (const unsigned char*)key->salt, ENCRYPTED_FILE_SALT_SIZE, iterations, EVP_sha256(), ENCRYPTED_FILE_KEY_SIZE, key->key);
		if (result != 1) {
			log_msg(LLVL_FATAL, "Fatal: key derivation using PBKDF2 failed");
			return false;
		}
	} else {
		log_msg(LLVL_FATAL, "Fatal: unknown key derivation function (0x%x)", key->kdf);
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
	if (!RAND_bytes(key->salt, ENCRYPTED_FILE_SALT_SIZE)) {
		log_msg(LLVL_FATAL, "Cannot get salt entropy from RAND_bytes()");
		return false;
	}
	return derive_previous_key(key);
}

struct decrypted_file_t read_encrypted_file(const char *filename) {
	struct decrypted_file_t result = {
		.success = true,
		.data = NULL,
	};
	struct encrypted_file_t *encrypted_file = NULL;

	do {
		/* Stat the file first to find out the size */
		struct stat statbuf;
		if (stat(filename, &statbuf) == -1) {
			log_libc(LLVL_ERROR, "stat of %s failed", filename);
			result.success = false;
			break;
		}

		/* Check if the file is long enough to be an encrypted file */
		const unsigned int encrypted_file_size = statbuf.st_size;
		if (encrypted_file_size < sizeof(struct encrypted_file_t)) {
			log_msg(LLVL_ERROR, "%s: too small to be encrypted file (%u bytes)", encrypted_file_size);
			result.success = false;
			break;
		}

		/* Now allocate memory for plain- and ciphertext */
		encrypted_file = malloc(encrypted_file_size);
		if (!encrypted_file) {
			log_libc(LLVL_ERROR, "malloc(3) of encrypted file (%u bytes) failed", encrypted_file_size);
			result.success = false;
			break;
		}

		const unsigned int ciphertext_size = encrypted_file_size - sizeof(struct encrypted_file_t);
		const unsigned int plaintext_size = ciphertext_size;
		result.data_length = plaintext_size;
		result.data = malloc(plaintext_size);
		if (!result.data) {
			log_libc(LLVL_ERROR, "malloc(3) of plaintext (%u bytes) failed", plaintext_size);
			result.success = false;
			break;
		}

		/* Read in the encrypted file */
		FILE *f = fopen(filename, "r");
		if (!f) {
			log_libc(LLVL_ERROR, "fopen");
			result.success = false;
			break;
		}
		if (fread(encrypted_file, encrypted_file_size, 1, f) != 1) {
			log_libc(LLVL_ERROR, "fread");
			result.success = false;
			fclose(f);
			break;
		}
		fclose(f);

		/* Copy the file's salt into the key structure so we can derive the
		 * proper decryption key */
		struct key_t key;
		memset(&key, 0, sizeof(struct key_t));
		memcpy(key.salt, encrypted_file->salt, ENCRYPTED_FILE_IV_SIZE);
		key.kdf = encrypted_file->kdf;

		/* Get the passphrase from the user (if it is protected with one) */
		char *user_passphrase = NULL;
		if (encrypted_file->empty_passphrase) {
			key.passphrase = "";
		} else {
			user_passphrase = query_passphrase("Keyfile password: ", MAX_PASSPHRASE_LENGTH);
			if (!user_passphrase) {
				log_msg(LLVL_FATAL, "Failed to query passphrase.");
				result.success = false;
				break;
			}
			key.passphrase = user_passphrase;
		}

		/* Then derive the key */
		if (!derive_previous_key(&key)) {
			log_msg(LLVL_FATAL, "Key derivation failed.");
			result.success = false;
			break;
		}

		/* If we used a passphrase, free it again */
		if (user_passphrase) {
			key.passphrase = NULL;
			OPENSSL_cleanse(user_passphrase, MAX_PASSPHRASE_LENGTH);
			free(user_passphrase);
		}

		/* Then do the decryption and check if authentication is OK */
		bool decryption_successful = decrypt_aes256_gcm(encrypted_file->ciphertext, ciphertext_size, encrypted_file->auth_tag, key.key, encrypted_file->iv, result.data);
		if (!decryption_successful) {
			log_msg(LLVL_FATAL, "Decryption error. Wrong passphrase or given file corrupt.");
			result.success = false;
			break;
		}
	} while (false);

	if (!result.success) {
		if (result.data) {
			OPENSSL_cleanse(result.data, result.data_length);
			free(result.data);
		}
		result.data = NULL;
		result.data_length = 0;
	}
	if (encrypted_file) {
		free(encrypted_file);
	}
	return result;
}

bool write_encrypted_file(const char *filename, const void *plaintext, unsigned int plaintext_length, const char *passphrase, enum kdf_t kdf) {
	struct key_t key = {
		.passphrase = passphrase ? passphrase : "",
		.kdf = kdf,
	};
	if (!derive_new_key(&key)) {
		log_msg(LLVL_FATAL, "Key derivation failed.");
		return false;
	}

	/* Allocate memory for plain- and ciphertext */
	const unsigned int ciphertext_length = plaintext_length;
	const unsigned int encrypted_file_size = sizeof(struct encrypted_file_t) + ciphertext_length;
	struct encrypted_file_t *encrypted_file = calloc(1, encrypted_file_size);
	if (!encrypted_file) {
		log_libc(LLVL_FATAL, "malloc(3) of encrypted_file failed");
		OPENSSL_cleanse(&key, sizeof(key));
		return false;
	}

	/* Initialize encrypted file structure */
	encrypted_file->empty_passphrase = (strlen(key.passphrase) == 0) ? 1 : 0;
	encrypted_file->kdf = key.kdf;
	memcpy(encrypted_file->salt, key.salt, ENCRYPTED_FILE_SALT_SIZE);

	/* Randomize encrypting IV */
	if (RAND_bytes(encrypted_file->iv, ENCRYPTED_FILE_IV_SIZE) != 1) {
		log_openssl(LLVL_FATAL, "Failed to get entropy from RAND_bytes for IV");
		OPENSSL_cleanse(&key, sizeof(key));
		free(encrypted_file);
		return false;
	}

	/* Encrypt and authenticate plaintext */
	if (!encrypt_aes256_gcm(plaintext, plaintext_length, key.key, encrypted_file->iv, encrypted_file->ciphertext, encrypted_file->auth_tag)) {
		log_libc(LLVL_FATAL, "encryption failed");
		OPENSSL_cleanse(&key, sizeof(key));
		free(encrypted_file);
		return false;
	}

	/* Destroy derived key */
	OPENSSL_cleanse(&key, sizeof(key));

	/* Write encrypted data to file */
	FILE *f = fopen(filename, "w");
	bool success = true;
	if (f) {
		if (fwrite(encrypted_file, encrypted_file_size, 1, f) != 1) {
			log_libc(LLVL_ERROR, "fwrite(3) into %s failed", filename);
			success = false;
		}
		fclose(f);
	} else {
		log_libc(LLVL_ERROR, "fopen(3) of %s failed", filename);
		success = false;
		return false;
	}

	free(encrypted_file);
	return success;
}

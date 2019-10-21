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

#ifndef __FILE_ENCRYPTION_H__
#define __FILE_ENCRYPTION_H__

#include <stdint.h>
#include <stdbool.h>

enum kdf_t {
	KDF_SCRYPT_MIN = 1,
	KDF_SCRYPT_N17_r8_p1 = KDF_SCRYPT_MIN + 0,
	KDF_SCRYPT_N18_r8_p1 = KDF_SCRYPT_MIN + 1,
	KDF_SCRYPT_MAX = KDF_SCRYPT_MIN + 1,

	KDF_PBKDF2_MIN = 0x100,
	KDF_PBKDF2_SHA256_1000 = KDF_PBKDF2_MIN + 0,		/* Deliberately crappy KDF for use with empty passphrases */
	KDF_PBKDF2_MAX = KDF_PBKDF2_MIN + 0,
};

#define ENCRYPTED_FILE_DEFAULT_KDF			KDF_SCRYPT_N17_r8_p1
#define ENCRYPTED_FILE_SALT_SIZE			16
#define ENCRYPTED_FILE_KEY_SIZE				32
#define ENCRYPTED_FILE_AUTH_TAG_SIZE		16
#define ENCRYPTED_FILE_IV_SIZE				16

typedef bool (*passphrase_callback_function_t)(char *buffer, unsigned int bufsize);

struct encrypted_file_t {
	uint32_t empty_passphrase;
	uint32_t kdf;
	uint8_t salt[ENCRYPTED_FILE_SALT_SIZE];
	uint8_t iv[ENCRYPTED_FILE_IV_SIZE];
	uint8_t auth_tag[ENCRYPTED_FILE_AUTH_TAG_SIZE];
	uint8_t ciphertext[];
};

struct decrypted_file_t {
	bool success;
	unsigned int data_length;
	void *data;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct decrypted_file_t read_encrypted_file(const char *filename, passphrase_callback_function_t passphrase_callback);
bool write_encrypted_file(const char *filename, const void *plaintext, unsigned int plaintext_length, const char *passphrase, enum kdf_t kdf);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

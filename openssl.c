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

#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl.h"
#include "log.h"

bool openssl_init(void) {
	OpenSSL_add_all_algorithms();
	return true;
}

bool create_generic_tls_context(struct generic_tls_ctx_t *gctx, bool server) {
	memset(gctx, 0, sizeof(struct generic_tls_ctx_t));

	gctx->conf_ctx = SSL_CONF_CTX_new();
	if (!gctx->conf_ctx) {
		log_openssl(LLVL_FATAL, "Cannot initialize TLS generic context config context.");
		return false;
	}

	if (server) {
		gctx->method = TLS_server_method();
		if (!gctx->method) {
			log_openssl(LLVL_FATAL, "Cannot initialize TLS server method.");
			return false;
		}
	} else {
		gctx->method = TLS_client_method();
		if (!gctx->method) {
			log_openssl(LLVL_FATAL, "Cannot initialize TLS client method.");
			return false;
		}
	}

	gctx->ctx = SSL_CTX_new(gctx->method);
	if (!gctx->ctx) {
		log_openssl(LLVL_FATAL, "Cannot initialize TLS generic context context.");
		return false;
	}

	/* Disable insecure previous protocol variants */
	/* Disable compression (not secure, should be disabled everywhere) */
	/* Disable DH param reuse (we use ECDH and this doesn't affect us, but in case someone changes to EDH) */
	/* Disable session resumption (unnecessary attack surface) */
	/* Disable resumption on renegotiation (unnecessary attack surface) */
	/* TODO: Disable renegotiation altogether! How? */
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	SSL_CTX_set_options(gctx->ctx, flags);

	if (!SSL_CTX_set_min_proto_version(gctx->ctx, TLS1_3_VERSION)) {
		log_openssl(LLVL_FATAL, "Cannot set TLS generic context minimal version.");
		return false;
	}

	if (!SSL_CTX_set_max_proto_version(gctx->ctx, TLS1_3_VERSION)) {
		log_openssl(LLVL_FATAL, "Cannot set TLS generic context maximal version.");
		return false;
	}

	/* SSL_CTX_set_ciphersuites for TLSv1.3
	 * SSL_CTX_set_cipher_list for TLS v1.2 and below */
	if (!SSL_CTX_set_ciphersuites(gctx->ctx, "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384")) {
		log_openssl(LLVL_FATAL, "Cannot set TLS generic context cipher suites.");
		return false;
	}

	if (!SSL_CTX_set1_sigalgs_list(gctx->ctx, "ed448:ed25519")) {
		log_openssl(LLVL_FATAL, "Cannot set TLS generic context signature algorithms.");
		return false;
	}

	if (!SSL_CTX_set1_curves_list(gctx->ctx, "X448:X25519")) {
		log_openssl(LLVL_FATAL, "Cannot set TLS generic context ECDHE curves.");
		return false;
	}
	return true;
}

void free_generic_tls_context(struct generic_tls_ctx_t *gctx) {
	SSL_CTX_free(gctx->ctx);
	gctx->ctx = NULL;

	SSL_CONF_CTX_free(gctx->conf_ctx);
	gctx->conf_ctx = NULL;
}

enum psk_hash_t {
	PSK_HASH_SHA256,
	PSK_HASH_SHA384,
};

int openssl_tls13_psk_establish_session(SSL *ssl, const uint8_t *psk, unsigned int psk_length, const EVP_MD *cipher_md, SSL_SESSION **new_session) {
	uint8_t codepoint[2];
	if (cipher_md == EVP_sha256()) {
		// TLS_AES_128_GCM_SHA256
		codepoint[0] = 0x13;
		codepoint[1] = 0x01;
	} else if (cipher_md == EVP_sha384()) {
		// TLS_AES_256_GCM_SHA384
		codepoint[0] = 0x13;
		codepoint[1] = 0x02;
	} else {
		log_msg(LLVL_ERROR, "Unknown hash function %p (%s) passed for which we do not know how to create a SSL_CIPHER*.", cipher_md, EVP_MD_name(cipher_md));
		return 0;
	}

	const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, codepoint);
	if (!cipher) {
		log_msg(LLVL_ERROR, "Unable to determine SSL_CIPHER* from codepoint 0x%02x 0x%02x (%s).", codepoint[0], codepoint[1], EVP_MD_name(cipher_md));
		return 0;
	}

	SSL_SESSION *sess = SSL_SESSION_new();
	if (!sess) {
		log_openssl(LLVL_ERROR, "Failed to create SSL_SESSION context for client.");
		return 0;
	}

	int return_value = 1;
	do {
		if (!SSL_SESSION_set1_master_key(sess, psk, psk_length)) {
			log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK master key.");
			return_value = 0;
			break;
		}

		if (!SSL_SESSION_set_cipher(sess, cipher)) {
			log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK cipher.");
			return_value = 0;
			break;
		}

		if (!SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION)) {
			log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK protocol version.");
			return_value = 0;
			break;
		}
	} while (false);

	if (return_value) {
		*new_session = sess;
	} else {
		SSL_SESSION_free(sess);
	}
	return return_value;
}

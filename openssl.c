#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl.h"
#include "log.h"

bool openssl_init(void) {
	OpenSSL_add_all_algorithms();
	ERR_load_ERR_strings();
	ERR_load_SSL_strings();
	return true;
}

bool create_generic_ssl_context(struct generic_ssl_ctx_t *gctx, bool server) {
	memset(gctx, 0, sizeof(struct generic_ssl_ctx_t));

	gctx->conf_ctx = SSL_CONF_CTX_new();
	if (!gctx->conf_ctx) {
		log_openssl(LLVL_FATAL, "Cannot initialize SSL generic context config context.");
		return false;
	}

	if (server) {
		gctx->method = TLS_server_method();
		if (!gctx->method) {
			log_openssl(LLVL_FATAL, "Cannot initialize SSL server method.");
			return false;
		}
	} else {
		gctx->method = TLS_client_method();
		if (!gctx->method) {
			log_openssl(LLVL_FATAL, "Cannot initialize SSL client method.");
			return false;
		}
	}

	gctx->ctx = SSL_CTX_new(gctx->method);
	if (!gctx->ctx) {
		log_openssl(LLVL_FATAL, "Cannot initialize SSL generic context context.");
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

	if (!SSL_CTX_set_min_proto_version(gctx->ctx, TLS1_2_VERSION)) {
		log_openssl(LLVL_FATAL, "Cannot set SSL generic context minimal version.");
		return false;
	}
	
	if (!SSL_CTX_set_max_proto_version(gctx->ctx, TLS1_2_VERSION)) {
		log_openssl(LLVL_FATAL, "Cannot set SSL generic context maximal version.");
		return false;
	}

	if (!SSL_CTX_set_cipher_list(gctx->ctx, "ECDHE-PSK-CHACHA20-POLY1305")) {
		log_openssl(LLVL_FATAL, "Cannot set SSL generic context cipher suites.");
		return false;
	}

	if (!SSL_CTX_set1_curves_list(gctx->ctx, "X25519")) {
		log_openssl(LLVL_FATAL, "Cannot set SSL generic context ECDHE curves.");
		return false;
	}
	
	return true;
}

void free_generic_ssl_context(struct generic_ssl_ctx_t *gctx) {
	SSL_CTX_free(gctx->ctx);
	gctx->ctx = NULL;

	SSL_CONF_CTX_free(gctx->conf_ctx);
	gctx->conf_ctx = NULL;
}


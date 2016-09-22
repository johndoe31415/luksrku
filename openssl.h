#ifndef __OPENSSL_H__
#define __OPENSSL_H__

#include <stdbool.h>
#include <openssl/ssl.h>

struct generic_ssl_ctx_t {
	SSL_CONF_CTX *conf_ctx;
	const SSL_METHOD *method;
	SSL_CTX *ctx;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool openssl_init(void);
bool create_generic_ssl_context(struct generic_ssl_ctx_t *gctx, bool server);
void free_generic_ssl_context(struct generic_ssl_ctx_t *gctx);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

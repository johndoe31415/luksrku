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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"
#include "openssl.h"
#include "global.h"
#include "msg.h"
#include "util.h"
#include "server.h"
#include "luks.h"
#include "pgmopts.h"
#include "uuid.h"
#include "thread.h"
#include "keydb.h"
#include "signals.h"

struct client_ctx_t {
	struct generic_tls_ctx_t *gctx;
	const struct keydb_t *keydb;
	const struct host_entry_t *host;
	int fd;
};

static int create_tcp_server_socket(int port) {
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		log_libc(LLVL_ERROR, "Unable to create TCP socket(2)");
		return -1;
	}

	{
		int value = 1;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log_libc(LLVL_ERROR, "Unable to bind(2) socket");
		return -1;
	}

	if (listen(sd, 1) < 0) {
		log_libc(LLVL_ERROR, "Unable to listen(2) on socket");
		return -1;
	}

	return sd;
}

static int psk_server_callback(SSL *ssl, const unsigned char *identity, size_t identity_len, SSL_SESSION **sessptr) {
	struct client_ctx_t *ctx = (struct client_ctx_t*)SSL_get_app_data(ssl);

	if (identity_len != ASCII_UUID_CHARACTER_COUNT) {
		log_msg(LLVL_WARNING, "Received client identity of length %d, cannot be a UUID.", identity_len);
		return 0;
	}

	char uuid_str[ASCII_UUID_BUFSIZE];
	memcpy(uuid_str, identity, ASCII_UUID_CHARACTER_COUNT);
	uuid_str[ASCII_UUID_CHARACTER_COUNT] = 0;
	if (!is_valid_uuid(uuid_str)) {
		log_msg(LLVL_WARNING, "Received client identity of length %d, but not a valid UUID.", identity_len);
		return 0;
	}

	uint8_t uuid[16];
	if (!parse_uuid(uuid, uuid_str)) {
		log_msg(LLVL_ERROR, "Failed to parse valid UUID.");
		return 0;
	}

	ctx->host = keydb_get_host_by_uuid(ctx->keydb, uuid);
	if (!ctx->host) {
		log_msg(LLVL_WARNING, "Client connected with client UUID %s, but not present in key database.", uuid_str);
		return 0;
	}

	return openssl_tls13_psk_establish_session(ssl, ctx->host->tls_psk, PSK_SIZE_BYTES, EVP_sha256(), sessptr);
}

static void client_handler_thread(void *vctx) {
	struct client_ctx_t *client = (struct client_ctx_t*)vctx;

	SSL *ssl = SSL_new(client->gctx->ctx);
	if (ssl) {
		SSL_set_fd(ssl, client->fd);
		SSL_set_app_data(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			if (client->host) {
				log_msg(LLVL_DEBUG, "Client \"%s\" connected, sending unlock data for %d volumes.", client->host->host_name, client->host->volume_count);
				for (unsigned int i = 0; i < client->host->volume_count; i++) {
					const struct volume_entry_t *volume = &client->host->volumes[i];

					struct msg_t msg = { 0 };
					memcpy(msg.volume_uuid, volume->volume_uuid, 16);
					memcpy(msg.luks_passphrase_raw, volume->luks_passphrase_raw, LUKS_PASSPHRASE_RAW_SIZE_BYTES);

					int txlen = SSL_write(ssl, &msg, sizeof(msg));
					OPENSSL_cleanse(&msg, sizeof(msg));
					if (txlen != sizeof(msg)) {
						log_msg(LLVL_WARNING, "Tried to send message of %d bytes, but sent %d. Severing connection to client.", sizeof(msg), txlen);
						break;
					}
				}
			} else {
				log_msg(LLVL_FATAL, "Client connected, but no host set.");
			}
		}
	} else {
		log_openssl(LLVL_FATAL, "Cannot establish SSL context for connecting client");
	}
	SSL_free(ssl);
	shutdown(client->fd, SHUT_RDWR);
	close(client->fd);
}

bool keyserver_start(const struct pgmopts_server_t *opts) {
	bool success = true;
	struct keydb_t* keydb = NULL;
	struct generic_tls_ctx_t gctx = { 0 };
	do {
		/* We ignore SIGPIPE or the server will die when clients disconnect suddenly */
		ignore_signal(SIGPIPE);

		/* Load key database first */
		keydb = keydb_read(opts->filename);
		if (!keydb) {
			log_msg(LLVL_FATAL, "Failed to load key database: %s", opts->filename);
			success = false;
			break;
		}

		if (!keydb->server_database) {
			log_msg(LLVL_FATAL, "Not a server key database: %s", opts->filename);
			success = false;
			break;
		}

		if (!create_generic_tls_context(&gctx, true)) {
			log_msg(LLVL_FATAL, "Failed to create OpenSSL server context.");
			success = false;
			break;
		}

		SSL_CTX_set_psk_find_session_callback(gctx.ctx, psk_server_callback);

		int tcp_sock = create_tcp_server_socket(opts->port);
		if (tcp_sock == -1) {
			log_msg(LLVL_ERROR, "Cannot start server without server socket.");
			success = false;
			break;
		}

		while (true) {
			struct sockaddr_in addr;
			unsigned int len = sizeof(addr);
			int client = accept(tcp_sock, (struct sockaddr*)&addr, &len);
			if (client < 0) {
				log_libc(LLVL_ERROR, "Unable to accept(2)");
				close(tcp_sock);
				free_generic_tls_context(&gctx);
				return false;
			}

			/* Client has connected, fire up client thread. */
			struct client_ctx_t client_ctx = {
				.gctx = &gctx,
				.keydb = keydb,
				.fd = client,
			};
			if (!pthread_create_detached_thread(client_handler_thread, &client_ctx, sizeof(client_ctx))) {
				log_libc(LLVL_FATAL, "Unable to pthread_attr_init(3)");
				close(tcp_sock);
				free_generic_tls_context(&gctx);
				return false;
			}
		}
	} while (false);
	free_generic_tls_context(&gctx);
	keydb_free(keydb);
	return success;
}

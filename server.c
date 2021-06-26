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
#include "udp.h"
#include "blacklist.h"
#include "vaulted_keydb.h"

struct keyserver_t {
	struct keydb_t* keydb;
	struct vaulted_keydb_t *vaulted_keydb;
	struct generic_tls_ctx_t gctx;
	const struct pgmopts_server_t *opts;
	int tcp_sd, udp_sd;
};

struct client_thread_ctx_t {
	struct generic_tls_ctx_t *gctx;
	const struct keydb_t *keydb;
	struct vaulted_keydb_t *vaulted_keydb;
	const struct host_entry_t *host;
	int fd;
};

struct udp_listen_thread_ctx_t {
	const struct keydb_t *keydb;
	int udp_sd;
	unsigned int port;
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
	struct client_thread_ctx_t *ctx = (struct client_thread_ctx_t*)SSL_get_app_data(ssl);

	if (identity_len != ASCII_UUID_CHARACTER_COUNT) {
		log_msg(LLVL_WARNING, "Received client identity of length %ld, cannot be a UUID.", identity_len);
		return 0;
	}

	char uuid_str[ASCII_UUID_BUFSIZE];
	memcpy(uuid_str, identity, ASCII_UUID_CHARACTER_COUNT);
	uuid_str[ASCII_UUID_CHARACTER_COUNT] = 0;
	if (!is_valid_uuid(uuid_str)) {
		log_msg(LLVL_WARNING, "Received client identity of length %ld, but not a valid UUID.", identity_len);
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

	uint8_t psk[PSK_SIZE_BYTES];
	if (!vaulted_keydb_get_tls_psk(ctx->vaulted_keydb, psk, ctx->host)) {
		log_msg(LLVL_WARNING, "Cannot establish server connection without TLS-PSK.");
		return 0;
	}

	int result = openssl_tls13_psk_establish_session(ssl, psk, PSK_SIZE_BYTES, EVP_sha256(), sessptr);
	OPENSSL_cleanse(psk, PSK_SIZE_BYTES);
	return result;
}

static void copy_luks_passphrase_callback(void *vctx, unsigned int volume_index, const void *source) {
	struct msg_t *msgs = (struct msg_t*)vctx;
	memcpy(msgs[volume_index].luks_passphrase_raw, source, LUKS_PASSPHRASE_RAW_SIZE_BYTES);
}

static void client_handler_thread(void *vctx) {
	struct client_thread_ctx_t *client = (struct client_thread_ctx_t*)vctx;

	SSL *ssl = SSL_new(client->gctx->ctx);
	if (ssl) {
		SSL_set_fd(ssl, client->fd);
		SSL_set_app_data(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			log_openssl(LLVL_WARNING, "Could not establish TLS connection to connecting client.");
			ERR_print_errors_fp(stderr);
		} else {
			if (client->host) {
				log_msg(LLVL_DEBUG, "Client \"%s\" connected, sending unlock data for %d volumes.", client->host->host_name, client->host->volume_count);
				/* Initially prepare all messages we're about to send to the
				 * client by filling the UUID fields */
				struct msg_t msgs[client->host->volume_count];
				for (unsigned int i = 0; i < client->host->volume_count; i++) {
					const struct volume_entry_t *volume = &client->host->volumes[i];
					memcpy(msgs[i].volume_uuid, volume->volume_uuid, 16);
				}

				/* Then also fill the keys */
				vaulted_keydb_get_volume_luks_passphases_raw(client->vaulted_keydb, copy_luks_passphrase_callback, msgs, client->host);

				int txlen = SSL_write(ssl, &msgs, sizeof(msgs));
				OPENSSL_cleanse(&msgs, sizeof(msgs));
				if (txlen != (long)sizeof(msgs)) {
					log_msg(LLVL_WARNING, "Tried to send message of %ld bytes, but sent %d. Severing connection to client.", sizeof(msgs), txlen);
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

static void udp_handler_thread(void *vctx) {
	struct udp_listen_thread_ctx_t *client = (struct udp_listen_thread_ctx_t*)vctx;

	while (true) {
		struct udp_query_t rx_msg;
		struct sockaddr_in origin;
		if (!wait_udp_query(client->udp_sd, &rx_msg, &origin)) {
			continue;
		}

		log_msg(LLVL_TRACE, "Recevied UDP query message from %d.%d.%d.%d:%d", PRINTF_FORMAT_IP(&origin), ntohs(origin.sin_port));

		/* Ensure that we only reply to this host once every minute */
		const uint32_t ipv4 = origin.sin_addr.s_addr;
		if (is_ip_blacklisted(ipv4)) {
			continue;
		}
		blacklist_ip(ipv4, BLACKLIST_TIMEOUT_SERVER);

		/* Check if we have this host in our database */
		if (keydb_get_host_by_uuid(client->keydb, rx_msg.host_uuid)) {
			/* Yes, it is. Notify the client who's asking that we have their key. */
			struct udp_response_t tx_msg;
			memcpy(tx_msg.magic, UDP_MESSAGE_MAGIC, UDP_MESSAGE_MAGIC_SIZE);
			send_udp_message(client->udp_sd, &origin, &tx_msg, sizeof(tx_msg), true);
		}
	}
}

bool keyserver_start(const struct pgmopts_server_t *opts) {
	bool success = true;
	struct keyserver_t keyserver = {
		.opts = opts,
		.tcp_sd = -1,
		.udp_sd = -1,
	};
	do {
		/* We ignore SIGPIPE or the server will die when clients disconnect suddenly */
		ignore_signal(SIGPIPE);

		/* Load key database first */
		keyserver.keydb = keydb_read(opts->filename);
		if (!keyserver.keydb) {
			log_msg(LLVL_FATAL, "Failed to load key database: %s", opts->filename);
			success = false;
			break;
		}

		if (!keyserver.keydb->server_database) {
			log_msg(LLVL_FATAL, "Not a server key database: %s", opts->filename);
			success = false;
			break;
		}

		if (keyserver.keydb->host_count == 0) {
			log_msg(LLVL_FATAL, "No host entries in key database: %s", opts->filename);
			success = false;
			break;
		}

		/* Then convert it into a vaulted key database */
		keyserver.vaulted_keydb = vaulted_keydb_new(keyserver.keydb);
		if (!keyserver.vaulted_keydb) {
			log_msg(LLVL_FATAL, "Failed to create vaulted key database.");
			success = false;
			break;
		}

		if (!create_generic_tls_context(&keyserver.gctx, true)) {
			log_msg(LLVL_FATAL, "Failed to create OpenSSL server context.");
			success = false;
			break;
		}

		SSL_CTX_set_psk_find_session_callback(keyserver.gctx.ctx, psk_server_callback);

		keyserver.tcp_sd = create_tcp_server_socket(opts->port);
		if (keyserver.tcp_sd == -1) {
			log_msg(LLVL_ERROR, "Cannot start server without server socket.");
			success = false;
			break;
		}

		if (opts->answer_udp_queries) {
			keyserver.udp_sd = create_udp_socket(opts->port, false, 1000);
			if (keyserver.udp_sd == -1) {
				success = false;
				break;
			}

			struct udp_listen_thread_ctx_t udp_thread_ctx = {
				.keydb = keyserver.keydb,
				.udp_sd = keyserver.udp_sd,
				.port = keyserver.opts->port,
			};
			if (!pthread_create_detached_thread(udp_handler_thread, &udp_thread_ctx, sizeof(udp_thread_ctx))) {
				log_libc(LLVL_FATAL, "Unable to create detached thread for UDP messages.");
				success = false;
				break;
			}
		}

		log_msg(LLVL_INFO, "Serving luksrku database for %u hosts.", keyserver.keydb->host_count);
		while (true) {
			struct sockaddr_in addr;
			unsigned int len = sizeof(addr);
			int client = accept(keyserver.tcp_sd, (struct sockaddr*)&addr, &len);
			if (client < 0) {
				log_libc(LLVL_ERROR, "Unable to accept(2)");
				success = false;
				break;
			}

			/* Client has connected, fire up client thread. */
			struct client_thread_ctx_t client_ctx = {
				.gctx = &keyserver.gctx,
				.keydb = keyserver.keydb,
				.vaulted_keydb = keyserver.vaulted_keydb,
				.fd = client,
			};
			if (!pthread_create_detached_thread(client_handler_thread, &client_ctx, sizeof(client_ctx))) {
				log_libc(LLVL_FATAL, "Unable to create detached thread for client.");
				success = false;
				break;
			}
		}
	} while (false);
	if (keyserver.udp_sd != -1) {
		close(keyserver.udp_sd);
	}
	if (keyserver.tcp_sd != -1) {
		close(keyserver.tcp_sd);
	}
	free_generic_tls_context(&keyserver.gctx);
	vaulted_keydb_free(keyserver.vaulted_keydb);
	keydb_free(keyserver.keydb);
	return success;
}

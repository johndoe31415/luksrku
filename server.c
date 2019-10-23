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

static int create_tcp_server_socket(int port) {
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		log_libc(LLVL_ERROR, "Unable to create TCP socket(2)");
		return -1;
	}

	{
		int value = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log_libc(LLVL_ERROR, "Unable to bind(2) socket");
		return -1;
	}

	if (listen(s, 1) < 0) {
		log_libc(LLVL_ERROR, "Unable to listen(2) on socket");
		return -1;
	}

	return s;
}

#if 0
static const struct keyentry_t *server_key;



/* Wait for the socket to become acceptable or time out after given number of
 * milliseconds. Return true if acceptable socket is present or false if
 * timeout occured. */
static bool socket_wait_acceptable(int sd, int timeout_millis) {
	struct timeval tv;
	memset(&tv, 0, sizeof(tv));
	tv.tv_usec = timeout_millis * 1000;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	int result = select(sd + 1, &fds, NULL, NULL, &tv);
	return result != 0;
}

static int create_udp_socket(void) {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_libc(LLVL_ERROR, "Unable to create UDP server socket(2)");
		return -1;
	}
	{
		int value = 1;
		if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value))) {
			log_libc(LLVL_ERROR, "Unable to set UDP socket in broadcast mode using setsockopt(2)");
			close(sd);
			return -1;
		}
	}


	return sd;
}

static bool send_udp_broadcast_message(int sd, int port, const void *data, int length) {
	struct sockaddr_in destination;
	memset(&destination, 0, sizeof(struct sockaddr_in));
	destination.sin_family = AF_INET;
	destination.sin_port = htons(port);
	destination.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	if (sendto(sd, data, length, 0, (struct sockaddr *)&destination, sizeof(struct sockaddr_in)) < 0) {
		log_libc(LLVL_ERROR, "Unable to sendto(2)");
		return false;
	}
	return true;
}

static bool announce_waiting_message(int sd, int port, const struct keyentry_t *key) {
	struct announcement_t msg;
	const uint8_t magic[16] = CLIENT_ANNOUNCE_MAGIC;
	memset(&msg, 0, sizeof(msg));
	memcpy(msg.magic, magic, 16);
	memcpy(msg.host_uuid, key->host_uuid, 16);

	return send_udp_broadcast_message(sd, port, &msg, sizeof(msg));
}

static bool unlock_disk(const struct diskentry_t *disk, const uint8_t *passphrase, int passphrase_length) {
	char ascii_uuid[40];
	sprintf_uuid(ascii_uuid, disk->disk_uuid);
	log_msg(LLVL_INFO, "Trying to unlock disk %s with UUID %s", disk->devmapper_name, ascii_uuid);
#ifdef DEBUG
	fprintf(stderr, "Using %d bytes key for unlocking: ", passphrase_length);
	dump_hex(stderr, passphrase, passphrase_length);
	fprintf(stderr, "\n");
#endif
	if (is_luks_device_opened(disk->devmapper_name)) {
		log_msg(LLVL_INFO, "Disk %s already unlocked, nothing to do.", disk->devmapper_name, ascii_uuid);
		return true;
	}
	return open_luks_device_pw(disk->disk_uuid, disk->devmapper_name, passphrase, passphrase_length);
}

static bool all_disks_unlocked(const struct keyentry_t *keyentry) {
	for (int i = 0; i < MAX_DISKS_PER_HOST; i++) {
		if (keyentry->disk_keys[i].occupied && !is_luks_device_opened(keyentry->disk_keys[i].devmapper_name)) {
			return false;
		}
	}
	return true;
}

static bool tls_server(const struct keyentry_t *key, const struct options_t *options) {
	if (all_disks_unlocked(key)) {
		log_msg(LLVL_INFO, "Starting of server not necessary, all disks already unlocked.");
		return true;
	}

	struct generic_tls_ctx_t gctx;
	create_generic_tls_context(&gctx, true);

	server_key = key;
	{
		char ascii_host_uuid[40];
		sprintf_uuid(ascii_host_uuid, key->host_uuid);
		SSL_CTX_use_psk_identity_hint(gctx.ctx, ascii_host_uuid);
	}
	SSL_CTX_set_psk_server_callback(gctx.ctx, psk_server_callback);

	int tcp_sock = create_tcp_socket(options->port);
	if (tcp_sock == -1) {
		log_msg(LLVL_ERROR, "Cannot start server without server socket.");
		free_generic_tls_context(&gctx);
		return false;
	}

	int udp_sock = create_udp_socket();
	if (tcp_sock == -1) {
		log_msg(LLVL_ERROR, "Cannot broadcast without announcement UDP socket.");
		close(tcp_sock);
		free_generic_tls_context(&gctx);
		return false;
	}

	log_msg(LLVL_DEBUG, "Created listening socket on port %d", options->port);
	int tries = 0;
	int failed_broadcast_cnt = 0;
	while ((options->unlock_cnt == 0) || (tries < options->unlock_cnt)) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);

		log_msg(LLVL_DEBUG, "Waiting for incoming connection...");
		if (!announce_waiting_message(udp_sock, options->port, key)) {
			failed_broadcast_cnt++;
			if ((options->max_broadcast_errs != 0) && (failed_broadcast_cnt >= options->max_broadcast_errs)) {
				log_msg(LLVL_ERROR, "Too many broadcast errors, aborting. Network unavailable?");
				break;
			}
		}
		if (!socket_wait_acceptable(tcp_sock, WAITING_MESSAGE_BROADCAST_INTERVAL_MILLISECONDS)) {
			/* No connection pending, timeout. */
			continue;
		}

		log_msg(LLVL_DEBUG, "Trying to accept connection...");
		int client = accept(tcp_sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			log_libc(LLVL_ERROR, "Unable to accept(2)");
			close(udp_sock);
			close(tcp_sock);
			free_generic_tls_context(&gctx);
			return false;
		}

		SSL *ssl = SSL_new(gctx.ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			tries++;
			log_msg(LLVL_DEBUG, "Client connected, waiting for data...");
			while (true) {
				struct msg_t msg;
				int rxlen = SSL_read(ssl, &msg, sizeof(msg));
				if (rxlen == 0) {
					/* Client severed the connection */
					break;
				}
				if (rxlen != sizeof(msg)) {
					log_msg(LLVL_ERROR, "Truncated message (%d bytes) received, terminating connection. Expected %d bytes.", rxlen, sizeof(msg));
					break;
				}
				msg_to_hbo(&msg);

				if ((msg.passphrase_length == 0) || (msg.passphrase_length > MAX_PASSPHRASE_LENGTH)) {
					log_msg(LLVL_FATAL, "Client sent malformed message indicating illegal passphrase length of %d bytes. Aborting connection.", msg.passphrase_length);
					break;
				}

				/* Now check if this is one of they keys we're actually looking for */
				bool found = false;
				for (int i = 0; i < MAX_DISKS_PER_HOST; i++) {
					if (!memcmp(key->disk_keys[i].disk_uuid, msg.disk_uuid, 16)) {
						bool success = unlock_disk(&key->disk_keys[i], msg.passphrase, msg.passphrase_length);
						log_msg(LLVL_DEBUG, "Unlocking of disk was %s", success ? "successful" : "unsuccessful");
						found = true;
						break;
					}
				}
				if (!found) {
					char ascii_uuid[40];
					sprintf_uuid(ascii_uuid, msg.disk_uuid);
					log_msg(LLVL_INFO, "Client sent passphrase for UUID %s; we were not expecting it. Ignored.", ascii_uuid);
				}
			}
		}

		SSL_free(ssl);
		close(client);

		/* Connection closed */
		if (all_disks_unlocked(key)) {
			log_msg(LLVL_INFO, "All disks successfully unlocked.");
			break;
		} else {
			log_msg(LLVL_DEBUG, "At least one disk remains locked after communication.");
		}
	}

	close(udp_sock);
	close(tcp_sock);
	free_generic_tls_context(&gctx);
	return true;
}
#endif

#if 0
static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
	if (max_psk_len < PSK_SIZE_BYTES) {
		log_msg(LLVL_FATAL, "Server error: max_psk_len too small.");
		return 0;
	}
	if (strcmp(identity, CLIENT_PSK_IDENTITY)) {
		log_msg(LLVL_FATAL, "Server error: client identity '%s' unexpected (expected '%s').", identity, CLIENT_PSK_IDENTITY);
		return 0;
	}
//	memcpy(psk, server_key->psk, PSK_SIZE_BYTES);
	return PSK_SIZE_BYTES;
}
#endif

struct client_ctx_t {
	struct generic_tls_ctx_t *gctx;
	const struct keydb_t *keydb;
	const struct host_entry_t *host;
	int fd;
};


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

	const uint8_t tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
	const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
	if (!cipher) {
		log_openssl(LLVL_ERROR, "Unable to look up SSL_CIPHER for TLSv1.3-PSK");
		return 0;
	}

	SSL_SESSION *sess = SSL_SESSION_new();
	if (!sess) {
		log_openssl(LLVL_ERROR, "Failed to create SSL_SESSION context for client.");
		return 0;
	}

	if (!SSL_SESSION_set1_master_key(sess, ctx->host->tls_psk, PSK_SIZE_BYTES)) {
		log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK master key.");
		SSL_SESSION_free(sess);
		return 0;
	}

	if (!SSL_SESSION_set_cipher(sess, cipher)) {
		log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK cipher.");
		SSL_SESSION_free(sess);
		return 0;
	}

	if (!SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION)) {
		log_openssl(LLVL_ERROR, "Failed to set TLSv1.3-PSK protocol version.");
		SSL_SESSION_free(sess);
		return 0;
	}

	*sessptr = sess;
	return 1;
}

static void *client_handler_thread(void *vctx) {
	struct client_ctx_t *client = (struct client_ctx_t*)vctx;

	SSL *ssl = SSL_new(client->gctx->ctx);
	SSL_set_fd(ssl, client->fd);
	SSL_set_app_data(ssl, client);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	} else {
		if (client->host) {
			log_msg(LLVL_DEBUG, "Client \"%s\" connected, sending unlock data for %d volumes...", client->host->host_name, client->host->volume_count);
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

	SSL_free(ssl);
	shutdown(client->fd, SHUT_RDWR);
	close(client->fd);
	free(client);
	return NULL;
}

bool keyserver_start(const struct pgmopts_server_t *opts) {
	/* Load key database first */
	struct keydb_t* keydb = keydb_read(opts->filename);
	if (!keydb) {
		log_msg(LLVL_FATAL, "Failed to load key database: %s", opts->filename);
		return false;
	}

	if (!keydb->server_database) {
		log_msg(LLVL_FATAL, "Not a server key database: %s", opts->filename);
		keydb_free(keydb);
		return false;
	}

	struct generic_tls_ctx_t gctx;
	if (!create_generic_tls_context(&gctx, true)) {
		log_msg(LLVL_FATAL, "Failed to create OpenSSL server context.");
		return false;
	}

	SSL_CTX_set_psk_find_session_callback(gctx.ctx, psk_server_callback);

	int tcp_sock = create_tcp_server_socket(opts->port);
	if (tcp_sock == -1) {
		log_msg(LLVL_ERROR, "Cannot start server without server socket.");
		free_generic_tls_context(&gctx);
		return false;
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
		struct client_ctx_t *client_ctx = calloc(1, sizeof(struct client_ctx_t));
		if (!client_ctx) {
			log_libc(LLVL_FATAL, "Unable to malloc(3) client ctx");
			close(tcp_sock);
			free_generic_tls_context(&gctx);
			return false;
		}
		client_ctx->gctx = &gctx;
		client_ctx->keydb = keydb;
		client_ctx->fd = client;

		pthread_t thread;
		pthread_attr_t attrs;
		if (pthread_attr_init(&attrs)) {
			log_libc(LLVL_FATAL, "Unable to pthread_attr_init(3)");
			close(tcp_sock);
			free_generic_tls_context(&gctx);
			return false;
		}
		if (pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED)) {
			log_libc(LLVL_FATAL, "Unable to pthread_attr_setdetachstate(3)");
			close(tcp_sock);
			free_generic_tls_context(&gctx);
			return false;
		}
		if (pthread_create(&thread, &attrs, client_handler_thread, client_ctx)) {
			log_libc(LLVL_FATAL, "Unable to pthread_create(3) a client thread");
			close(tcp_sock);
			free_generic_tls_context(&gctx);
			return false;

		}



	}

	free_generic_tls_context(&gctx);
	return true;
}

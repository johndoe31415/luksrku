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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#include "log.h"
#include "openssl.h"
#include "util.h"
#include "msg.h"
#include "client.h"
#include "blacklist.h"
#include "keydb.h"
#include "uuid.h"

struct keyclient_t {
	const struct pgmopts_client_t *opts;
	struct keydb_t *keydb;
	bool volume_unlocked[MAX_VOLUMES_PER_HOST];
	unsigned char identifier[ASCII_UUID_BUFSIZE];
};

static int psk_client_callback(SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen, SSL_SESSION **sessptr) {
	struct keyclient_t *key_client = (struct keyclient_t*)SSL_get_app_data(ssl);
	*id = key_client->identifier;
	*idlen = ASCII_UUID_CHARACTER_COUNT;

	return openssl_tls13_psk_establish_session(ssl, key_client->keydb->hosts[0].tls_psk, PSK_SIZE_BYTES, EVP_sha256(), sessptr);
}

static bool contact_keyserver_socket(struct keyclient_t *keyclient, int sd) {
	struct generic_tls_ctx_t gctx;
	if (!create_generic_tls_context(&gctx, false)) {
		log_msg(LLVL_FATAL, "Failed to create OpenSSL client context.");
		return false;
	}
	SSL_CTX_set_psk_use_session_callback(gctx.ctx, psk_client_callback);

	SSL *ssl = SSL_new(gctx.ctx);
	if (ssl) {
		SSL_set_fd(ssl, sd);
		SSL_set_app_data(ssl, keyclient);

		if (SSL_connect(ssl) == 1) {
			struct msg_t msg;
			while (true) {
				int bytes_read = SSL_read(ssl, &msg, sizeof(msg));
				if (bytes_read == 0) {
					/* Server closed the connection. */
					break;
				}
				if (bytes_read != sizeof(msg)) {
					log_openssl(LLVL_FATAL, "SSL_read returned %d bytes when we expected to read %d", bytes_read, sizeof(msg));
					break;
				}
				if (should_log(LLVL_TRACE)) {
					char uuid_str[ASCII_UUID_BUFSIZE];
					sprintf_uuid(uuid_str, msg.volume_uuid);
					log_msg(LLVL_TRACE, "Received LUKS key to unlock volume with UUID %s", uuid_str);
				}
			}
			OPENSSL_cleanse(&msg, sizeof(msg));
		} else {
			log_openssl(LLVL_FATAL, "SSL_connect failed");
		}

	} else {
		log_openssl(LLVL_FATAL, "Cannot establish SSL context when trying to connect to server");
	}

	SSL_free(ssl);
	free_generic_tls_context(&gctx);
	return true;
}

static bool contact_keyserver_ipv4(struct keyclient_t *keyclient, struct sockaddr_in *sockaddr_in, unsigned int port) {
	sockaddr_in->sin_port = htons(port);

	int sd = socket(sockaddr_in->sin_family, SOCK_STREAM, 0);
	if (sd == -1) {
		log_libc(LLVL_ERROR, "Failed to create socket(3)");
		return false;
	}

	if (connect(sd, (struct sockaddr*)sockaddr_in, sizeof(struct sockaddr_in)) == -1) {
		log_libc(LLVL_ERROR, "Failed to connect(3) to %d.%d.%d.%d:%d", PRINTF_FORMAT_IP(sockaddr_in), port);
		close(sd);
		return false;
	}

	bool success = contact_keyserver_socket(keyclient, sd);

	shutdown(sd, SHUT_RDWR);
	close(sd);
	return success;
}

static bool contact_keyserver_hostname(struct keyclient_t *keyclient, const char *hostname) {
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *result;
	int resolve_result = getaddrinfo(hostname, NULL, &hints, &result);
	if (resolve_result) {
		log_msg(LLVL_ERROR, "Failed to resolve hostname %s using getaddrinfo(3): %s", hostname, gai_strerror(resolve_result));
		return false;
	}

	if (result->ai_addr->sa_family != AF_INET) {
		freeaddrinfo(result);
		log_msg(LLVL_ERROR, "getaddrinfo(3) returned non-IPv4 entry");
		return false;
	}

	struct sockaddr_in *sin_address = (struct sockaddr_in*)result->ai_addr;
	log_msg(LLVL_TRACE, "Resolved %s to %d.%d.%d.%d", hostname, PRINTF_FORMAT_IP(sin_address));

	bool success = contact_keyserver_ipv4(keyclient, sin_address, keyclient->opts->port);

	freeaddrinfo(result);
	return success;
}

bool keyclient_start(const struct pgmopts_client_t *opts) {
	/* Load key database first */
	struct keyclient_t keyclient = {
		.opts = opts,
	};
	bool success = true;

	do {
		keyclient.keydb = keydb_read(opts->filename);
		if (!keyclient.keydb) {
			log_msg(LLVL_FATAL, "Failed to load key database: %s", opts->filename);
			success = false;
			break;
		}

		if (keyclient.keydb->server_database) {
			log_msg(LLVL_FATAL, "Not an exported key database: %s -- this database contains LUKS passphrases, refusing to work with it!", opts->filename);
			success = false;
			break;
		}

		if (keyclient.keydb->host_count != 1) {
			log_msg(LLVL_FATAL, "Host count %d in %s -- expected exactly one host entry for an exported database.", keyclient.keydb->host_count, opts->filename);
			success = false;
			break;
		}

		struct host_entry_t *host = &keyclient.keydb->hosts[0];
		if (host->volume_count == 0) {
			log_msg(LLVL_FATAL, "No volumes found in exported database %s.", opts->filename);
			success = false;
			break;
		}

		/* Transcribe the host UUID to ASCII so we only have to do this once */
		sprintf_uuid((char*)keyclient.identifier, host->host_uuid);

		log_msg(LLVL_DEBUG, "Attempting to unlock %d volumes of host \"%s\".", host->volume_count, host->host_name);
		if (opts->hostname) {
			if (!contact_keyserver_hostname(&keyclient, opts->hostname)) {
				log_msg(LLVL_ERROR, "Failed to contact key server: %s", opts->hostname);
				success = false;
				break;
			}
		} else {
			/* TODO: Loop until keyserver found */
		}
	} while (false);

	if (keyclient.keydb) {
		keydb_free(keyclient.keydb);
	}
	return success;
}

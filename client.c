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

#include "log.h"
#include "openssl.h"
#include "util.h"
#include "msg.h"
#include "client.h"
#include "blacklist.h"

#if 0
static const struct keydb_t *client_keydb;

static unsigned int psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) {
	log_msg(LLVL_DEBUG, "psk_client_callback: SSL %p, hint '%s'.", ssl, hint);
	if (max_psk_len < PSK_SIZE_BYTES) {
		log_msg(LLVL_ERROR, "Client error: max_psk_len too small.");
		return 0;
	}
	if (max_identity_len < strlen(CLIENT_PSK_IDENTITY) + 1) {
		log_msg(LLVL_ERROR, "Client error: max_identity_len too small.");
		return 0;
	}

	uint8_t parsed_uuid[16];
	if (!parse_uuid(parsed_uuid, hint)) {
		log_msg(LLVL_ERROR, "Client error: given hint '%s' is not a valid UUID.", hint);
		return 0;
	}

	const struct keyentry_t *entry = keydb_find_entry_by_host_uuid(client_keydb, parsed_uuid);
	if (!entry) {
		log_msg(LLVL_ERROR, "Client error: server hint '%s' not present in database.", hint);
		return 0;
	}

	strncpy(identity, CLIENT_PSK_IDENTITY, max_identity_len);
	memcpy(psk, entry->psk, PSK_SIZE_BYTES);
	return PSK_SIZE_BYTES;
}

static int tls_client_connect(const struct keyentry_t *keyentry, const char *host_port) {
	struct generic_tls_ctx_t gctx;
	create_generic_tls_context(&gctx, false);

	SSL_CTX_set_psk_client_callback(gctx.ctx, psk_client_callback);

	BIO *conn = BIO_new_ssl_connect(gctx.ctx);
	if (!conn) {
		log_openssl(LLVL_ERROR, "Cannot get SSL client connect BIO.");
		return false;
	}

	if (BIO_set_conn_hostname(conn, host_port) != 1) {
		log_openssl(LLVL_ERROR, "Cannot set SSL client connect hostname/port.");
		return false;
	}

	SSL *ssl = NULL;
	BIO_get_ssl(conn, &ssl);
	if (!ssl) {
		log_openssl(LLVL_ERROR, "Cannot get SSL client SSL context.");
		return false;
	}

	if (BIO_do_connect(conn) != 1) {
		log_openssl(LLVL_ERROR, "Cannot perform SSL client connect.");
		return false;
	}

	if (BIO_do_handshake(conn) != 1) {
		log_openssl(LLVL_ERROR, "Cannot perform SSL client handshake.");
		return false;
	}

	log_msg(LLVL_DEBUG, "Client successfully connected to server.");
	for (int i = 0; i < MAX_DISKS_PER_HOST; i++) {
		if (keyentry->disk_keys[i].occupied) {
			log_msg(LLVL_DEBUG, "Client sending key #%d", i);

			struct msg_t msg;
			memset(&msg, 0, sizeof(msg));
			memcpy(msg.disk_uuid, keyentry->disk_keys[i].disk_uuid, 16);
			msg.passphrase_length = keyentry->disk_keys[i].passphrase_length;
			memcpy(msg.passphrase, keyentry->disk_keys[i].passphrase, MAX_PASSPHRASE_LENGTH);
			msg_to_nbo(&msg);
			int txed = SSL_write(ssl, &msg, sizeof(msg));
			if (txed != sizeof(msg)) {
				log_msg(LLVL_ERROR, "Truncated message sent: tried to send %d bytes, but only %d bytes went through. Aborting connection.", sizeof(msg), txed);
				break;
			}
		}
	}
	BIO_free_all(conn);
	free_generic_tls_context(&gctx);
	return 0;
}

static bool parse_announcement(const struct options_t *options, const struct sockaddr_in *peer_addr, const struct announcement_t *announcement) {
	log_msg(LLVL_DEBUG, "Parsing possible announcement from %d.%d.%d.%d:%d", PRINTF_FORMAT_IP(peer_addr), ntohs(peer_addr->sin_port));
	const uint8_t expect_magic[16] = CLIENT_ANNOUNCE_MAGIC;
	if (memcmp(announcement->magic, expect_magic, 16)) {
		/* Magic number does not match, discard. */
		return false;
	}

	const struct keyentry_t *keyentry = keydb_find_entry_by_host_uuid(client_keydb, announcement->host_uuid);

	char ascii_host_uuid[40];
	sprintf_uuid(ascii_host_uuid, announcement->host_uuid);
	log_msg(LLVL_DEBUG, "Received valid announcement from %s host %s", (keyentry == NULL) ? "unknown" : "known", ascii_host_uuid);

	if (keyentry == NULL) {
		/* The announcement is valid, but we don't know the client -- so we
		 * can't do anything further */
		return false;
	}

	/* We know the server. But maybe we've already tried to contact them and
	 * therefore they're blacklisted for a certain period of time. Check this
	 * now (we don't want to spam servers with maybe invalid passphrases). */
	uint32_t ip = peer_addr->sin_addr.s_addr;
	if (is_ip_blacklisted(ip)) {
		log_msg(LLVL_DEBUG, "%d.%d.%d.%d is currently blacklisted for %d seconds.", PRINTF_FORMAT_IP(peer_addr), BLACKLIST_ENTRY_TIMEOUT_SECS);
		return false;
	} else {
		/* Blacklist for next time */
		blacklist_ip(ip);
	}

	char destination_address[32];
	snprintf(destination_address, sizeof(destination_address) - 1, "%d.%d.%d.%d:%d", PRINTF_FORMAT_IP(peer_addr), options->port);
	log_msg(LLVL_DEBUG, "Trying to connect to %s in order to transmit keys", destination_address);

	tls_client_connect(keyentry, destination_address);
	return true;
}

static bool tls_client(const struct keydb_t *keydb, const struct options_t *options) {
	client_keydb = keydb;

	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_libc(LLVL_ERROR, "Unable to create UDP client socket(2)");
		return false;
	}

	{
		int value = 1;
		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
	}

	struct sockaddr_in local_addr;
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(options->port);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(local_addr.sin_zero, 0, sizeof(local_addr.sin_zero));

	if (bind(sd, (struct sockaddr*)&local_addr, sizeof(local_addr))) {
		log_libc(LLVL_ERROR, "Unable to bind(2) UDP client socket to port %d", options->port);
		return false;
	}

	int tries = 0;
	while ((options->unlock_cnt == 0) || (tries < options->unlock_cnt)) {
		uint8_t rxbuf[2048];
		struct sockaddr_in peer_addr;
		socklen_t addr_size = sizeof(peer_addr);
		int rxlen = recvfrom(sd, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&peer_addr, &addr_size);
		if (rxlen == sizeof(struct announcement_t)) {
			if (parse_announcement(options, &peer_addr, (struct announcement_t*)rxbuf)) {
				tries++;
			}
		}
	}

	return true;
}
#endif

bool keyclient_start(const struct pgmopts_client_t *opts) {
	return true;
}

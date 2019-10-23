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

	SSL_SESSION *sess = SSL_SESSION_new();
	if (!sess) {
		log_openssl(LLVL_ERROR, "Failed to create SSL_SESSION context for client.");
		return 0;
	}

	const uint8_t tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
	const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
	if (!cipher) {
		log_openssl(LLVL_ERROR, "Unable to look up SSL_CIPHER for TLSv1.3-PSK");
		return 0;
	}

	int return_value = 1;
	do {
		if (!SSL_SESSION_set1_master_key(sess, key_client->keydb->hosts[0].tls_psk, PSK_SIZE_BYTES)) {
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
		*sessptr = sess;
	}

	return return_value;
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

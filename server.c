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
#include "keyfile.h"
#include "msg.h"
#include "util.h"
#include "cmdline.h"
#include "server.h"
#include "luks.h"

static const struct keyentry_t *server_key;

static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
	if (max_psk_len < PSK_SIZE_BYTES) {
		log_msg(LLVL_FATAL, "Server error: max_psk_len too small.");
		return 0;
	}
	if (strcmp(identity, CLIENT_PSK_IDENTITY)) {
		log_msg(LLVL_FATAL, "Server error: client identity '%s' unexpected (expected '%s').", identity, CLIENT_PSK_IDENTITY);
		return 0;
	}	
	memcpy(psk, server_key->psk, PSK_SIZE_BYTES);
	return PSK_SIZE_BYTES;
}

static int create_tcp_socket(int port) {
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
	fprintf(stderr, "Using key: ");
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

bool dtls_server(const struct keyentry_t *key, const struct options_t *options) {
	if (all_disks_unlocked(key)) {
		log_msg(LLVL_INFO, "Starting of server not necessary, all disks already unlocked.");
		return true;
	}

	struct generic_ssl_ctx_t gctx;
	create_generic_ssl_context(&gctx, true);

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
		free_generic_ssl_context(&gctx);
		return false;
	}

	int udp_sock = create_udp_socket();
	if (tcp_sock == -1) {
		log_msg(LLVL_ERROR, "Cannot broadcast without announcement UDP socket.");
		close(tcp_sock);
		free_generic_ssl_context(&gctx);
		return false;
	}

	log_msg(LLVL_DEBUG, "Created listening socket on port %d", options->port);	
	while (true) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);

		log_msg(LLVL_DEBUG, "Waiting for incoming connection...");
		announce_waiting_message(udp_sock, options->port, key);
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
			free_generic_ssl_context(&gctx);
			return false;
		}


		SSL *ssl = SSL_new(gctx.ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
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
	free_generic_ssl_context(&gctx);
	return true;
}


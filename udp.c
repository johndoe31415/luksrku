/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2019 Johannes Bauer

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
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "udp.h"

int create_udp_socket(unsigned int listen_port, bool send_broadcast) {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_libc(LLVL_ERROR, "Unable to create UDP server socket(2)");
		return -1;
	}
	if (send_broadcast) {
		int value = 1;
		if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value))) {
			log_libc(LLVL_ERROR, "Unable to set UDP socket in broadcast mode using setsockopt(2)");
			close(sd);
			return -1;
		}
	}

	if (listen_port) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(listen_port),
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};
		if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			log_libc(LLVL_ERROR, "Unable to bind UDP socket to listen to port %d", listen_port);
			close(sd);
			return -1;
		}
	}

	return sd;
}
bool wait_udp_message(int sd, int port, void *data, unsigned int length, struct sockaddr_in *source, unsigned int timeout_millis) {
	fprintf(stderr, "RECV...\n");
	socklen_t socklen = sizeof(struct sockaddr_in);
	ssize_t rx_bytes = recvfrom(sd,data, length, 0, (struct sockaddr*)source, &socklen);
	fprintf(stderr, "RECV %ld\n", rx_bytes);
	return rx_bytes == length;
}

bool send_udp_message(int sd, struct sockaddr_in *destination, const void *data, unsigned int length, bool is_response) {
	int flags = is_response ? MSG_CONFIRM : 0;
	ssize_t tx_bytes = sendto(sd, data, length, flags, (struct sockaddr*)destination, sizeof(struct sockaddr_in));
	if (tx_bytes < 0) {
		log_libc(LLVL_ERROR, "Unable to sendto(2)");
		return false;
	} else if (tx_bytes != length) {
		log_libc(LLVL_ERROR, "Unable to sendto(2) the complete message, %d bytes sent, but %u requested.", tx_bytes, length);
		return false;
	}
	return true;
}

bool send_udp_broadcast_message(int sd, int port, const void *data, unsigned int length) {
	struct sockaddr_in destination = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_BROADCAST),
	};
	return send_udp_message(sd, &destination, data, length, false);
}

bool wait_udp_query(int sd, int port, struct udp_query_t *query, struct sockaddr_in *source, unsigned int timeout_millis) {
	bool rx_successful = wait_udp_message(sd, port, query, sizeof(struct udp_query_t), source, timeout_millis);
	if (rx_successful) {
		/* Also check if the message contains the correct magic */
		if (!memcmp(query->magic, UDP_MESSAGE_MAGIC, UDP_MESSAGE_MAGIC_SIZE)) {
			return true;
		}
	}
	return false;
}

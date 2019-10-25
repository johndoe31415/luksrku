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

#ifndef __UDP_H__
#define __UDP_H__

#include <stdbool.h>
#include "msg.h"

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
int create_udp_socket(unsigned int listen_port, bool send_broadcast);
bool wait_udp_message(int sd, int port, void *data, unsigned int max_length, struct sockaddr_in *source, unsigned int timeout_millis);
bool send_udp_broadcast_message(int sd, int port, const void *data, unsigned int length);
bool wait_udp_query(int sd, int port, struct udp_query_t *query, struct sockaddr_in *source, unsigned int timeout_millis);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

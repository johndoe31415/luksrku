#include <arpa/inet.h>

#include "msg.h"

void msg_to_nbo(struct msg_t *msg) {
	msg->passphrase_length = htonl(msg->passphrase_length);
}

void msg_to_hbo(struct msg_t *msg) {
	msg->passphrase_length = ntohl(msg->passphrase_length);
}


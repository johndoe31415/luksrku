#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define PRINTF_FORMAT_IP(saddrptr)		(saddrptr->sin_addr.s_addr >> 0) & 0xff, (saddrptr->sin_addr.s_addr >> 8) & 0xff, (saddrptr->sin_addr.s_addr >> 16) & 0xff, (saddrptr->sin_addr.s_addr >> 24) & 0xff

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
char* query_passphrase(const char *prompt);
void dump_hex_long(FILE *f, const void *vdata, unsigned int length);
void dump_hex(FILE *f, const void *vdata, unsigned int length);
bool is_hex(const char *str, int length);
int parse_hexstr(const char *hexstr, uint8_t *data, int maxlen);
bool is_valid_uuid(const char *ascii_uuid);
bool parse_uuid(uint8_t *uuid, const char *ascii_uuid);
void sprintf_uuid(char *buffer, const uint8_t *uuid);
void dump_uuid(FILE *f, const uint8_t *uuid);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

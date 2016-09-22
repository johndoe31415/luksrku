#ifndef __LUKS_H__
#define __LUKS_H__

#include <stdbool.h>
#include <stdint.h>

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
bool is_luks_device_opened(const char *mapping_name);
bool open_luks_device(const uint8_t *encrypted_device_uuid, const char *mapping_name, const char *passphrase_file);
bool open_luks_device_pw(const uint8_t *encrypted_device_uuid, const char *mapping_name, const uint8_t *passphrase, int passphrase_length);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif

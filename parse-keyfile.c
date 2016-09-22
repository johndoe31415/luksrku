#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "keyfile.h"
#include "parse-keyfile.h"
#include "log.h"
#include "util.h"

static bool is_valid_psk(const char *hexpsk) {
	if (strlen(hexpsk) != 2 * PSK_SIZE_BYTES) {
		return false;
	}
	if (!is_hex(hexpsk, strlen(hexpsk))) {
		return false;
	}
	return true;
}

static bool is_valid_passphrase(const char *hexpass) {
	if ((strlen(hexpass) % 2) == 1) {
		return false;
	}
	return is_hex(hexpass, strlen(hexpass));
}

bool parse_keyfile(const char *filename, struct keydb_t *keydb, bool server_keyfile) {
	log_msg(LLVL_DEBUG, "Parsing %s keyfile from %s.", server_keyfile ? "server" : "client", filename);
	
	memset(keydb, 0, sizeof(struct keydb_t));
	FILE *f = fopen(filename, "r");
	if (!f) {
		return false;
	}

	char line[4096];
	int lineno = 0;
	while (fgets(line, sizeof(line) - 1, f) != NULL) {
		lineno++;
		/* Guarantee zero-termination */
		line[sizeof(line) - 1] = 0;

		int len = strlen(line);

		/* Remove CR/LF */
		if (line[len - 1] == '\r') {
			line[--len] = 0;
		}
		if (line[len - 1] == '\n') {
			line[--len] = 0;
		}

		if (len == 0) {
			/* Empty line */
			continue;
		}

		if ((line[0] == '#') || (line[0] == ';')) {
			/* Comment */
			continue;
		}

		if (!add_keyslot(keydb)) {
			log_msg(LLVL_ERROR, "Cannot allocate memory for keydb in line %d.", lineno);
			return false;
		}
		struct keyentry_t *slot = last_keyentry(keydb);


		char *saveptr = NULL;
		char *next;
		next = strtok_r(line, "\t ", &saveptr);
		if (!next) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: Empty line.", lineno, filename);
			return false;
		}

		if (!parse_uuid(slot->host_uuid, next)) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: No UUID given as server identifier.", lineno, filename);
			return false;
		}

		next = strtok_r(NULL, "\t ", &saveptr);
		if (!next) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: No second token (TLS PSK).", lineno, filename);
			return false;
		}
		if (!is_valid_psk(next)) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: No valid PSK given (needs to be %d bytes, i.e. %d hex characters).", lineno, filename, PSK_SIZE_BYTES, 2 * PSK_SIZE_BYTES);
			return false;
		}
		
		int psk_len = parse_hexstr(next, slot->psk, PSK_SIZE_BYTES);
		if (psk_len != PSK_SIZE_BYTES) {
			/* Should never happen, but double-check for robustness */
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: %d bytes parsed, but %d expected.", lineno, filename, psk_len, PSK_SIZE_BYTES);
			return false;
		}
		
		next = strtok_r(NULL, "\t ", &saveptr);
		if (!next) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: No third token (disk UUIDs/passphrases).", lineno, filename);
			return false;
		}

		if (next != NULL) {
			for (int i = 0; i < MAX_DISKS_PER_HOST; i++) {
				log_msg(LLVL_DEBUG, "Parsing keyentry #%d", i);
				next = strtok_r(next, "=", &saveptr);
				if (!next) {
					log_msg(LLVL_DEBUG, "Done parsing host config.");
					break;
				}
				if (!parse_uuid(slot->disk_keys[i].disk_uuid, next)) {
					log_msg(LLVL_ERROR, "Cannot parse line %d of %s: disk identifier '%s' is not a valid UUID.", lineno, filename, next);
					return false;
				}

				next = strtok_r(NULL, ",", &saveptr);
				if (!server_keyfile) {
					if (!next) {
						log_msg(LLVL_ERROR, "Client config needs to have a hex passphrase after a LUKS disk UUID.");
						return false;
					}
					if (!is_valid_passphrase(next)) {
						log_msg(LLVL_ERROR, "Cannot parse line %d of %s: disk passphrase '%s' is invalid.", lineno, filename, next);
						return false;
					}					
					slot->disk_keys[i].passphrase_length = parse_hexstr(next, slot->disk_keys[i].passphrase, MAX_PASSPHRASE_LENGTH);
				} else {
					if (!next) {
						log_msg(LLVL_ERROR, "Server config needs to have a device mapper name after a LUKS disk UUID.");
						return false;
					}
					if (strlen(next) > MAX_DEVMAPPER_NAME_LENGTH) {
						log_msg(LLVL_ERROR, "Cannot parse line %d of %s: device mapper name '%s' is too long (%d characters max).", lineno, filename, next, MAX_DEVMAPPER_NAME_LENGTH);
						return false;
					}
					if (next[0] == 0) {
						log_msg(LLVL_ERROR, "Cannot parse line %d of %s: device mapper name is empty.", lineno, filename);
						return false;
					}
					strcpy(slot->disk_keys[i].devmapper_name, next);
				}

				slot->disk_keys[i].occupied = true;
				next = NULL;
			}
		}
		
		next = strtok_r(NULL, "\t ", &saveptr);
		if (next) {
			log_msg(LLVL_ERROR, "Cannot parse line %d of %s: Too many fields in line.", lineno, filename);
			return false;
		}
	}

	fclose(f);

#ifdef DEBUG
	keydb_dump(keydb);
#endif
	return true;
}


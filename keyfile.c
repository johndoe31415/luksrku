#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "keyfile.h"
#include "util.h"

struct keyentry_t *last_keyentry(struct keydb_t *keydb) {
	return keydb_getentry(keydb, keydb->entrycnt - 1);
}

bool add_keyslot(struct keydb_t *keydb) {
	struct keyentry_t *new_db = realloc(keydb->entries, (keydb->entrycnt + 1) * sizeof(struct keyentry_t));
	if (!new_db) {
		return false;
	}
	keydb->entries = new_db;

	keydb->entrycnt++;
	memset(&keydb->entries[keydb->entrycnt - 1], 0, sizeof(struct keyentry_t));

	return true;
}

const struct keyentry_t *keydb_find_entry_by_host_uuid(const struct keydb_t *keydb, const uint8_t *server_uuid) {
	for (int i = 0; i < keydb->entrycnt; i++) {
		if (!memcmp(server_uuid, keydb->entries[i].host_uuid, 16)) {
			return keydb->entries + i;
		}
	}
	return NULL;
}

struct keyentry_t* keydb_getentry(struct keydb_t *keydb, int keyid) {
	if ((keyid < 0) || (keyid >= keydb->entrycnt)) {
		return NULL;
	}	
	return keydb->entries + keyid;
}

void keydb_dump(const struct keydb_t *keydb) {
	fprintf(stderr, "Dumping key database with %d host entries:\n", keydb->entrycnt);
	for (int i = 0; i < keydb->entrycnt; i++) {
		fprintf(stderr, "    Host entry %d: host UUID ", i);
		dump_uuid(stderr, keydb->entries[i].host_uuid);
		fprintf(stderr, ", PSK ");
		dump_hex(stderr, keydb->entries[i].psk, PSK_SIZE_BYTES);
		fprintf(stderr, "\n");
		
		for (int j = 0; j < MAX_DISKS_PER_HOST; j++) {
			if (keydb->entries[i].disk_keys[j].occupied) {
				fprintf(stderr, "        Disk key %d: UUID ", j);
				dump_uuid(stderr, keydb->entries[i].disk_keys[j].disk_uuid);
				if (keydb->entries[i].disk_keys[j].passphrase_length) {
					fprintf(stderr, " Key (%d bytes): ", keydb->entries[i].disk_keys[j].passphrase_length);
					dump_hex(stderr, keydb->entries[i].disk_keys[j].passphrase, keydb->entries[i].disk_keys[j].passphrase_length);
				}
				if (keydb->entries[i].disk_keys[j].devmapper_name[0] != 0) {
					fprintf(stderr, " devmapper name %s", keydb->entries[i].disk_keys[j].devmapper_name);
				}
				fprintf(stderr, "\n");
			}
		}
	}
}

unsigned int keydb_disk_key_count(const struct keydb_t *keydb) {
	unsigned int cnt = 0;
	for (int i = 0; i < keydb->entrycnt; i++) {
		for (int j = 0; j < MAX_DISKS_PER_HOST; j++) {
			if (keydb->entries[i].disk_keys[j].occupied && (keydb->entries[i].disk_keys[j].passphrase_length > 0)) {
				cnt++;
			}
		}
	}
	return cnt;
}

void keydb_free(struct keydb_t *keydb) {
	memset(keydb->entries, 0, keydb->entrycnt * sizeof(struct keyentry_t));
	free(keydb->entries);
	memset(keydb, 0, sizeof(struct keydb_t));
}

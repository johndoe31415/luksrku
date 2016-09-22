#ifndef __GLOBAL_H__
#define __GLOBAL_H__

/* Magic is the prefix of announcement packages. It is the MD5SUM over the
 * CLIENT_PSK_IDENTITY. This only changes when the protocol that is spoken
 * changes. */
#define CLIENT_PSK_IDENTITY									"luksrku v1"
#define CLIENT_ANNOUNCE_MAGIC								{ 0x46, 0xf2, 0xf6, 0xc6, 0x63, 0x12, 0x2e, 0x00, 0xa0, 0x8a, 0xae, 0x42, 0x0c, 0x51, 0xf5, 0x65 }

#define LUKSRKU_VERSION										"0.01"

/* Size in bytes of the PSK that is used for TLS */
#define PSK_SIZE_BYTES										32

/* How many disks every entry may contain */
#define MAX_DISKS_PER_HOST									8

/* How long a passphrase can be maximally */
#define MAX_PASSPHRASE_LENGTH								64

/* How long in characters a cryptsetup device name mapping may be */
#define MAX_DEVMAPPER_NAME_LENGTH							63

/* In what interval the server should broadcast that it's waiting for unlocking */
#define WAITING_MESSAGE_BROADCAST_INTERVAL_MILLISECONDS		1000


#define BLACKLIST_ENTRY_COUNT								16
#define BLACKLIST_ENTRY_TIMEOUT_SECS						120

/* Scrypt parameters for config file encryption */
#define SCRYPT_N											(1 << 17)
#define SCRYPT_r											8
#define SCRYPT_p											1

#define staticassert(cond)		_Static_assert((cond), #cond)

#endif

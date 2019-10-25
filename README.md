# luksrku
luksrku is a tool that allows you to remotely unlock LUKS disks during bootup
from within your initrd.  The intention is to have full-disk-encryption with
LUKS-rootfs running headlessly. You should be able to remotely unlock their
LUKS cryptographic file systems when you know they have been (legitimately)
rebooted. 

This works as follows: The luksrku client (which needs unlocking) and luksrku
server (which holds all the LUKS keys) share a secret. The client either knows
the address of the server or it can issue a broadcast in the network to find
the correct one.  With the help of the shared secret, a TLS connection is
established betweem the client and a legitimate server (who also knows the same
secret). The server then tells the client all the LUKS passphrases, which
performs luksOpen on all volumes.

## Security
luksrku uses TLSv1.3-PSK with forward-secrecy key shares (i.e., ECDHE). The
curves that are used are X448 and X25519 for key agreement and
TLS_CHACHA20_POLY1305_SHA256 or TLS_AES_256_GCM_SHA384 as cipher suites. PSKs
are 256 bit long and randomly generated (/dev/urandom). Likewise, the LUKS
passphrases are based on 256 bit long secrets and are converted to Base64 for
easier handling (when setting up everything initially).

The binary protocol that runs between both is intentionally extremely simple to
allow for easy code review. It exclusively uses fixed message lengths.

The key database is encrypted itself, using AES256-GCM, a 128 bit randomized
initialization vector and authenticated with a 128 bit authentication tag. Key
derivation is done using scrypt with N = 131072 = 2^18, r = 8, p = 1.

## Dependencies
OpenSSL v1.1 is required for luksrku.

## Example
TODO

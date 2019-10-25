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
derivation is done using scrypt with N = 262144 = 2^18, r = 8, p = 1.

When not in use, the server encrypts all LUKS passphrases and PSKs in-memory. A
large, 1 MiB pre-key is also kept in memory. This is to thwart cold-boot
attacks, because a successful cold-boot attack would require a complete and
perfect 1 MiB snapshot of the pre-key (or an acquisition in the short timeframe
where the keyvault is open) -- something that is difficult to do because of
naturally occuring bit errors during cold boot acquisition.

## Dependencies
OpenSSL v1.1 is required for luksrku as well as pkg-config.

## Usage
The help pages of luksrku are fairly well documented, i.e.:

```
$ ./luksrku
error: no command supplied

Available commands:
    ./luksrku edit     Interactively edit a key database
    ./luksrku server   Start a key server process
    ./luksrku client   Unlock LUKS volumes by querying a key server

For futher help: ./luksrku (command) --help

luksrku version v0.02-45-gf01ec97d6b-dirty
```

Then, for each command, you have an own help page:

```
$ ./luksrku edit --help
usage: luksrku edit [-v] [filename]

Edits a luksrks key database.

positional arguments:
  filename       Database file to edit.

optional arguments:
  -v, --verbose  Increase verbosity. Can be specified multiple times.
```

```
$ ./luksrku server --help
usage: luksrku server [-p port] [-s] [-v] filename

Starts a luksrku key server.

positional arguments:
  filename              Database file to load keys from.

optional arguments:
  -p port, --port port  Port that is used for both UDP and TCP communication.
                        Defaults to 23170.
  -s, --silent          Do not answer UDP queries for clients trying to find a
                        key server, only serve key database using TCP.
  -v, --verbose         Increase verbosity. Can be specified multiple times.
```

```
$ ./luksrku client --help
usage: luksrku client [-t secs] [-p port] [--no-luks] [-v] filename [hostname]

Connects to a luksrku key server and unlocks local LUKS volumes.

positional arguments:
  filename              Exported database file to load TLS-PSKs and list of
                        disks from.
  hostname              When hostname is given, auto-searching for suitable
                        servers is disabled and only a connection to the given
                        hostname is attempted.

optional arguments:
  -t secs, --timeout secs
                        When searching for a keyserver and not all volumes can
                        be unlocked, abort after this period of time, given in
                        seconds. Defaults to 60 seconds.
  -p port, --port port  Port that is used for both UDP and TCP communication.
                        Defaults to 23170.
  --no-luks             Do not call LUKS/cryptsetup. Useful for testing
                        unlocking procedure.
  -v, --verbose         Increase verbosity. Can be specified multiple times.
```

## Example
First, you need to create a server key database. For this you use the editor:

```
$ ./luksrku edit
> add_host my_host
```

Now there's a host "my_host" in the key database. At any point you can inspect
the database by using the "list" command:

```
Keydb version 2, server database, 1 hosts.
    Host 1: "my_host" UUID e7ff6e3d-1793-48f6-b43b-9c7bb0348622 -- 0 volumes:
```

You'll see that the host has no volumes associated with it. Determine the UUID
of the LUKS device that you want luksrku to decrypt, then add this volume with
the name you want it to have after unlocking. In our case, the UUID is
18de9f14-2914-4a8b-9b46-b7deacbfbe8a and we want it to decrypt as "crypt-root":

```
> add_volume my_host crypt-root 18de9f14-2914-4a8b-9b46-b7deacbfbe8a
LUKS passphrase of crypt-root / 18de9f14-2914-4a8b-9b46-b7deacbfbe8a: 5DySDFcpVtBRoIMNv7mrLqlozPYeq7X5kPmB3M1wsW8A
```

At this point, luksrku will tell you, in clear text, the LUKS passphrase that
you need to add to the volume. Then, you save the server database:

```
> save server.bin
Database passphrase:
```

It asks you for a passphrase that is needed to decrypt the file. On disk it's
always stored encrypted. Using an encrypted server database is highly
recommended.

For the client, you export the client portion of the database:

```
> export my_host my_host.bin
Client passphrase:
```

Note that client databases can also be encrypted, but they're less critical
than the server database. The client database does *not* contain the LUKS
passphrases, it only contains the required TLS-PSK so that a successful
connection to a luksrku server can be established.

With these two in place, you can now start a luksrku server:

```
$ ./luksrku server server.bin
Database passphrase:
[I]: Serving luksrku database for 1 hosts.
```

And on your client, when you want the LUKS disks to be unlocked:

```
$ ./luksrku client my_host.bin
```

## Integration into initramfs
Using luksrku as part of your initramfs is quite easy. You'll need a server
somewhere in your network and an exported client database. On the client, you
copy the client database file into `/etc/luksrku-client.bin`.

Then, install luksrku globally by performing `make install` as root and install
the initramfs script by running `install` in the initramfs/ subdirectory.
You'll only need to install that once.

```
# make install
strip luksrku
cp luksrku /usr/local/sbin/
chown root:root /usr/local/sbin/luksrku
chmod 755 /usr/local/sbin/luksrku
# cd initramfs
# ./install
```

Finally, have initramfs recreate your initial ramdisk:

```
# update-initramfs -u
```

That's it, it should now work.

## License
GNU GPL-3.

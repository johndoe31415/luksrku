Disclaimer
==========
**Warning** luksrku is currently *highly* experimental software. It is not
intended for production use yet. It is released following the "release early,
release often" philosophy in the hope to get valuable feedback for possible
areas of improvement. Please only use it when you're pretty certain that you
know what you're doing. Better yet, only use it after code review. If you've
reviewed my code, please let me know. I'm very interested in any and all
feedback. Drop it at joe@johannes-bauer.com, please. Thanks!

luksrku
=======
luksrku is a tool that allows you to remotely unlock LUKS disks during bootup.
The intention is to have headless systems running and you should be able to
remotely unlock their LUKS cryptographic file systems when you know they have
been (legitimately) rebooted. This works as follows: The *TLS server* runs on
the computer which needs unlocking. This computer broadcasts a UDP packet onto
the network indicating that it needs unlocking. The *TLS client* which knows
the LUKS passphrase then catches that packet, connect to the server and sends
the passphrase. The TLS configuration that is used ensures mutual
authentication and perfect forward secrecy. Concretely, TLS v1.2 is used with a
ECDHE handshake on Curve25519 and using the ECDHE-PSK-CHACHA20-POLY1305 cipher
suite. For authentication, a 256 bit long random PSK is used. The passphrase
for unlocking should be in a own keyslot (i.e., do not use a passphrase which
you remember).

Configuration
=============
Clients and servers use a configuration file. This is originally a text file
that is then converted to encrypted binary format using the luksrku-config
tool. This binary configuration file is encrypted using AES256-GCM, uses a 128
bit randomized initialization vector and authenticated with a 128 bit
authentication tag. The key derivation function which is used to derive the 256
bit AES key from the passphrase is scrypt with N = 131072, r = 8, p = 1.

Storing in a binary format serves two purposes: 
  1. Error-prone parsing of human-modifiable text is done in a separate
     application. These chunks of code are not linked into the luksrku binary.
  2. It allows for easy encryption.

The server key database contains no secrets, yet it is encrypted nevertheless.
The sole purpose is to keep the number of alternative code paths minimal. There
is no technical reason to encrypt the server configuration file, but again: it
contains *no* secrets. Using the same storage for server and client was maybe
an awkward design choice, but this is something that is ugly, but not
security-critical.

The client key database contains the LUKS keys, therefore it is advisable to
keep it encrypted with a passphrase. Only if this passphrase is correctly
entered on the client, the password can be decrypted on the client and
transmitted to the server. Note that care is taken to ensure no
length-of-message side channels reveal information about the underlying LUKS
passphrase. Therefore the transmitted messages are always of the same length.

The PSK that is used to communicate between client and server ensures mutual
authentication. If the PSK is stolen by an adversary, that adversary can simply
pose as a server and ask the client for the LUKS key. Therefore it is integral
that this PSK is kept safe. Passive attacks (i.e., where the adversary is only
eavesdropping on communication), however, are not compromised because the TLS
channel provides PFS.

Prerequisites
=============
Since the used cryptography (such as ECDH on Curve25519 and the
ECDHE-PSK-CHACHA20-POLY1305 cipher suite) are fairly new, support for at least
OpenSSL-1.1.0 is essential.


Example
=======
This is a very crude example. Feel free to improve it and send a PR. Let's say
we want to unlock the crypt-root of a headless system. I.e., only one LUKS
partition that should be unlocked. That LUKS partition has the UUID of
952ebed9-5256-4b4c-9de5-7f8829b4a74a (use blkid to find out). This is what we
can do:

  1. Build >=OpenSSL-1.1.0 (e.g., using the provided ./build_openssl command)
  2. Build and install luksrku: make && sudo make install
  3. Generate the keyfiles. For this we use the provided gen_config script:

```
Disk UUID : 952ebed9-5256-4b4c-9de5-7f8829b4a74a
Disk name : crypt-root
Suggestion: TDFV6Z6XyDQ52ASswVFSEl8mrVfnH9F5b
Passphrase: 

Disk UUID : 
# server.txt
# Host UUID                             Host PSK                                                            Disk UUIDs
d66f96fc-7056-46e1-aea6-0f3d705cd3bc    d94f3fc6c3507123bda4034dd8c865a1b4cf9870bda50e9ed9f861621d581017    952ebed9-5256-4b4c-9de5-7f8829b4a74a=crypt-root

# client.txt
# Host UUID                             Host PSK                                                            Disk UUIDs
d66f96fc-7056-46e1-aea6-0f3d705cd3bc    d94f3fc6c3507123bda4034dd8c865a1b4cf9870bda50e9ed9f861621d581017    952ebed9-5256-4b4c-9de5-7f8829b4a74a=54444656365a3658794451353241537377564653456c386d7256666e4839463562
```

     We follow the suggested passphrase, which should contain 192 bits of entropy.
  4. We use cryptsetup luksAddKey to add the suggested passphrase to the LUKS
     keyring of the server.
  5. The config script has given suggestions for server.txt and client.txt. We
     copy the respective contents into the files.
  6. Then we create the client and server binary configuration files:

```
$ luksrku-config server server.txt server.bin
Successfully read key file with 1 entries.
$ luksrku-config client client.txt client.bin
Successfully read key file with 1 entries.
Passphrase to encrypt keyfile:
```

     Now we'll have a server.bin and password-protected client.bin.
  7. On the server machine (i.e., the one with the LUKS disk) we copy
     server.bin to /etc/luksrku-server.bin.
  8. On the server, we modify the luksrku-script in the initramfs/ subdirectory
     to fit the NIC of the server and the IP address we want (this is really
     ugly at the moment and needs to be fixed ASAP, but it is what it is now).
  9. On the server, then run the "./install" script as root which will install
     initramfs hooks.
  10. On the server, update the initramfs (update-initramfs -u). Previously make
      a copy of your initramfs so that you can boot your system in case things
      go wrong (which they will, trust me).
  11. Boot the server. If everything went fine (it won't at the first run), it
      will now broadcast UDP packets onto the network indicating its presence.
      These packets will be sent to UDP port 23170.
  12. On the client, start the client to unlock the server's key:

```
$ luksrku --client-mode -k client.bin 
Keyfile password:
```



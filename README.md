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
luksrus is a tool that allows you to remotely unlock LUKS disks during bootup.
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



#!/bin/sh
#
# By Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

if [ ! -f /etc/luksrku-client.bin ]; then
        exit 1
fi

# on wicked based SUSE systems, the network-legacy module applies network configuration from the booted system, but it does not start the interface in time
ifup eth0

/sbin/luksrku client -v -t 10 /etc/luksrku-client.bin
luksrku_result="$?"

# unfortunately systemd does not seem to wait for the initqueue to finish before starting the password agent - hence we make the password prompt fail if luksrku succeeded 
if [ "$luksrku_result" = "0" ]; then
        echo "" | systemd-tty-ask-password-agent
fi

exit 0

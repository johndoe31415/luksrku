#!/bin/sh
#
# By Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

# called by dracut
check() {
        if [ ! -f /etc/luksrku-client.bin ]; then
                exit 0
        fi

        require_binaries /usr/local/sbin/luksrku cryptsetup
}

# called by dracut
depends() {
        echo network
}

cmdline() {
        printf "%s" "rd.neednet=1"
}

# called by dracut
install() {
        inst /usr/local/sbin/luksrku /sbin/luksrku
        inst cryptsetup
        inst_hook initqueue 10 "$moddir/luksrku-script.sh"
        inst_simple /etc/luksrku-client.bin /etc/luksrku-client.bin
        local _netconf=$(cmdline)
        printf "%s\n" "$_netconf" >> "$initdir/etc/cmdline.d/89luksrku.conf"
}

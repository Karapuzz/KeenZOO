#!/bin/sh

[ "$1" != "start" ] && exit 0

for s in unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter; do
    ipset create "$s" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null
done

if ls -d /opt/etc/unblock/vpn-*.txt >/dev/null 2>&1; then
    for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
        [ -f "$vpn_file_names" ] || continue
        vpn_file_name=$(basename "$vpn_file_names" .txt)
        unblockvpn="unblock${vpn_file_name}"
        ipset create "$unblockvpn" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null
    done
fi

exit 0

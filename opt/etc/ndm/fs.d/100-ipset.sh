#!/bin/sh
# /opt/etc/ndm/fs.d/100-ipset.sh — создание наборов ipset при монтировании
# накопителя Entware, до старта сервисов и правил netfilter.
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

[ "${1:-}" != "start" ] && exit 0

for s in unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter unblockdns; do
    ipset create "$s" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
done

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    ipset create "$unblockvpn" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
done

exit 0

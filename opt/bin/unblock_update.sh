#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

SCRIPT_LOCK="${SCRIPT_LOCK:-/tmp/unblock_update.lockdir}"
STATUS_FILE="${STATUS_FILE:-/tmp/unblock_update_status.json}"
TMP_STATUS="${STATUS_FILE}.tmp"

write_status() {
    _st="$1"
    _msg="$2"
    _ts="$(date +%s)"
    printf '{"status":"%s","ts":%s,"message":"%s"}\n' \
        "$_st" "$_ts" "$_msg" > "$TMP_STATUS"
    mv -f "$TMP_STATUS" "$STATUS_FILE"
}

cleanup() {
    rm -f "$TMP_STATUS"
    rm -rf "$SCRIPT_LOCK"
}
trap cleanup EXIT INT TERM HUP

TRIES=0
while ! mkdir "$SCRIPT_LOCK" 2>/dev/null; do
    if [ -f "$SCRIPT_LOCK/pid" ]; then
        OLD_PID="$(cat "$SCRIPT_LOCK/pid" 2>/dev/null || true)"
        if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
            rm -rf "$SCRIPT_LOCK"
            continue
        fi
    fi

    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 150 ]; then
        write_status "error" "locked"
        exit 1
    fi
    sleep 2
done

echo "$$" > "$SCRIPT_LOCK/pid"
write_status "running" "start"

STATIC_SETS="unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter"
VPN_SETS=""

for s in $STATIC_SETS; do
    ipset create "$s" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset create "${s}_new" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset flush "${s}_new" 2>/dev/null || true
done

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    VPN_SETS="${VPN_SETS}${VPN_SETS:+ }${unblockvpn}"
    ipset create "$unblockvpn" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset create "${unblockvpn}_new" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset flush "${unblockvpn}_new" 2>/dev/null || true
done

if ! IPSET_SUFFIX="_new" /opt/bin/unblock_dnsmasq.sh; then
    write_status "error" "dnsmasq gen"
    exit 1
fi

if ! IPSET_SUFFIX="_new" /opt/bin/unblock_ipset.sh; then
    write_status "error" "ipset fill"
    exit 1
fi

for s in $STATIC_SETS $VPN_SETS; do
    ipset swap "$s" "${s}_new" 2>/dev/null || true
done

[ -x /opt/etc/init.d/S56dnsmasq ] && /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1 || true

for s in $STATIC_SETS $VPN_SETS; do
    ipset flush "${s}_new" 2>/dev/null || true
    ipset destroy "${s}_new" 2>/dev/null || true
done

write_status "done" "ok"
exit 0
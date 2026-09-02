#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

OUT_FILE="/opt/etc/unblock.dnsmasq"
CIDR_FILE="/opt/etc/unblock.dnsmasq.cidr"
IPSET_SUFFIX="${IPSET_SUFFIX:-}"

TMP_OUT="$(mktemp /tmp/unblock.dnsmasq.XXXXXX)"
TMP_CIDR="$(mktemp /tmp/unblock.dnsmasq.cidr.XXXXXX)"

cleanup() {
    rm -f "$TMP_OUT" "$TMP_CIDR"
}
trap cleanup EXIT INT TERM HUP

: > "$TMP_OUT"
: > "$TMP_CIDR"

trim_comment() {
    printf '%s' "$1" | sed 's/[[:space:]]*#.*$//' | sed 's/[[:space:]]*$//'
}

is_ip() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/) exit 1
                if ($i < 0 || $i > 255) exit 1
                if ($i ~ /^0[0-9]+$/) exit 1
            }
        }
        END { exit 0 }
    '
}

is_cidr() {
    _entry="$1"
    case "$_entry" in
        */*)
            _ip="${_entry%/*}"
            _prefix="${_entry#*/}"
            ;;
        *)
            return 1
            ;;
    esac

    printf '%s\n' "$_prefix" | grep -Eq '^[0-9]{1,2}$' || return 1
    [ "$_prefix" -le 32 ] || return 1
    is_ip "$_ip"
}

is_domain_core() {
    printf '%s\n' "$1" | awk '
        {
            s = tolower($0)
            if (s == "" || index(s, "/") > 0) { bad = 1; exit }
            n = split(s, a, ".")
            if (n < 2) { bad = 1; exit }

            for (i = 1; i <= n; i++) {
                if (a[i] == "" || length(a[i]) > 63) { bad = 1; exit }
                if (a[i] !~ /^[0-9a-z]([0-9a-z-]*[0-9a-z])?$/) { bad = 1; exit }
            }
        }
        END { exit (bad ? 1 : 0) }
    '
}

normalize_domain_mode() {
    _value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"

    case "$_value" in
        \*.*)
            _base="${_value#*.}"
            is_domain_core "$_base" || return 1
            printf 'wildcard %s\n' "$_base"
            ;;
        *)
            is_domain_core "$_value" || return 1
            printf 'domain %s\n' "$_value"
            ;;
    esac
}

DNS_PORTS_DOT="40500 40501 40502 40503"
DNS_PORTS_DOH="40508 40509 40510 40511"

find_first_working_port() {
    for _fwp_port in "$@"; do
        if dig +short +timeout=2 +tries=1 google.com @localhost -p "$_fwp_port" 2>/dev/null \
            | grep -qE '^[0-9]+\.[0-9]+'; then
            echo "$_fwp_port"
            return 0
        fi
    done
    return 1
}

DNS_DOT_PORT="$(find_first_working_port 40500 40501 40502 40503 || true)"
DNS_DOH_PORT="$(find_first_working_port 40508 40509 40510 40511 || true)"

if [ -n "$DNS_DOT_PORT" ]; then
    DNS_PRIMARY="$DNS_DOT_PORT"
    DNS_BACKUP="$DNS_DOH_PORT"
elif [ -n "$DNS_DOH_PORT" ]; then
    DNS_PRIMARY="$DNS_DOH_PORT"
    DNS_BACKUP=""
else
    DNS_PRIMARY="40500"
    DNS_BACKUP=""
fi

logger -t "unblock_dnsmasq" "DNS primary=$DNS_PRIMARY backup=${DNS_BACKUP:-none}"

append_domain_rules() {
    _host="$1"
    _setname="$2"
    _dns_port="$3"
    _backup_port="$4"
    _wildcard="${5:-no}"

    if [ "$_wildcard" = "yes" ]; then
        printf 'ipset=/*.%s/%s\n' "$_host" "$_setname" >> "$TMP_OUT"
        printf 'server=/*.%s/127.0.0.1#%s\n' "$_host" "$_dns_port" >> "$TMP_OUT"
        [ -n "$_backup_port" ] && printf 'server=/*.%s/127.0.0.1#%s\n' "$_host" "$_backup_port" >> "$TMP_OUT"
    fi

    printf 'ipset=/%s/%s\n' "$_host" "$_setname" >> "$TMP_OUT"
    printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_dns_port" >> "$TMP_OUT"
    [ -n "$_backup_port" ] && printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_backup_port" >> "$TMP_OUT"
}

process_dnsmasq_list() {
    _file="$1"
    _setname="$2"
    _dns_port="$3"
    _allow_wildcard="$4"

    [ -f "$_file" ] || return 0

    _backup_port=""
    if [ "$_dns_port" != "9053" ] && [ -n "$DNS_BACKUP" ] && [ "$DNS_BACKUP" != "$_dns_port" ]; then
        _backup_port="$DNS_BACKUP"
    fi

    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line="$(trim_comment "$raw_line")"
        [ -n "$line" ] || continue

        if is_ip "$line"; then
            continue
        fi

        if is_cidr "$line"; then
            printf 'add %s %s\n' "$_setname" "$line" >> "$TMP_CIDR"
            continue
        fi

        _normalized="$(normalize_domain_mode "$line" 2>/dev/null || true)"
        if [ -z "$_normalized" ]; then
            logger -t "unblock_dnsmasq" "skip invalid entry: $line"
            continue
        fi

        _mode="${_normalized%% *}"
        _host="${_normalized#* }"

        if [ "$_mode" = "wildcard" ]; then
            if [ "$_allow_wildcard" = "yes" ]; then
                append_domain_rules "$_host" "$_setname" "$_dns_port" "$_backup_port" "yes"
            else
                logger -t "unblock_dnsmasq" "skip wildcard in non-wildcard list: $line"
            fi
            continue
        fi

        append_domain_rules "$_host" "$_setname" "$_dns_port" "$_backup_port" "no"
    done < "$_file"
}

process_dnsmasq_list /opt/etc/unblock/shadowsocks.txt unblocksh "$DNS_PRIMARY" yes
process_dnsmasq_list /opt/etc/unblock/tor.txt unblocktor 9053 no
process_dnsmasq_list /opt/etc/unblock/vless.txt unblockvless "$DNS_PRIMARY" no
process_dnsmasq_list /opt/etc/unblock/trojan.txt unblocktroj "$DNS_PRIMARY" no
process_dnsmasq_list /opt/etc/unblock/hysteria.txt unblockhysteria "$DNS_PRIMARY" no
process_dnsmasq_list /opt/etc/unblock/bot.txt unblockrouter "$DNS_PRIMARY" no

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    process_dnsmasq_list "$vpn_file_names" "$unblockvpn" "$DNS_PRIMARY" no
done

if [ -s "$TMP_OUT" ]; then
    LC_ALL=C sort -u "$TMP_OUT" > "${TMP_OUT}.sorted"
    mv -f "${TMP_OUT}.sorted" "$OUT_FILE"
else
    : > "$OUT_FILE"
fi

if [ -s "$TMP_CIDR" ]; then
    LC_ALL=C sort -u "$TMP_CIDR" > "${TMP_CIDR}.sorted"
    mv -f "${TMP_CIDR}.sorted" "$CIDR_FILE"

    while IFS=' ' read -r _action set_name cidr_entry; do
        [ -n "$set_name" ] || continue
        [ -n "$cidr_entry" ] || continue
        ipset create "${set_name}${IPSET_SUFFIX}" hash:net family inet -exist 2>/dev/null || true
        ipset del "${set_name}${IPSET_SUFFIX}" "$cidr_entry" 2>/dev/null || true
    done < "$CIDR_FILE"

    while IFS=' ' read -r _action set_name cidr_entry; do
        [ -n "$set_name" ] || continue
        [ -n "$cidr_entry" ] || continue
        ipset create "${set_name}${IPSET_SUFFIX}" hash:net family inet -exist 2>/dev/null || true
        ipset add "${set_name}${IPSET_SUFFIX}" "$cidr_entry" 2>/dev/null || true
    done < "$CIDR_FILE"
else
    rm -f "$CIDR_FILE"
fi
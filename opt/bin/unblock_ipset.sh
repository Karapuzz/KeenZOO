#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

MAX_PARALLEL="${MAX_PARALLEL:-4}"
TMP_BASE="/tmp/unblock_resolve"
IPSET_SUFFIX="${IPSET_SUFFIX:-}"

rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE"

cleanup() {
    rm -rf "$TMP_BASE"
}
trap cleanup EXIT INT TERM HUP

DNS_PORTS_DOT="40500 40501 40502 40503"
DNS_PORTS_DOH="40508 40509 40510 40511"
DNS_PORTS_ALL="$DNS_PORTS_DOT $DNS_PORTS_DOH"

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

ip_range_in_order() {
    _start="$1"
    _end="$2"
    awk -v a="$_start" -v b="$_end" '
        function ip2int(ip, p) {
            split(ip, p, ".")
            return (((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4])
        }
        BEGIN {
            exit !(ip2int(a) <= ip2int(b))
        }
    '
}

is_range() {
    _entry="$1"
    case "$_entry" in
        *-*)
            _start="${_entry%-*}"
            _end="${_entry#*-}"
            ;;
        *)
            return 1
            ;;
    esac

    is_ip "$_start" || return 1
    is_ip "$_end" || return 1
    ip_range_in_order "$_start" "$_end"
}

is_public_ipv4() {
    _ip="$1"
    is_ip "$_ip" || return 1

    printf '%s\n' "$_ip" | awk -F. '
        $1 == 0 { exit 1 }
        $1 == 10 { exit 1 }
        $1 == 127 { exit 1 }
        $1 == 169 && $2 == 254 { exit 1 }
        $1 == 172 && $2 >= 16 && $2 <= 31 { exit 1 }
        $1 == 192 && $2 == 168 { exit 1 }
        END { exit 0 }
    '
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

normalize_domain_target() {
    _value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"

    case "$_value" in
        \*.*)
            _base="${_value#*.}"
            is_domain_core "$_base" || return 1
            printf '%s\n' "$_base"
            ;;
        *)
            is_domain_core "$_value" || return 1
            printf '%s\n' "$_value"
            ;;
    esac
}

test_dns_port() {
    dig +short +timeout=2 +tries=1 google.com @localhost -p "$1" 2>/dev/null \
        | grep -qE '^[0-9]+\.[0-9]+'
}

find_all_working_ports() {
    _faw_result=""
    for _faw_port in $DNS_PORTS_ALL; do
        if test_dns_port "$_faw_port"; then
            _faw_result="${_faw_result}${_faw_result:+ }${_faw_port}"
        fi
    done
    echo "$_faw_result"
}

COUNT=0
WORKING_DNS_PORTS=""
while [ -z "$WORKING_DNS_PORTS" ]; do
    WORKING_DNS_PORTS="$(find_all_working_ports)"
    [ -n "$WORKING_DNS_PORTS" ] && break
    sleep 5
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -gt 12 ]; then
        WORKING_DNS_PORTS="40500"
        break
    fi
done

WORKING_PORT_COUNT="$(printf '%s\n' "$WORKING_DNS_PORTS" | wc -w | awk '{print $1}')"
logger -t "unblock_ipset" "DNS ports ($WORKING_PORT_COUNT): $WORKING_DNS_PORTS"

resilient_dig() {
    _rd_domain="$1"
    _rd_primary_port="$2"
    _rd_tried=""

    for _rd_port in "$_rd_primary_port" $WORKING_DNS_PORTS; do
        printf ' %s ' "$_rd_tried" | grep -q " $_rd_port " && continue
        _rd_tried="${_rd_tried}${_rd_tried:+ }${_rd_port}"

        _rd_result="$(dig +short +timeout=3 +tries=1 \
            "$_rd_domain" @localhost -p "$_rd_port" 2>/dev/null || true)"

        if [ -n "$_rd_result" ]; then
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                [ -n "$_candidate" ] || continue
                if is_public_ipv4 "$_candidate"; then
                    printf '%s\n' "$_candidate"
                fi
            done
            return 0
        fi
    done

    return 1
}

get_rr_port() {
    if [ "$WORKING_PORT_COUNT" -le 0 ] 2>/dev/null; then
        echo "40500"
        return
    fi
    _grp_n=$(( (("$1" - 1) % WORKING_PORT_COUNT) + 1 ))
    echo "$WORKING_DNS_PORTS" | tr ' ' '\n' | sed -n "${_grp_n}p"
}

process_list() {
    _pl_file="$1"
    _pl_setname="$2"
    _pl_setname_real="${_pl_setname}${IPSET_SUFFIX}"

    [ -f "$_pl_file" ] || return 0

    _pl_work="${TMP_BASE}/${_pl_setname}"
    _pl_batch="${_pl_work}/batch.txt"
    _pl_resdir="${_pl_work}/res"

    rm -rf "$_pl_work"
    mkdir -p "$_pl_resdir"
    : > "$_pl_batch"

    ipset create "$_pl_setname_real" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || return 1

    _pl_jobs=0
    _pl_idx=0

    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line="$(trim_comment "$raw_line")"
        [ -n "$line" ] || continue

        if is_cidr "$line"; then
            _cidr_ip="${line%/*}"
            if is_public_ipv4 "$_cidr_ip"; then
                printf 'add %s %s\n' "$_pl_setname_real" "$line" >> "$_pl_batch"
            fi
            continue
        fi

        if is_range "$line"; then
            _range_start="${line%-*}"
            if is_public_ipv4 "$_range_start"; then
                printf 'add %s %s\n' "$_pl_setname_real" "$line" >> "$_pl_batch"
            fi
            continue
        fi

        if is_ip "$line"; then
            if is_public_ipv4 "$line"; then
                printf 'add %s %s\n' "$_pl_setname_real" "$line" >> "$_pl_batch"
            fi
            continue
        fi

        _domain_target="$(normalize_domain_target "$line" 2>/dev/null || true)"
        [ -n "$_domain_target" ] || continue

        _pl_idx=$((_pl_idx + 1))
        _pl_dig_port="$(get_rr_port "$_pl_idx")"

        (
            resilient_dig "$_domain_target" "$_pl_dig_port" \
                | awk -v s="$_pl_setname_real" '{print "add " s " " $0}' \
                > "$_pl_resdir/$_pl_idx" 2>/dev/null || true
        ) &
        _pl_jobs=$((_pl_jobs + 1))

        if [ "$_pl_jobs" -ge "$MAX_PARALLEL" ]; then
            wait || true
            _pl_jobs=0
        fi
    done < "$_pl_file"

    wait || true

    _pl_restore="${_pl_work}/restore.txt"
    {
        cat "$_pl_batch"
        cat "$_pl_resdir"/* 2>/dev/null || true
    } | LC_ALL=C sort -u > "$_pl_restore"

    if [ -s "$_pl_restore" ]; then
        if ! ipset restore -exist < "$_pl_restore" 2>/tmp/unblock_ipset_restore.err; then
            logger -t "unblock_ipset" "ipset restore failed for $_pl_setname_real"
            cat /tmp/unblock_ipset_restore.err >&2 || true
            rm -rf "$_pl_work"
            return 1
        fi
    fi

    rm -rf "$_pl_work"
    return 0
}

FAILED=""

run_list() {
    _rl_file="$1"
    _rl_set="$2"
    if ! process_list "$_rl_file" "$_rl_set"; then
        FAILED="${FAILED}${FAILED:+ }${_rl_set}"
    fi
}

run_list /opt/etc/unblock/shadowsocks.txt  unblocksh
run_list /opt/etc/unblock/tor.txt          unblocktor
run_list /opt/etc/unblock/vless.txt        unblockvless
run_list /opt/etc/unblock/trojan.txt       unblocktroj
run_list /opt/etc/unblock/hysteria.txt     unblockhysteria
run_list /opt/etc/unblock/bot.txt          unblockrouter

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    ipset create "${unblockvpn}${IPSET_SUFFIX}" hash:net hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    run_list "$vpn_file_names" "$unblockvpn"
done

if [ -n "$FAILED" ]; then
    logger -t "unblock_ipset" "process_list failed: $FAILED"
    echo "process_list failed: $FAILED" >&2
    exit 1
fi

exit 0
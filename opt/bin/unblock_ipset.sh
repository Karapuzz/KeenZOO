#!/bin/sh
# remove keeps data but disables cron/NDM reactivation until next install.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# Keep the tunnel listener ports in step with the existing deploy
# configuration. Parsing is intentionally simple and BusyBox-compatible;
# missing values keep the known Keenetic defaults.
config_number() {
    _cn_key="$1"
    _cn_default="$2"
    _cn_value="$(sed -n \
        -e "s/^[[:space:]]*${_cn_key}[[:space:]]*=[[:space:]]*'\\([0-9][0-9]*\\)'.*$/\\1/p" \
        -e 's/^[[:space:]]*'"${_cn_key}"'[[:space:]]*=[[:space:]]*"\\([0-9][0-9]*\\)".*$/\\1/p' \
        -e "s/^[[:space:]]*${_cn_key}[[:space:]]*=[[:space:]]*\\([0-9][0-9]*\\).*$/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    case "$_cn_value" in ''|*[!0-9]*) _cn_value="$_cn_default" ;; esac
    printf '%s\n' "$_cn_value"
}

config_string() {
    _cs_key="$1"
    _cs_default="$2"
    _cs_value="$(sed -n \
        -e "s/^[[:space:]]*${_cs_key}[[:space:]]*=[[:space:]]*'\\([^']*\\)'.*$/\\1/p" \
        -e 's/^[[:space:]]*'"${_cs_key}"'[[:space:]]*=[[:space:]]*"\\([^"\\]*\\)".*/\\1/p' \
        /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    [ -n "$_cs_value" ] || _cs_value="$_cs_default"
    printf '%s\n' "$_cs_value"
}

PORT_VLESS="${PORT_VLESS:-$(config_number localportvless 10810)}"
PORT_TROJAN="${PORT_TROJAN:-$(config_number localporttrojan 10829)}"
PORT_HYSTERIA="${PORT_HYSTERIA:-$(config_number localporthysteria 10830)}"

# Глобальный лимит одновременных dig. Списков шесть и более, поэтому без
# общего ограничения на роутере могло подниматься до нескольких десятков
# процессов dig одновременно (перегрузка dnsmasq и нехватка памяти).
MAX_PARALLEL="${MAX_PARALLEL:-4}"
MIN_RESOLVE_RATIO="${MIN_RESOLVE_RATIO:-50}"
IPSET_SUFFIX="${IPSET_SUFFIX:-}"

# Keep standalone/manual ipset runs from racing with cron or a WAN hook.
# unblock_update.sh exports KEENZOO_UPDATE_LOCK_HELD while it owns the same
# lock for the whole transaction.
KEENZOO_LOCK_DIR="${KEENZOO_LOCK_DIR:-/tmp/unblock_update.lockdir}"
KEENZOO_UPDATE_LOCK_HELD="${KEENZOO_UPDATE_LOCK_HELD:-0}"
LOCK_ACQUIRED=0
if [ "$KEENZOO_UPDATE_LOCK_HELD" != "1" ]; then
    _kz_lock_tries=0
    while ! mkdir "$KEENZOO_LOCK_DIR" 2>/dev/null; do
        # mkdir is atomic, but pid/start are written immediately afterwards.
        # Preserve a fresh metadata-less lock instead of deleting a live owner.
        if [ ! -f "$KEENZOO_LOCK_DIR/pid" ]; then
            _kz_mtime="$(stat -c %Y "$KEENZOO_LOCK_DIR" 2>/dev/null || echo 0)"
            _kz_now="$(date +%s 2>/dev/null || echo 0)"
            case "$_kz_mtime:$_kz_now" in
                *[!0-9:]*|0:*) ;;
                *)
                    if [ $((_kz_now - _kz_mtime)) -lt 10 ]; then
                        _kz_lock_tries=$((_kz_lock_tries + 1))
                        [ "$_kz_lock_tries" -lt 60 ] || exit 75
                        sleep 1
                        continue
                    fi
                    ;;
            esac
        fi
        _kz_old_pid="$(cat "$KEENZOO_LOCK_DIR/pid" 2>/dev/null || true)"
        _kz_old_start="$(cat "$KEENZOO_LOCK_DIR/start" 2>/dev/null || true)"
        _kz_live=0
        case "$_kz_old_pid" in
            ''|*[!0-9]*) ;;
            *)
                if kill -0 "$_kz_old_pid" 2>/dev/null; then
                    _kz_now_start="$(awk '{print $22}' "/proc/$_kz_old_pid/stat" 2>/dev/null || true)"
                    [ -z "$_kz_old_start" ] || [ "$_kz_now_start" = "$_kz_old_start" ] && _kz_live=1
                fi
                ;;
        esac
        if [ "$_kz_live" -eq 0 ]; then
            rm -rf "$KEENZOO_LOCK_DIR"
            continue
        fi
        _kz_lock_tries=$((_kz_lock_tries + 1))
        [ "$_kz_lock_tries" -lt 60 ] || exit 75
        sleep 1
    done
    LOCK_ACQUIRED=1
    printf '%s\n' "$$" > "$KEENZOO_LOCK_DIR/pid"
    awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$KEENZOO_LOCK_DIR/start" || true
fi

# Child netfilter calls are part of this transaction; do not let them try to
# acquire the same lock a second time when this script owns it directly.
[ "$LOCK_ACQUIRED" -eq 1 ] && KEENZOO_UPDATE_LOCK_HELD=1
export KEENZOO_LOCK_DIR KEENZOO_UPDATE_LOCK_HELD

TMP_BASE="/tmp/unblock_resolve.$$"
rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE"

cleanup() {
    rm -rf "$TMP_BASE"
    if [ "$LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$KEENZOO_LOCK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

trim_comment() {
    printf '%s' "$1" | sed 's/[[:space:]]*#.*$//' | sed 's/[[:space:]]*$//'
}

# ── Валидация записей ────────────────────────────────────────────────────
# awk BusyBox не поддерживает интервалы {n,m} в регулярных выражениях
# надёжно, поэтому проверки октетов выполняются арифметикой, а домены —
# посимвольным разбором меток.

is_ip() {
    # ВАЖНО: в BusyBox awk "exit N" из основного блока передаёт управление
    # в END, и повторный exit там перезаписывает код возврата. Поэтому
    # результат накапливается во флаге bad и возвращается один раз в END.
    printf '%s\n' "$1" | awk -F. '
        {
            if (NF != 4) { bad = 1; exit }
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/) { bad = 1; exit }
                if (length($i) > 3) { bad = 1; exit }
                if (length($i) > 1 && substr($i, 1, 1) == "0") { bad = 1; exit }
                if ($i + 0 > 255) { bad = 1; exit }
            }
        }
        END { exit (bad ? 1 : 0) }
    '
}

is_cidr() {
    _entry="$1"
    case "$_entry" in
        */*)
            _ip="${_entry%%/*}"
            _prefix="${_entry#*/}"
            ;;
        *)
            return 1
            ;;
    esac

    case "$_prefix" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#_prefix}" -le 2 ] || return 1
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
            _start="${_entry%%-*}"
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

# Приватные/служебные диапазоны в туннель не отправляем.
# Полный набор RFC1918 + CGNAT + link-local + loopback + multicast.
is_public_ipv4() {
    _ip="$1"
    is_ip "$_ip" || return 1

    printf '%s\n' "$_ip" | awk -F. '
        {
            o1 = $1 + 0; o2 = $2 + 0
            if (o1 == 0) { bad = 1; exit }
            if (o1 == 10) { bad = 1; exit }
            if (o1 == 127) { bad = 1; exit }
            if (o1 == 100 && o2 >= 64 && o2 <= 127) { bad = 1; exit }
            if (o1 == 169 && o2 == 254) { bad = 1; exit }
            if (o1 == 172 && o2 >= 16 && o2 <= 31) { bad = 1; exit }
            if (o1 == 192 && o2 == 168) { bad = 1; exit }
            if (o1 == 192 && o2 == 0 && ($3 == 0 || $3 == 2)) { bad = 1; exit }
            if (o1 == 198 && o2 == 51 && $3 == 100) { bad = 1; exit }
            if (o1 == 203 && o2 == 0 && $3 == 113) { bad = 1; exit }
            if (o1 == 198 && (o2 == 18 || o2 == 19)) { bad = 1; exit }
            if (o1 >= 224) { bad = 1; exit }
        }
        END { exit (bad ? 1 : 0) }
    '
}


# Validate the complete CIDR/range interval, not only its first address.
is_public_cidr() {
    _ipc_entry="$1"
    case "$_ipc_entry" in
        */*) _ipc_ip="${_ipc_entry%%/*}"; _ipc_prefix="${_ipc_entry#*/}" ;;
        *) return 1 ;;
    esac
    is_ip "$_ipc_ip" || return 1
    case "$_ipc_prefix" in ''|*[!0-9]*) return 1 ;; esac
    awk -F. -v p="$_ipc_prefix" -v ip="$_ipc_ip" '
        function ip2int(v, a) {
            split(v, a, ".")
            return (((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4])
        }
        function overlap(a, b, c, d) { return a <= d && b >= c }
        BEGIN {
            if (p < 0 || p > 32) exit 1
            v = ip2int(ip); block = 2 ^ (32 - p)
            first = int(v / block) * block; last = first + block - 1
            if (overlap(first,last,0,16777215) ||
                overlap(first,last,167772160,184549375) ||
                overlap(first,last,1681915904,1686110207) ||
                overlap(first,last,2130706432,2147483647) ||
                overlap(first,last,2851995648,2852061183) ||
                overlap(first,last,2886729728,2887778303) ||
                overlap(first,last,3221225472,3221225727) ||
                overlap(first,last,3221225984,3221226239) ||
                overlap(first,last,3232235520,3232301055) ||
                overlap(first,last,3323068416,3323199487) ||
                overlap(first,last,3325256704,3325256959) ||
                overlap(first,last,3405803776,3405804031) ||
                overlap(first,last,3758096384,4294967295)) exit 1
            exit 0
        }
    '
}

is_public_range() {
    _ipr_entry="$1"
    case "$_ipr_entry" in
        *-*) _ipr_start="${_ipr_entry%%-*}"; _ipr_end="${_ipr_entry#*-}" ;;
        *) return 1 ;;
    esac
    is_ip "$_ipr_start" || return 1
    is_ip "$_ipr_end" || return 1
    awk -F. -v a="$_ipr_start" -v b="$_ipr_end" '
        function ip2int(v, p) {
            split(v, p, ".")
            return (((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4])
        }
        function overlap(x, y, z, w) { return x <= w && y >= z }
        BEGIN {
            first = ip2int(a); last = ip2int(b)
            if (first > last) exit 1
            if (overlap(first,last,0,16777215) ||
                overlap(first,last,167772160,184549375) ||
                overlap(first,last,1681915904,1686110207) ||
                overlap(first,last,2130706432,2147483647) ||
                overlap(first,last,2851995648,2852061183) ||
                overlap(first,last,2886729728,2887778303) ||
                overlap(first,last,3221225472,3221225727) ||
                overlap(first,last,3221225984,3221226239) ||
                overlap(first,last,3232235520,3232301055) ||
                overlap(first,last,3323068416,3323199487) ||
                overlap(first,last,3325256704,3325256959) ||
                overlap(first,last,3405803776,3405804031) ||
                overlap(first,last,3758096384,4294967295)) exit 1
            exit 0
        }
    '
}

DNSMASQ_CONF="${DNSMASQ_CONF:-/opt/etc/dnsmasq.conf}"
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-$(config_string dns_health_log /opt/var/log/unblock_dns_health.log)}"
KEENZOO_DNS_SNAPSHOT_MAX_AGE="${KEENZOO_DNS_SNAPSHOT_MAX_AGE:-$(config_number dns_snapshot_max_age 90000)}"
case "$KEENZOO_DNS_SNAPSHOT_MAX_AGE" in
    ''|*[!0-9]*) KEENZOO_DNS_SNAPSHOT_MAX_AGE=90000 ;;
esac
DNS_TUNNEL_PROTOCOL=""


tunnel_protocol_init() {
    case "$1" in
        xray) printf '%s %s\n' /opt/etc/init.d/S24xray xray ;;
        trojan) printf '%s %s\n' /opt/etc/init.d/S22trojan trojan ;;
        hysteria) printf '%s %s\n' /opt/etc/init.d/S57hysteria hysteria ;;
        *) return 1 ;;
    esac
}

tunnel_listener_port() {
    case "$1" in
        xray) printf '%s\n' "$PORT_VLESS" ;;
        trojan) printf '%s\n' "$PORT_TROJAN" ;;
        hysteria) printf '%s\n' "$PORT_HYSTERIA" ;;
        *) return 1 ;;
    esac
}

tunnel_listener_ready() {
    _tlr_port="$(tunnel_listener_port "$1" 2>/dev/null || true)"
    case "$_tlr_port" in ''|*[!0-9]*) return 1 ;; esac
    # /proc/net/* prints hexadecimal ports in uppercase on BusyBox/Linux.
    _tlr_hex="$(printf '%04X' "$_tlr_port")"
    # /proc/net/tcp state 0A is LISTEN. Hysteria may expose UDP only, so
    # accept an exact local UDP bind for that protocol as well.
    if awk -v p=":$_tlr_hex" 'index($2,p) == length($2)-length(p)+1 && $4 == "0A" {ok=1} END {exit !ok}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        return 0
    fi
    [ "$1" = "hysteria" ] || return 1
    awk -v p=":$_tlr_hex" 'index($2,p) == length($2)-length(p)+1 {ok=1} END {exit !ok}' \
        /proc/net/udp /proc/net/udp6 2>/dev/null
}

tunnel_protocol_active() {
    _tpa_proto="$1"
    set -- $(tunnel_protocol_init "$_tpa_proto") || return 1
    _tpa_init="$1"
    _tpa_proc="$2"
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_tpa_init" 2>/dev/null && return 1
    pidof "$_tpa_proc" >/dev/null 2>&1 || return 1
    tunnel_listener_ready "$_tpa_proto"
}


is_domain_core() {
    printf '%s\n' "$1" | awk '
        {
            s = tolower($0)
            if (s == "" || length(s) > 253) { bad = 1; exit }
            if (index(s, "/") > 0 || index(s, " ") > 0) { bad = 1; exit }
            if (index(s, "..") > 0) { bad = 1; exit }
            n = split(s, a, ".")
            if (n < 2) { bad = 1; exit }

            for (i = 1; i <= n; i++) {
                lbl = a[i]
                L = length(lbl)
                if (L == 0 || L > 63) { bad = 1; exit }
                if (substr(lbl, 1, 1) == "-" || substr(lbl, L, 1) == "-") { bad = 1; exit }
                for (j = 1; j <= L; j++) {
                    ch = substr(lbl, j, 1)
                    if (index("abcdefghijklmnopqrstuvwxyz0123456789-", ch) == 0) { bad = 1; exit }
                }
            }
            # TLD не может быть полностью числовым (иначе это битый IP).
            if (a[n] ~ /^[0-9]+$/) { bad = 1; exit }
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

# Возвращает upstream-ы из resource-specific server=/zone/... правил
# основного dnsmasq.conf в порядке их появления. Это важно для .onion,
# OpenNIC и других зон, для которых общий local DNS-порт не является
# правильным resolver-ом. Формат результата: LOCAL#port или host#port.
dnsmasq_resource_servers() {
    _drs_host="$1"
    [ -f "$DNSMASQ_CONF" ] || return 1
    awk -v h="$_drs_host" '
        function covered(d) {
            d = tolower(d)
            return h == d || h ~ ("\\." d "$")
        }
        /^[[:space:]]*server=\/[^#]/ {
            line = $0
            sub(/^[[:space:]]*server=\//, "", line)
            n = split(line, fields, "/")
            if (n < 2) next
            matched = 0
            for (i = 1; i < n; i++) {
                if (fields[i] != "" && covered(fields[i])) {
                    matched = 1
                    break
                }
            }
            if (matched && fields[n] != "") print fields[n]
        }
    ' "$DNSMASQ_CONF" 2>/dev/null \
        | awk '
            /^::1#[0-9][0-9]*$/ { next }
            /^127\.0\.0\.1#[0-9][0-9]*$/ {
                sub(/^127\.0\.0\.1#/, "LOCAL#")
                print
                next
            }
            /^[^#]+$/ { print $0 "#53"; next }
            { print }
        '
}

# The canonical DNS owner writes the compact decision snapshot. This
# consumer does not probe, rewrite or rotate that file.

# The canonical DNS owner writes the tunnel choice into the bounded
# decision snapshot. This consumer validates that selected tunnel live; it
# must not re-select a protocol from process state or start a service here.
DNS_TUNNEL_REQUIRED=0

# Reuse the decision produced by unblock_dnsmasq during the same
# unblock_update transaction. The existing bounded health log acts as the
# short-lived snapshot, avoiding another persistent state file.
load_dns_snapshot() {
    # The stable facade remains valid while its internal active resolver
    # changes. Read the live controller, not yesterday's apply log.
    if [ -f /opt/etc/bot/utils.py ] && grep -q 'class DNSPolicyV4' /opt/etc/bot/utils.py; then
        _v4_snapshot="$(python3 /opt/etc/bot/utils.py --dns-shell)" || return 1
        eval "$_v4_snapshot"
        [ "$DNS_MODE" != DNS_UNAVAILABLE ] || return 1
        WORKING_DNS_PORTS="$DNS_WORKING_PORTS"
        return 0
    fi
    [ "${KEENZOO_USE_DNS_SNAPSHOT:-0}" = "1" ] || return 1
    [ -f "$DNS_HEALTH_LOG" ] || return 1
    _snp_line="$(grep 'decision=final ' "$DNS_HEALTH_LOG" 2>/dev/null | tail -1 || true)"
    [ -n "$_snp_line" ] || return 1
    _snp_epoch="$(printf '%s\n' "$_snp_line" | sed -n 's/.* epoch=\([0-9][0-9]*\) .*/\1/p')"
    case "$_snp_epoch" in ''|*[!0-9]*) return 1 ;; esac
    _snp_now="$(date +%s 2>/dev/null || echo 0)"
    [ $((_snp_now - _snp_epoch)) -ge 0 ] || return 1
    [ $((_snp_now - _snp_epoch)) -le "${KEENZOO_DNS_SNAPSHOT_MAX_AGE:-90000}" ] || return 1

    _snp_mode="$(printf '%s\n' "$_snp_line" | sed -n 's/.* mode=\([^ ]*\).*/\1/p')"
    _snp_level="$(printf '%s\n' "$_snp_line" | sed -n 's/.* level=\([^ ]*\).*/\1/p')"
    _snp_required="$(printf '%s\n' "$_snp_line" | sed -n 's/.* required=\([^ ]*\).*/\1/p')"
    _snp_verified="$(printf '%s\n' "$_snp_line" | sed -n 's/.* verified=\([^ ]*\).*/\1/p')"
    _snp_primary="$(printf '%s\n' "$_snp_line" | sed -n 's/.* primary=\([^ ]*\).*/\1/p')"
    _snp_rtt="$(printf '%s\n' "$_snp_line" | sed -n 's/.* primary_rtt=\([^ ]*\).*/\1/p')"
    _snp_ports="$(printf '%s\n' "$_snp_line" | sed -n 's/.* ports=\([^ ]*\).*/\1/p')"
    _snp_secure="$(printf '%s\n' "$_snp_line" | sed -n 's/.* secure=\([^ ]*\).*/\1/p')"
    _snp_insecure="$(printf '%s\n' "$_snp_line" | sed -n 's/.* insecure=\([^ ]*\).*/\1/p')"
    _snp_backups="$(printf '%s\n' "$_snp_line" | sed -n 's/.* backups=\([^ ]*\).*/\1/p')"
    _snp_ranking="$(printf '%s\n' "$_snp_line" | sed -n 's/.* ranking=\([^ ]*\).*/\1/p')"
    _snp_tunnel="$(printf '%s\n' "$_snp_line" | sed -n 's/.* tunnel=\([^ ]*\).*/\1/p')"
    # dnsmasq stores the transport mode (LOCAL_DNSSEC) separately from the
    # health level (DNSSEC_OK). Validate both fields instead of treating mode
    # and level as interchangeable.
    case "$_snp_mode:$_snp_level:$_snp_required:$_snp_verified" in
        LOCAL_DNSSEC:DNSSEC_OK:0:0|DNS_OK_NO_DNSSEC:DNS_OK_NO_DNSSEC:0:0|TUNNEL_DNS:TUNNEL_DNS:1:1) ;;
        *) return 1 ;;
    esac
    if [ "$_snp_required" -eq 0 ]; then
        [ "$_snp_tunnel" = "none" ] || return 1
    fi
    if [ "$_snp_required" -eq 1 ]; then
        # The snapshot may legitimately select Trojan/Hysteria when a
        # higher-priority Xray process is alive but its listener or endpoint
        # failed. Validate the selected protocol itself; do not compare it to
        # a fresh priority scan and accidentally reject the canonical choice.
        case "$_snp_tunnel" in
            xray|trojan|hysteria) ;;
            *) return 1 ;;
        esac
        tunnel_protocol_active "$_snp_tunnel" || return 1
        DNS_TUNNEL_REQUIRED=1
    else
        DNS_TUNNEL_REQUIRED=0
    fi
    [ -n "$_snp_ports" ] && [ "$_snp_ports" != "none" ] || return 1
    valid_dns_port() {
        case "$1" in ''|*[!0-9]*) return 1 ;; esac
        [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
    }
    valid_dns_port "$_snp_primary" || return 1
    case "$_snp_rtt" in ''|none|*[!0-9]*) [ "$_snp_rtt" = "none" ] || return 1 ;; esac
    for _snp_port in $(printf '%s' "$_snp_ports" | tr ',' ' '); do
        valid_dns_port "$_snp_port" || return 1
    done
    for _snp_class_ports in "$_snp_secure" "$_snp_insecure"; do
        for _snp_port in $(printf '%s' "$_snp_class_ports" | tr ',' ' ' | sed 's/none//g'); do
            valid_dns_port "$_snp_port" || return 1
        done
    done
    _snp_ports_spaced="$(printf '%s' "$_snp_ports" | tr ',' ' ')"
    for _snp_class_ports in "$_snp_secure" "$_snp_insecure"; do
        for _snp_port in $(printf '%s' "$_snp_class_ports" | tr ',' ' ' | sed 's/none//g'); do
            case " $_snp_ports_spaced " in
                *" $_snp_port "*) ;;
                *) return 1 ;;
            esac
        done
    done
    case " $_snp_ports_spaced " in
        *" $_snp_primary "*) ;;
        *) return 1 ;;
    esac
    for _snp_port in $(printf '%s' "$_snp_backups" | tr ',' ' ' | sed 's/none//g'); do
        valid_dns_port "$_snp_port" || return 1
    done

    DNS_WORKING_PORTS="$(printf '%s' "$_snp_ports" | tr ',' ' ')"
    WORKING_DNS_PORTS="$DNS_WORKING_PORTS"
    DNS_SECURE_PORTS="$(printf '%s' "$_snp_secure" | tr ',' ' ' | sed 's/none//g')"
    DNS_INSECURE_PORTS="$(printf '%s' "$_snp_insecure" | tr ',' ' ' | sed 's/none//g')"
    # Older snapshots did not carry the per-port classes. Preserve their
    # bounded migration semantics while preferring the owner's explicit lists.
    if [ -z "$DNS_SECURE_PORTS" ] && [ -z "$DNS_INSECURE_PORTS" ]; then
        case "$_snp_mode" in
            LOCAL_DNSSEC|TUNNEL_DNS) DNS_SECURE_PORTS="$DNS_WORKING_PORTS" ;;
            DNS_OK_NO_DNSSEC) DNS_INSECURE_PORTS="$DNS_WORKING_PORTS" ;;
        esac
    fi
    DNS_TUNNEL_READY="$_snp_verified"
    DNS_TUNNEL_PROTOCOL=""
    [ "$_snp_tunnel" = "none" ] || DNS_TUNNEL_PROTOCOL="$_snp_tunnel"
    DNS_PRIMARY="$_snp_primary"
    DNS_PRIMARY_RTT_MS="$_snp_rtt"
    DNS_BACKUP_PORTS="$(printf '%s' "$_snp_backups" | tr ',' ' ' | sed 's/none//g')"
    DNS_RANKING="$_snp_ranking"
    DNS_HEALTH_MODE="$_snp_mode"
    WORKING_PORT_COUNT="$(printf '%s\n' "$DNS_WORKING_PORTS" | wc -w | awk '{print $1}')"
    logger -t "unblock_ipset" \
        "DNS snapshot reused epoch=$_snp_epoch mode=$_snp_mode level=$_snp_level required=$_snp_required verified=$_snp_verified primary=$_snp_primary ports=$DNS_WORKING_PORTS tunnel=${DNS_TUNNEL_PROTOCOL:-none}"
    return 0
}

select_working_ports() {
    if ! load_dns_snapshot; then
        logger -t "unblock_ipset" \
            "DNS snapshot missing, stale or invalid; refusing independent DNS decision"
        return 1
    fi
    WORKING_DNS_PORTS="$DNS_WORKING_PORTS"
    WORKING_PORT_COUNT="$(printf '%s\n' "$WORKING_DNS_PORTS" \
        | wc -w | awk '{print $1}')"
    [ "${WORKING_PORT_COUNT:-0}" -gt 0 ]
}

if ! select_working_ports; then
    echo "DNS snapshot unavailable; run unblock_update.sh" >&2
    exit 1
fi

logger -t "unblock_ipset" \
    "DNS snapshot consumed: ports=$WORKING_DNS_PORTS primary=${DNS_PRIMARY:-none} \
health=${DNS_HEALTH_MODE:-unknown} tunnel=${DNS_TUNNEL_PROTOCOL:-none}"

emit_public_dns_answers() {
    _epa_result="$1"
    printf '%s\n' "$_epa_result" | while IFS= read -r _epa_candidate; do
        [ -n "$_epa_candidate" ] || continue
        is_public_ipv4 "$_epa_candidate" && printf '%s\n' "$_epa_candidate"
    done
}

resilient_dig() {
    _rd_domain="$1"
    _rd_tried=""

    if [ "$DNS_TUNNEL_REQUIRED" -eq 1 ] && [ "$DNS_TUNNEL_READY" -ne 1 ]; then
        logger -t "unblock_ipset" \
            "DNS resolve: $_rd_domain source=FAIL_CLOSED reason=tunnel-client-plane-unavailable"
        return 1
    fi

    # First preserve explicit resource-specific server=/zone/... rules in
    # dnsmasq.conf and their configured order. External resource resolvers are
    # never used while a tunnel is required; that would bypass the tunnel.
    for _rd_resource in $(dnsmasq_resource_servers "$_rd_domain" || true); do
        case "$_rd_resource" in
            LOCAL#[0-9]*)
                _rd_resource_port="${_rd_resource#LOCAL#}"
                _rd_result="$(dig +short +timeout=3 +tries=1 \
                    "$_rd_domain" @localhost -p "$_rd_resource_port" 2>/dev/null || true)"
                ;;
            *#[0-9]*)
                # An explicit external server=/zone/ upstream is a direct DNS
                # path. While a tunnel is required it must not bypass the
                # tunnel; the common local system DoH/DoT path is used below.
                [ "$DNS_TUNNEL_REQUIRED" -eq 0 ] || continue
                _rd_resource_host="${_rd_resource%#*}"
                _rd_resource_port="${_rd_resource#*#}"
                _rd_result="$(dig +short +timeout=3 +tries=1 \
                    "$_rd_domain" "@$_rd_resource_host" -p "$_rd_resource_port" 2>/dev/null || true)"
                ;;
            *)
                _rd_result=""
                ;;
        esac
        if [ -n "$_rd_result" ]; then
            _rd_public="$(emit_public_dns_answers "$_rd_result")"
            if [ -n "$_rd_public" ]; then
                logger -t "unblock_ipset" \
                    "DNS resolve: $_rd_domain source=DNSMASQ_RESOURCE upstream=$_rd_resource"
                printf '%s\n' "$_rd_public"
                return 0
            fi
        fi
    done

    # The canonical dnsmasq owner has already selected the healthy path and
    # rendered its managed upstream block. This consumer only queries the
    # snapshot-approved transports; it never performs another DNS decision.
    for _rd_port in $DNS_SECURE_PORTS $DNS_INSECURE_PORTS; do
        [ -n "$_rd_port" ] || continue
        printf ' %s ' "$_rd_tried" | grep -q " $_rd_port " && continue
        _rd_tried="${_rd_tried}${_rd_tried:+ }${_rd_port}"
        _rd_result="$(dig +short +timeout=3 +tries=1 \
            "$_rd_domain" @localhost -p "$_rd_port" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            _rd_public="$(emit_public_dns_answers "$_rd_result")"
            if [ -n "$_rd_public" ]; then
                [ -n "$DNS_INSECURE_PORTS" ] && [ -z "$DNS_SECURE_PORTS" ] && \
                    logger -t "unblock_ipset" \
                        "DNS resolve: $_rd_domain source=DNS_OK_NO_DNSSEC"
                printf '%s\n' "$_rd_public"
                return 0
            fi
        fi
    done

    logger -t "unblock_ipset" \
        "DNS resolve: $_rd_domain source=DNSMASQ_SNAPSHOT exhausted ports=$DNS_WORKING_PORTS"
    return 1
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

    ipset create "$_pl_setname_real" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || return 1

    _pl_jobs=0
    _pl_idx=0

    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line="$(trim_comment "$raw_line")"
        [ -n "$line" ] || continue

        if is_cidr "$line"; then
            if is_public_cidr "$line"; then
                printf 'add %s %s\n' "$_pl_setname_real" "$line" >> "$_pl_batch"
            else
                logger -t "unblock_ipset" "skip non-public network: $line"
            fi
            continue
        fi

        if is_range "$line"; then
            if is_public_range "$line"; then
                printf 'add %s %s\n' "$_pl_setname_real" "$line" >> "$_pl_batch"
            else
                logger -t "unblock_ipset" "skip non-public range: $line"
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

        (
            resilient_dig "$_domain_target" \
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
    } | LC_ALL=C sort -u > "${_pl_restore}.unsorted"

    # Структурирование по возрастанию: сначала числовой порядок по октетам
    # (IP и CIDR), затем домены по алфавиту. Отсортированный restore-файл
    # ускоряет ipset restore и делает вывод предсказуемым.
    awk -F' ' '{
        n = split($3, o, ".")
        if (n >= 4) {
            split(o[4], last, "/")
            printf "0%03d%03d%03d%03d\t%s\n", o[1], o[2], o[3], last[1], $0
        } else {
            printf "1%s\t%s\n", $3, $0
        }
    }' "${_pl_restore}.unsorted" \
        | LC_ALL=C sort \
        | cut -f2- > "$_pl_restore"
    rm -f "${_pl_restore}.unsorted"

    # Подсчёт доменов, которые не удалось разрезолвить.
    _pl_resolved=0
    if [ -d "$_pl_resdir" ]; then
        for _pl_rf in "$_pl_resdir"/*; do
            [ -f "$_pl_rf" ] || continue
            [ -s "$_pl_rf" ] && _pl_resolved=$((_pl_resolved + 1))
        done
    fi

    # Защита от подмены рабочего набора пустым при отказе DNS: если в списке
    # были домены, но разрезолвить удалось меньше MIN_RESOLVE_RATIO процентов,
    # набор считается недостоверным и не применяется.
    if [ "$_pl_idx" -gt 0 ]; then
        _pl_ratio=$(( _pl_resolved * 100 / _pl_idx ))
        if [ "$_pl_ratio" -lt "$MIN_RESOLVE_RATIO" ]; then
            logger -t "unblock_ipset" \
                "DNS degraded for $_pl_setname_real: $_pl_resolved/$_pl_idx (${_pl_ratio}%), set not replaced"
            rm -rf "$_pl_work"
            return 1
        fi
    fi

    if [ -s "$_pl_restore" ]; then
        if ! ipset restore -exist < "$_pl_restore" 2>"${TMP_BASE}/restore.err"; then
            logger -t "unblock_ipset" "ipset restore failed for $_pl_setname_real"
            cat "${TMP_BASE}/restore.err" >&2 || true
            rm -rf "$_pl_work"
            return 1
        fi
    fi

    logger -t "unblock_ipset" \
        "$_pl_setname_real: domains=$_pl_idx resolved=$_pl_resolved"

    rm -rf "$_pl_work"
    return 0
}

FAILED=""

run_list() {
    _rl_file="$1"
    _rl_set="$2"
    # Фильтр ONLY_SETS: пропускаем наборы, которые не запрашивали.
    # ВАЖНО: пропуск — это именно «не трогать». Набор остаётся как был,
    # его нельзя ни чистить, ни пересоздавать, иначе частичное
    # обновление обнулило бы соседние протоколы.
    set_selected "$_rl_set" || return 0
    if ! process_list "$_rl_file" "$_rl_set"; then
        FAILED="${FAILED}${FAILED:+ }${_rl_set}"
    fi
}

# Протокол выключен ползунком веб-панели, если в его init-скрипте
# стоит ENABLED=no. Резолвить домены такого протокола не нужно:
# правила перехвата для него уже сняты в 100-redirect.sh, а сотни
# лишних DNS-запросов замедляют обработку остальных списков на
# слабом CPU роутера.
svc_enabled() {
    _init="$1"
    [ -f "$_init" ] || return 0
    if grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_init" 2>/dev/null
    then
        return 1
    fi
    return 0
}

# Набор выключенного протокола очищается: устаревшие адреса в нём
# бесполезны, а при обратном включении он наполнится заново.
run_list_if_enabled() {
    _ie_init="$1"
    _ie_file="$2"
    _ie_set="$3"

    # Проверка ДО ветвления: при частичном обновлении чужой набор
    # нельзя ни наполнять, ни очищать.
    set_selected "$_ie_set" || return 0

    if svc_enabled "$_ie_init"; then
        run_list "$_ie_file" "$_ie_set"
    else
        ipset flush "${_ie_set}${IPSET_SUFFIX}" 2>/dev/null || true
        logger -t "unblock_ipset" \
            "skip $_ie_set: протокол отключён"
    fi
}

# ONLY_SETS — обработать лишь указанные наборы вместо всех.
# Правка одной записи в панели запускала полный цикл по всем 319
# доменам: сотни DNS-запросов и десятки секунд ради одного адреса.
# Значение — список имён через пробел, например ONLY_SETS="unblockvless".
# Пусто (по умолчанию) — поведение прежнее, обрабатываются все списки.
ONLY_SETS="${ONLY_SETS:-}"

set_selected() {
    [ -n "$ONLY_SETS" ] || return 0   # фильтр не задан — берём всё
    for _ss_want in $ONLY_SETS; do
        [ "$_ss_want" = "$1" ] && return 0
    done
    return 1
}

run_list_if_enabled /opt/etc/init.d/S65shadowsocks \
    /opt/etc/unblock/shadowsocks.txt  unblocksh
run_list_if_enabled /opt/etc/init.d/S35tor \
    /opt/etc/unblock/tor.txt          unblocktor
run_list_if_enabled /opt/etc/init.d/S24xray \
    /opt/etc/unblock/vless.txt        unblockvless
run_list_if_enabled /opt/etc/init.d/S22trojan \
    /opt/etc/unblock/trojan.txt       unblocktroj
run_list_if_enabled /opt/etc/init.d/S57hysteria \
    /opt/etc/unblock/hysteria.txt     unblockhysteria

# bot.txt — трафик самого роутера, идёт через xray/VLESS.
run_list_if_enabled /opt/etc/init.d/S24xray \
    /opt/etc/unblock/bot.txt          unblockrouter

# VPN-списки необязательны для общего commit. Сначала вызывающий скрипт
# применяет шесть статических наборов, а затем каждый VPN-набор отдельно.
# Поэтому ошибка одного отсоединённого/битого VPN не может отменить bot/vless.
if [ "${SKIP_VPN:-0}" != "1" ]; then
    for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
        [ -f "$vpn_file_names" ] || continue
        vpn_file_name="$(basename "$vpn_file_names" .txt)"
        unblockvpn="unblock${vpn_file_name}"
        ipset create "${unblockvpn}${IPSET_SUFFIX}" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
        run_list "$vpn_file_names" "$unblockvpn"
    done
fi

if [ -n "$FAILED" ]; then
    if [ "${OPTIONAL_VPN:-0}" = "1" ]; then
        logger -t "unblock_ipset" "optional VPN list failed: $FAILED"
        echo "optional VPN list failed: $FAILED" >&2
    else
        logger -t "unblock_ipset" "process_list failed: $FAILED"
        echo "process_list failed: $FAILED" >&2
    fi
    exit 1
fi

exit 0
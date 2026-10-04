#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# Глобальный лимит одновременных dig. Списков шесть и более, поэтому без
# общего ограничения на роутере могло подниматься до нескольких десятков
# процессов dig одновременно (перегрузка dnsmasq и нехватка памяти).
MAX_PARALLEL="${MAX_PARALLEL:-4}"
MIN_RESOLVE_RATIO="${MIN_RESOLVE_RATIO:-50}"
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
# torproject.org здесь не используется: его блокировка в России не
# должна превращаться в ложный отказ локального DNS.
DNS_HEALTH_DOMAIN="${DNS_HEALTH_DOMAIN:-example.com}"
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-/opt/var/log/unblock_dns_health.log}"
DNS_HEALTH_LOG_MAX="${DNS_HEALTH_LOG_MAX:-131072}"
DNS_HEALTH_LOG_KEEP="${DNS_HEALTH_LOG_KEEP:-200}"
DNS_METRICS_FILE="$TMP_BASE/dns.metrics"

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
            if (o1 == 192 && o2 == 0) { bad = 1; exit }
            if (o1 == 198 && (o2 == 18 || o2 == 19)) { bad = 1; exit }
            if (o1 >= 224) { bad = 1; exit }
        }
        END { exit (bad ? 1 : 0) }
    '
}

DNSMASQ_CONF="${DNSMASQ_CONF:-/opt/etc/dnsmasq.conf}"
DNS_TUNNEL_SET="unblockdns"
# Проверяем DNS REDIRECT тем же бинарником, который умеет match-set.
# Это не обязательно /opt/sbin/iptables: Entware может поставлять
# вариант без расширения set, а NDM-hook выбирает прошивочный бинарник.
IPTABLES_DNS_BIN="${IPTABLES_DNS_BIN:-}"
if [ -z "$IPTABLES_DNS_BIN" ]; then
    for _idc in /usr/sbin/iptables /sbin/iptables /bin/iptables \
        /usr/bin/iptables /usr/local/sbin/iptables \
        /tmp/sbin/iptables /tmp/usr/sbin/iptables \
        /opt/sbin/iptables /opt/bin/iptables; do
        [ -x "$_idc" ] || continue
        _idc_help="$("$_idc" -m set --help 2>&1 || true)"
        if printf '%s' "$_idc_help" | grep -q -- '--match-set'; then
            IPTABLES_DNS_BIN="$_idc"
            break
        fi
    done
fi
if [ -z "$IPTABLES_DNS_BIN" ]; then
    IPTABLES_DNS_BIN="$(command -v iptables 2>/dev/null || true)"
fi
DNS_ENDPOINT_HOSTS="${DNS_ENDPOINT_HOSTS:-${TUNNEL_DOH_HOSTS:-dns.google cloudflare-dns.com dns11.quad9.net opennic1.eth-services.de opennic2.eth-services.de}}"
TUNNEL_DOH_HOSTS="$DNS_ENDPOINT_HOSTS"
HOSTS_FILE="${HOSTS_FILE:-/opt/etc/hosts}"
NDM_PIN_BEGIN="# --- KeenZOO NDM bootstrap (управляется проектом) ---"
NDM_PIN_END="# --- end KeenZOO NDM bootstrap ---"
DNS_TUNNEL_PROTOCOL="${DNS_TUNNEL_PROTOCOL:-}"
BOOTSTRAP_RESOLVERS="${BOOTSTRAP_RESOLVERS:-9.9.9.9 8.8.8.8 1.1.1.1}"

ndm_pinned_lookup() {
    _nplh="$1"
    [ -f "$HOSTS_FILE" ] || return 1
    awk -v b="$NDM_PIN_BEGIN" -v e="$NDM_PIN_END" -v h="$_nplh" '
        $0 == b { inside=1; next }
        $0 == e { inside=0; next }
        inside && $2 == h && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 }
    ' "$HOSTS_FILE" 2>/dev/null
}

tunnel_protocol_init() {
    case "$1" in
        xray) printf '%s %s\n' /opt/etc/init.d/S24xray xray ;;
        trojan) printf '%s %s\n' /opt/etc/init.d/S22trojan trojan ;;
        hysteria) printf '%s %s\n' /opt/etc/init.d/S57hysteria hysteria ;;
        *) return 1 ;;
    esac
}

tunnel_protocol_active() {
    _tpa_proto="$1"
    case "${DNS_TUNNEL_PROTOCOL:-}" in
        "$_tpa_proto") return 0 ;;
    esac
    set -- $(tunnel_protocol_init "$_tpa_proto") || return 1
    _tpa_init="$1"
    _tpa_proc="$2"
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_tpa_init" 2>/dev/null && return 1
    pidof "$_tpa_proc" >/dev/null 2>&1
}

active_tunnel_protocol() {
    for _atp in xray trojan hysteria; do
        tunnel_protocol_active "$_atp" || continue
        printf '%s\n' "$_atp"
        return 0
    done
    return 1
}

start_tunnel_protocol() {
    _stp_proto="$1"
    set -- $(tunnel_protocol_init "$_stp_proto") || return 1
    _stp_init="$1"
    _stp_proc="$2"
    [ -x "$_stp_init" ] || return 1
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_stp_init" 2>/dev/null && return 1
    "$_stp_init" start >/dev/null 2>&1 || true
    sleep 1
    tunnel_protocol_active "$_stp_proto"
}

# При отказе локального DNS пытаемся поднять tunnel service с помощью
# старого pin из /opt/etc/hosts. Проверка и запуск идут строго в порядке
# Xray/VLESS -> Trojan -> Hysteria.
ensure_active_tunnel_protocol() {
    _eatp="$(active_tunnel_protocol || true)"
    [ -n "$_eatp" ] && { printf '%s\n' "$_eatp"; return 0; }
    for _eatp in xray trojan hysteria; do
        start_tunnel_protocol "$_eatp" || continue
        printf '%s\n' "$_eatp"
        return 0
    done
    return 1
}
tunnel_dns_prepare() {
    _tdp_proto="$1"
    _tdp_ips=""
    ipset create "$DNS_TUNNEL_SET" hash:net family inet \
        hashsize 64 maxelem 64 -exist 2>/dev/null || return 1
    ipset flush "$DNS_TUNNEL_SET" 2>/dev/null || true
    for _tdp_host in $DNS_ENDPOINT_HOSTS; do
        for _tdp_ip in $(ndm_pinned_lookup "$_tdp_host" || true); do
            is_public_ipv4 "$_tdp_ip" || continue
            ipset add "$DNS_TUNNEL_SET" "$_tdp_ip" -exist 2>/dev/null || true
            _tdp_ips="${_tdp_ips}${_tdp_ips:+ }$_tdp_ip"
        done
    done
    [ -n "$_tdp_ips" ] || return 1
    if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        DNS_TUNNEL_PROTOCOL="$_tdp_proto" type=iptable table=nat \
            /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    fi
    _tdp_port=10810
    case "$_tdp_proto" in
        trojan) _tdp_port=10829 ;;
        hysteria) _tdp_port=10830 ;;
    esac
    [ -n "$IPTABLES_DNS_BIN" ] || return 1
    _tdp_rule_ok=0
    for _tdp_remote_port in 443 853; do
        if "$IPTABLES_DNS_BIN" -w -t nat -C OUTPUT -p tcp \
            --dport "$_tdp_remote_port" \
            -m set --match-set "$DNS_TUNNEL_SET" dst \
            -j REDIRECT --to-port "$_tdp_port" >/dev/null 2>&1; then
            _tdp_rule_ok=1
        fi
    done
    [ "$_tdp_rule_ok" -eq 1 ]
}

prepare_tunnel_dns() {
    _ptd_seen=""
    _ptd_order="${DNS_TUNNEL_PROTOCOL:-} xray trojan hysteria"
    for _ptd_proto in $_ptd_order; do
        [ -n "$_ptd_proto" ] || continue
        case " $_ptd_seen " in *" $_ptd_proto "*) continue ;; esac
        _ptd_seen="${_ptd_seen}${_ptd_seen:+ }$_ptd_proto"
        tunnel_protocol_active "$_ptd_proto" || \
            start_tunnel_protocol "$_ptd_proto" || continue
        tunnel_dns_prepare "$_ptd_proto" || continue
        DNS_TUNNEL_PROTOCOL="$_ptd_proto"
        return 0
    done
    return 1
}

tunnel_dns_lookup() {
    _tdl_name="$1"
    _tdl_seen=""
    _tdl_order="${DNS_TUNNEL_PROTOCOL:-} xray trojan hysteria"
    for _tdl_proto in $_tdl_order; do
        [ -n "$_tdl_proto" ] || continue
        case " $_tdl_seen " in *" $_tdl_proto "*) continue ;; esac
        _tdl_seen="${_tdl_seen}${_tdl_seen:+ }$_tdl_proto"
        tunnel_protocol_active "$_tdl_proto" || \
            start_tunnel_protocol "$_tdl_proto" || continue
        tunnel_dns_prepare "$_tdl_proto" || continue

        for _tdl_host in $DNS_ENDPOINT_HOSTS; do
            case "$_tdl_host" in
                dns.google) _tdl_path="/resolve?name=$_tdl_name&type=A&cd=0" ;;
                *) _tdl_path="/dns-query?name=$_tdl_name&type=A&do=1" ;;
            esac
            for _tdl_ip in $(ndm_pinned_lookup "$_tdl_host" || true); do
                is_public_ipv4 "$_tdl_ip" || continue
                _tdl_json="$(curl -sS --noproxy '*' \
                    --connect-timeout 4 --max-time 8 \
                    --resolve "${_tdl_host}:443:${_tdl_ip}" \
                    -H 'accept: application/dns-json' \
                    "https://${_tdl_host}${_tdl_path}" 2>/dev/null || true)"
                [ -n "$_tdl_json" ] || continue
                case "$_tdl_json" in
                    *'"AD":true'*|*'"AD": true'*) ;;
                    *) continue ;;
                esac
                _tdl_answers="$(printf '%s\n' "$_tdl_json" \
                    | sed -n 's/.*"data"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' \
                    | while IFS= read -r _tdl_answer; do
                        is_public_ipv4 "$_tdl_answer" && printf '%s\n' "$_tdl_answer"
                      done)"
                if [ -n "$_tdl_answers" ]; then
                    logger -t "unblock_ipset" \
                        "DNS tunnel: protocol=$_tdl_proto endpoint=$_tdl_host level=TUNNEL_DNS"
                    printf '%s\n' "$_tdl_answers"
                    return 0
                fi
            done
        done
    done
    return 1
}

provider_resolver_list() {
    sed -n 's/^[[:space:]]*nameserver[[:space:]]\{1,\}\([0-9.]\{7,\}\).*/\1/p' \
        /tmp/resolv.conf 2>/dev/null | grep -v '^127\.' | head -2
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

# Результат:
#   0 — NOERROR + A + DNSSEC AD, без AA;
#   2 — DNS-ответ есть, но AD отсутствует;
#   1 — ошибка DNS или подозрительный авторитетный ответ.
dns_health_probe() {
    _dhp_port="$1"
    DNS_LAST_RTT_MS=999999
    DNS_LAST_REASON=""
    DNS_LAST_STATUS=""
    DNS_LAST_FLAGS=""
    _dhp_out="$(dig +dnssec +noall +comments +answer +stats \
        +time=2 +tries=1 "$DNS_HEALTH_DOMAIN" \
        @localhost -p "$_dhp_port" 2>/dev/null || true)"
    _dhp_status="$(printf '%s\n' "$_dhp_out" \
        | sed -n 's/.*status:[[:space:]]*\([^,;]*\).*/\1/p' \
        | head -1)"
    _dhp_flags="$(printf '%s\n' "$_dhp_out" \
        | sed -n 's/.*flags:[[:space:]]*\([^;]*\).*/\1/p' \
        | head -1)"
    _dhp_rtt="$(printf '%s\n' "$_dhp_out" \
        | sed -n 's/.*Query time:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*msec.*/\1/p' \
        | head -1)"
    DNS_LAST_STATUS="${_dhp_status:-EMPTY}"
    DNS_LAST_FLAGS="${_dhp_flags:-none}"
    if [ "$_dhp_status" != "NOERROR" ]; then
        DNS_LAST_REASON="status=${_dhp_status:-EMPTY}"
        return 1
    fi
    case "$_dhp_rtt" in
        ''|*[!0-9]*)
            DNS_LAST_REASON="no_rtt"
            return 1
            ;;
        *) DNS_LAST_RTT_MS="$_dhp_rtt" ;;
    esac
    if ! printf '%s\n' "$_dhp_out" | awk '
        $1 !~ /^;/ && $4 == "A" && $5 ~ /^[0-9]+\.[0-9]+\./ { ok=1 }
        END { exit (ok ? 0 : 1) }
    '; then
        DNS_LAST_REASON="no_a"
        return 1
    fi
    case " $_dhp_flags " in
        *" aa "*)
            DNS_LAST_REASON="authoritative"
            return 1
            ;;
    esac
    case " $_dhp_flags " in
        *" ad "*)
            DNS_LAST_REASON="validated"
            return 0
            ;;
    esac
    DNS_LAST_REASON="no_ad"
    # AD обязателен для DNSSEC_OK. Ответ без AD может быть использован
    # только как DNS_OK_NO_DNSSEC либо внутри уже работающего tunnel.
    return 2
}

# Same portable ranking as unblock_dnsmasq.sh. Do not rely on the router's
# BusyBox sort implementation for numeric field ordering.
rank_dns_metrics() {
    _rdm_src="$1"
    _rdm_dst="$2"
    _rdm_remaining="${_rdm_dst}.remaining.$$"
    _rdm_next="${_rdm_dst}.next.$$"
    : > "$_rdm_dst"
    cp "$_rdm_src" "$_rdm_remaining" 2>/dev/null || return 1
    while [ -s "$_rdm_remaining" ]; do
        _rdm_best="$(awk -F'|' '
            ($2 == "secure" || $2 == "insecure") && $3 ~ /^[0-9]+$/ {
                cls = ($2 == "secure" ? 0 : 1)
                rtt = $3 + 0
                port = $1 + 0
                if (!found || cls < best_cls ||
                    (cls == best_cls && (rtt < best_rtt ||
                    (rtt == best_rtt && port < best_port)))) {
                    found = 1
                    best_cls = cls
                    best_rtt = rtt
                    best_port = port
                    best_line = $0
                }
            }
            END { if (found) print best_line }
        ' "$_rdm_remaining")"
        [ -n "$_rdm_best" ] || break
        printf '%s\n' "$_rdm_best" >> "$_rdm_dst"
        _rdm_port="${_rdm_best%%|*}"
        awk -F'|' -v p="$_rdm_port" '$1 != p' \
            "$_rdm_remaining" > "$_rdm_next"
        mv -f "$_rdm_next" "$_rdm_remaining"
    done
    rm -f "$_rdm_remaining" "$_rdm_next"
}

set_dns_working_order() {
    DNS_WORKING_PORTS="$1"
    DNS_PRIMARY=""
    DNS_BACKUP_PORTS=""
    for _dwp in $DNS_WORKING_PORTS; do
        if [ -z "$DNS_PRIMARY" ]; then
            DNS_PRIMARY="$_dwp"
        else
            DNS_BACKUP_PORTS="${DNS_BACKUP_PORTS}${DNS_BACKUP_PORTS:+ }$_dwp"
        fi
    done
    DNS_PRIMARY_RTT_MS=""
    if [ -n "$DNS_PRIMARY" ] && [ -f "${DNS_METRICS_FILE}.ranked" ]; then
        DNS_PRIMARY_RTT_MS="$(awk -F'|' -v p="$DNS_PRIMARY" \
            '$1 == p { print $3; exit }' "${DNS_METRICS_FILE}.ranked")"
    fi
}

collect_working_ports() {
    : > "$DNS_METRICS_FILE"
    for _faw_port in $DNS_PORTS_DOT; do
        if dns_health_probe "$_faw_port"; then _faw_rc=0; else _faw_rc=$?; fi
        case "$_faw_rc" in
            0) printf '%s|secure|%s|dot\n' "$_faw_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE" ;;
            2) printf '%s|insecure|%s|dot\n' "$_faw_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE" ;;
        esac
    done
    for _faw_port in $DNS_PORTS_DOH; do
        if dns_health_probe "$_faw_port"; then _faw_rc=0; else _faw_rc=$?; fi
        case "$_faw_rc" in
            0) printf '%s|secure|%s|doh\n' "$_faw_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE" ;;
            2) printf '%s|insecure|%s|doh\n' "$_faw_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE" ;;
        esac
    done
    _faw_ranked="${DNS_METRICS_FILE}.ranked"
    rank_dns_metrics "$DNS_METRICS_FILE" "$_faw_ranked"
    DNS_SECURE_PORTS="$(awk -F'|' '$2 == "secure" { print $1 }' "$_faw_ranked" \
        | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    DNS_INSECURE_PORTS="$(awk -F'|' '$2 == "insecure" { print $1 }' "$_faw_ranked" \
        | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    DNS_RANKING="$(awk -F'|' '{ printf "%s:%s,", $1, $3 }' "$_faw_ranked" \
        | sed 's/,$//')"
    if [ -n "$DNS_SECURE_PORTS" ]; then
        set_dns_working_order "$DNS_SECURE_PORTS"
    else
        set_dns_working_order "$DNS_INSECURE_PORTS"
    fi
    dns_health_file_log \
        "ranking=${DNS_RANKING:-none} primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} secure=${DNS_SECURE_PORTS:-none} insecure=${DNS_INSECURE_PORTS:-none}"
}

# Bounded compact log shared with unblock_dnsmasq.sh. rotate_logs.sh also
# rotates the same inode from cron every six hours.
dns_health_log_rotate() {
    [ -n "$DNS_HEALTH_LOG" ] || return 0
    mkdir -p "$(dirname "$DNS_HEALTH_LOG")" 2>/dev/null || return 0
    [ -f "$DNS_HEALTH_LOG" ] || return 0
    _dhl_size="$(wc -c < "$DNS_HEALTH_LOG" 2>/dev/null || echo 0)"
    _dhl_lines="$(wc -l < "$DNS_HEALTH_LOG" 2>/dev/null || echo 0)"
    case "$_dhl_size" in ''|*[!0-9]*) return 0 ;; esac
    case "$_dhl_lines" in ''|*[!0-9]*) return 0 ;; esac
    case "$DNS_HEALTH_LOG_MAX" in ''|*[!0-9]*) return 0 ;; esac
    case "$DNS_HEALTH_LOG_KEEP" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$_dhl_size" -gt "$DNS_HEALTH_LOG_MAX" ] || [ "$_dhl_lines" -gt "$DNS_HEALTH_LOG_KEEP" ]; then
        _dhl_tmp="${DNS_HEALTH_LOG}.tmp.$$"
        _dhl_bytes="${_dhl_tmp}.bytes"
        if tail -n "$DNS_HEALTH_LOG_KEEP" "$DNS_HEALTH_LOG" > "$_dhl_tmp" 2>/dev/null; then
            _dhl_tmp_size="$(wc -c < "$_dhl_tmp" 2>/dev/null || echo 0)"
            case "$_dhl_tmp_size" in
                ''|*[!0-9]*) ;;
                *)
                    if [ "$_dhl_tmp_size" -gt "$DNS_HEALTH_LOG_MAX" ]; then
                        tail -c "$DNS_HEALTH_LOG_MAX" "$_dhl_tmp" > "$_dhl_bytes" 2>/dev/null \
                            && mv -f "$_dhl_bytes" "$_dhl_tmp"
                    fi
                    cat "$_dhl_tmp" > "$DNS_HEALTH_LOG" 2>/dev/null || true
                    ;;
            esac
        fi
        rm -f "$_dhl_tmp" "$_dhl_bytes"
    fi
}

dns_health_file_log() {
    [ -n "$DNS_HEALTH_LOG" ] || return 0
    dns_health_log_rotate
    _dhl_now="$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date)"
    printf '%s unblock_ipset %s\n' "$_dhl_now" "$*" \
        >> "$DNS_HEALTH_LOG" 2>/dev/null || true
    dns_health_log_rotate
}

select_working_ports() {
    collect_working_ports
    DNS_INITIAL_INSECURE_PORTS="$DNS_INSECURE_PORTS"
    DNS_INITIAL_WORKING_PORTS="$DNS_WORKING_PORTS"
    DNS_INITIAL_PRIMARY="$DNS_PRIMARY"
    DNS_INITIAL_BACKUP_PORTS="$DNS_BACKUP_PORTS"
    DNS_INITIAL_PRIMARY_RTT_MS="$DNS_PRIMARY_RTT_MS"
    DNS_INITIAL_RANKING="$DNS_RANKING"
    DNS_TUNNEL_READY=0
    # Протокол выбирается по фактическому процессу и client-plane
    # проверке, а не по внешней переменной окружения.
    DNS_TUNNEL_PROTOCOL=""
    if [ -z "$DNS_SECURE_PORTS" ]; then
        _st_seen=""
        _st_order="${DNS_TUNNEL_PROTOCOL:-} xray trojan hysteria"
        for _st_proto in $_st_order; do
            [ -n "$_st_proto" ] || continue
            case " $_st_seen " in *" $_st_proto "*) continue ;; esac
            _st_seen="${_st_seen}${_st_seen:+ }$_st_proto"
            tunnel_protocol_active "$_st_proto" || start_tunnel_protocol "$_st_proto" || continue
            tunnel_dns_prepare "$_st_proto" || continue
            DNS_TUNNEL_PROTOCOL="$_st_proto"
            # Проверяем уже настоящий local client-plane path через
            # системные DoH/DoT listeners, а не только curl/процесс.
            collect_working_ports
            if [ -n "$DNS_WORKING_PORTS" ]; then
                DNS_TUNNEL_READY=1
                break
            fi
        done
    fi

    if [ -n "$DNS_SECURE_PORTS" ] && [ "$DNS_TUNNEL_READY" -eq 0 ]; then
        DNS_TUNNEL_PROTOCOL=""
        WORKING_DNS_PORTS="$DNS_WORKING_PORTS"
        DNS_HEALTH_MODE="DNSSEC_OK"
    elif [ "$DNS_TUNNEL_READY" -eq 1 ]; then
        WORKING_DNS_PORTS="$DNS_WORKING_PORTS"
        DNS_HEALTH_MODE="TUNNEL_DNS"
    elif [ -n "$DNS_INITIAL_INSECURE_PORTS" ]; then
        DNS_TUNNEL_PROTOCOL=""
        DNS_TUNNEL_READY=0
        DNS_SECURE_PORTS=""
        DNS_INSECURE_PORTS="$DNS_INITIAL_INSECURE_PORTS"
        DNS_WORKING_PORTS="$DNS_INITIAL_WORKING_PORTS"
        DNS_PRIMARY="$DNS_INITIAL_PRIMARY"
        DNS_BACKUP_PORTS="$DNS_INITIAL_BACKUP_PORTS"
        DNS_PRIMARY_RTT_MS="$DNS_INITIAL_PRIMARY_RTT_MS"
        DNS_RANKING="$DNS_INITIAL_RANKING"
        WORKING_DNS_PORTS="$DNS_INITIAL_INSECURE_PORTS"
        DNS_HEALTH_MODE="DNS_OK_NO_DNSSEC"
        # Restore the client-plane rule state after unsuccessful protocols.
        if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
            DNS_TUNNEL_DISABLE=1 type=iptable table=nat \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
        fi
    else
        DNS_TUNNEL_PROTOCOL=""
        WORKING_DNS_PORTS=""
        DNS_HEALTH_MODE="DNS_UNAVAILABLE"
        if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
            DNS_TUNNEL_DISABLE=1 type=iptable table=nat \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
        fi
    fi
}

COUNT=0
WORKING_DNS_PORTS=""
DNS_PRIMARY=""
DNS_BACKUP_PORTS=""
DNS_PRIMARY_RTT_MS=""
DNS_RANKING=""
while [ -z "$WORKING_DNS_PORTS" ]; do
    select_working_ports
    [ -n "$WORKING_DNS_PORTS" ] && break
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -gt 12 ]; then
        # Сохраняем аварийный fallback, но явно не выдаём его за DNSSEC.
        WORKING_DNS_PORTS="40500"
        DNS_PRIMARY="40500"
        DNS_BACKUP_PORTS=""
        DNS_PRIMARY_RTT_MS=""
        DNS_HEALTH_MODE="DNS_UNAVAILABLE_FALLBACK"
        break
    fi
    sleep 5
done

WORKING_PORT_COUNT="$(printf '%s\n' "$WORKING_DNS_PORTS" | wc -w | awk '{print $1}')"
logger -t "unblock_ipset" \
    "DNS ports ($WORKING_PORT_COUNT): $WORKING_DNS_PORTS primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} ranking=${DNS_RANKING:-none} health=$DNS_HEALTH_MODE tunnel=${DNS_TUNNEL_PROTOCOL:-none} domain=$DNS_HEALTH_DOMAIN"
dns_health_file_log \
    "decision=final mode=$DNS_HEALTH_MODE primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} ports=$WORKING_DNS_PORTS ranking=${DNS_RANKING:-none} tunnel=${DNS_TUNNEL_PROTOCOL:-none}"

resilient_dig() {
    _rd_domain="$1"
    _rd_primary_port="$2"
    _rd_tried=""

    # 0. Сначала соблюдаем явные resource-specific правила dnsmasq.conf.
    # Если специальный upstream недоступен, возвращаемся к общей схеме
    # DNSSEC -> tunnel-DNS -> insecure -> 40500/provider/bootstrap.
    for _rd_resource in $(dnsmasq_resource_servers "$_rd_domain" || true); do
        case "$_rd_resource" in
            LOCAL#[0-9]*)
                _rd_resource_port="${_rd_resource#LOCAL#}"
                _rd_result="$(dig +short +timeout=3 +tries=1 \
                    "$_rd_domain" @localhost -p "$_rd_resource_port" 2>/dev/null || true)"
                ;;
            *#[0-9]*)
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
            logger -t "unblock_ipset" \
                "DNS resolve: $_rd_domain source=DNSMASQ_RESOURCE upstream=$_rd_resource"
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                [ -n "$_candidate" ] || continue
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
            done
            return 0
        fi
    done

    # 1. Все DNSSEC-проверенные local DoT/DoH-порты. ВАЖНО: не
    # подставляем сюда рабочий placeholder 40500 — при tunnel-DNS он
    # должен идти только после tunnel-DNS, а не перед ним.
    for _rd_port in $DNS_SECURE_PORTS; do
        [ -n "$_rd_port" ] || continue
        printf ' %s ' "$_rd_tried" | grep -q " $_rd_port " && continue
        _rd_tried="${_rd_tried}${_rd_tried:+ }${_rd_port}"
        _rd_result="$(dig +short +timeout=3 +tries=1 \
            "$_rd_domain" @localhost -p "$_rd_port" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                [ -n "$_candidate" ] || continue
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
            done
            return 0
        fi
    done

    # 2. Tunnel-DNS через сохранённые endpoint pins.
    if [ "$DNS_TUNNEL_READY" -eq 1 ]; then
        _rd_result="$(tunnel_dns_lookup "$_rd_domain" || true)"
        if [ -n "$_rd_result" ]; then
            printf '%s\n' "$_rd_result"
            return 0
        fi
    fi

    # 3. Валидные ответы без AD — только после tunnel-DNS.
    for _rd_port in $DNS_INSECURE_PORTS; do
        printf ' %s ' "$_rd_tried" | grep -q " $_rd_port " && continue
        _rd_tried="${_rd_tried}${_rd_tried:+ }$_rd_port"
        _rd_result="$(dig +short +timeout=3 +tries=1 \
            "$_rd_domain" @localhost -p "$_rd_port" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            logger -t "unblock_ipset" \
                "DNS resolve: $_rd_domain source=DNS_OK_NO_DNSSEC"
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
            done
            return 0
        fi
    done

    # 4. Аварийный local port и DNS провайдера.
    if ! printf ' %s ' "$_rd_tried" | grep -q ' 40500 '; then
        _rd_result="$(dig +short +timeout=3 +tries=1 \
            "$_rd_domain" @localhost -p 40500 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            logger -t "unblock_ipset" \
                "DNS resolve: $_rd_domain source=40500 level=DNS_UNAVAILABLE"
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
            done
            return 0
        fi
    fi
    for _rd_ns in $(provider_resolver_list); do
        _rd_result="$(dig +short +timeout=3 +tries=1 +tcp \
            "$_rd_domain" "@$_rd_ns" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            logger -t "unblock_ipset" \
                "DNS resolve: $_rd_domain source=PROVIDER_DNS"
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
            done
            return 0
        fi
    done

    # 5. Одноразовый cold-start bootstrap — последний внешний вариант.
    for _rd_ns in $BOOTSTRAP_RESOLVERS; do
        _rd_result="$(dig +short +timeout=3 +tries=1 +tcp \
            "$_rd_domain" "@$_rd_ns" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            logger -t "unblock_ipset" \
                "DNS resolve: $_rd_domain source=COLD_START_BOOTSTRAP resolver=$_rd_ns"
            printf '%s\n' "$_rd_result" | while IFS= read -r _candidate; do
                is_public_ipv4 "$_candidate" && printf '%s\n' "$_candidate"
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
    # Внутри $(( )) операнды НЕ заключаются в кавычки: bash это допускает,
    # но BusyBox ash/dash падают с "arithmetic syntax error", из-за чего
    # функция возвращала пустую строку и dig уходил на порт "".
    _grp_idx="$1"
    _grp_n=$(( ((_grp_idx - 1) % WORKING_PORT_COUNT) + 1 ))
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

    ipset create "$_pl_setname_real" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || return 1

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
            _range_start="${line%%-*}"
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
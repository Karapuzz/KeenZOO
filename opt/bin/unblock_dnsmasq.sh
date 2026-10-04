#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

OUT_FILE="/opt/etc/unblock.dnsmasq"
CIDR_FILE="/opt/etc/unblock.dnsmasq.cidr"
DNSMASQ_CONF="/opt/etc/dnsmasq.conf"
DNS_UPSTREAM_BEGIN="# BEGIN KeenZOO managed DNS upstreams"
DNS_UPSTREAM_END="# END KeenZOO managed DNS upstreams"
DNSMASQ_IF_BEGIN="# BEGIN KeenZOO dynamic WireGuard interfaces"
DNSMASQ_IF_END="# END KeenZOO dynamic WireGuard interfaces"
IPSET_SUFFIX="${IPSET_SUFFIX:-}"

TMP_OUT="$(mktemp /tmp/unblock.dnsmasq.XXXXXX)"
TMP_CIDR="$(mktemp /tmp/unblock.dnsmasq.cidr.XXXXXX)"

cleanup() {
    rm -f "$TMP_OUT" "$TMP_CIDR"
}
trap cleanup EXIT INT TERM HUP

: > "$TMP_OUT"
: > "$TMP_CIDR"

# Обновляем управляемый блок В СУЩЕСТВУЮЩЕМ dnsmasq.conf.
# В Keenetic логическое имя NDM Wireguard0 соответствует kernel-имени
# nwg0; отсутствующий nwg1 нельзя держать статической строкой — dnsmasq
# печатает warning при каждом старте. Если nwg1 появится позже, следующий
# запуск обновления добавит его в этот же блок.
update_dynamic_interfaces() {
    [ -f "$DNSMASQ_CONF" ] || return 0
    _udi_ifaces=""
    for _udi_if in $(ip -o link show 2>/dev/null \
        | awk -F': ' '{print $2}' | sed 's/@.*//' \
        | grep -E '^(nwg|wg)[0-9]+$' || true); do
        _udi_ifaces="${_udi_ifaces}${_udi_ifaces:+ }interface=$_udi_if"
    done

    _udi_tmp="${DNSMASQ_CONF}.tmp.$$"
    awk -v b="$DNSMASQ_IF_BEGIN" -v e="$DNSMASQ_IF_END" \
        -v ifaces="$_udi_ifaces" '
        $0 == b { skip=1; next }
        $0 == e {
            if (!inserted) {
                print b
                if (ifaces != "") {
                    n = split(ifaces, a, " ")
                    for (i = 1; i <= n; i++) print a[i]
                }
                print e
                inserted=1
            }
            skip=0
            next
        }
        !skip { print }
        END {
            if (!inserted) {
                print DNSMASQ_IF_BEGIN
                if (ifaces != "") {
                    n = split(ifaces, a, " ")
                    for (i = 1; i <= n; i++) print a[i]
                }
                print DNSMASQ_IF_END
            }
        }
    ' "$DNSMASQ_CONF" > "$_udi_tmp"
    chmod 0644 "$_udi_tmp" 2>/dev/null || true
    mv -f "$_udi_tmp" "$DNSMASQ_CONF"

    # При вызове из ifstatechanged dnsmasq уже работает. HUP перечитывает
    # изменённый существующий конфиг без создания отдельного файла; при
    # полном unblock_update последующий restart остаётся штатным.
    _udi_pids="$(pidof dnsmasq 2>/dev/null || true)"
    [ -n "$_udi_pids" ] && kill -HUP $_udi_pids 2>/dev/null || true
}

update_dynamic_interfaces

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

# Публичный IPv4 для tunnel-DNS. Частные и служебные ответы не должны
# попадать в ipset: это одновременно защита от DNS-rebind и от ошибочного
# маршрута в локальный tunnel endpoint.
is_public_ipv4() {
    _ipi="$1"
    is_ip "$_ipi" || return 1
    printf '%s\n' "$_ipi" | awk -F. '
        {
            a=$1+0; b=$2+0
            if (a == 0 || a == 10 || a == 127) bad=1
            if (a == 100 && b >= 64 && b <= 127) bad=1
            if (a == 169 && b == 254) bad=1
            if (a == 172 && b >= 16 && b <= 31) bad=1
            if (a == 192 && b == 168) bad=1
            if (a == 192 && b == 0) bad=1
            if (a == 198 && (b == 18 || b == 19)) bad=1
            if (a >= 224) bad=1
        }
        END { exit (bad ? 1 : 0) }
    '
}

# Рантайм-канал tunnel-DNS не создаёт новый файл или daemon. В уже
# существующий ipset unblockdns добавляются только адреса DoH endpoint-ов,
# найденные в сохранённой NDM-секции /opt/etc/hosts. 100-redirect.sh
# направляет TCP/443 к активному локальному туннелю.
DNS_TUNNEL_SET="unblockdns"
# Проверяем DNS REDIRECT тем же бинарником, который умеет match-set.
# /opt/sbin/iptables может быть урезанным Entware-вариантом, тогда как
# 100-redirect.sh выбирает прошивочный бинарник отдельно.
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

# Обязательные кэшируемые параметры задаются до health-check: функции
# ниже вызываются до генерации dnsmasq и используют только shell-переменные.
PIN_BEGIN="# --- KeenZOO pinned (не редактировать вручную) ---"
PIN_END="# --- end KeenZOO pinned ---"
PIN_ENABLED="${PIN_ENABLED:-1}"
NDM_ENDPOINT_HOSTS="${NDM_ENDPOINT_HOSTS:-dns11.quad9.net dns.google cloudflare-dns.com opennic1.eth-services.de opennic2.eth-services.de}"
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

    # Перестраиваем существующий NDM hook, а не создаём новый скрипт.
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
                    logger -t "unblock_dnsmasq" \
                        "DNS tunnel: protocol=$_tdl_proto endpoint=$_tdl_host level=TUNNEL_DNS"
                    printf '%s\n' "$_tdl_answers"
                    return 0
                fi
            done
        done
    done
    return 1
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

normalize_domain_mode() {
    # dnsmasq в правилах вида ipset=/example.com/set и server=/example.com/...
    # покрывает и сам домен, и ВСЕ его поддомены. Поэтому запись "*.host"
    # нормализуется в базовый домен, а не превращается в литерал "*.host"
    # (прежний вариант создавал заведомо несовпадающие правила).
    _value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"

    case "$_value" in
        \*.*)
            _base="${_value#*.}"
            is_domain_core "$_base" || return 1
            printf '%s\n' "$_base"
            ;;
        .*)
            _base="${_value#.}"
            is_domain_core "$_base" || return 1
            printf '%s\n' "$_base"
            ;;
        *)
            is_domain_core "$_value" || return 1
            printf '%s\n' "$_value"
            ;;
    esac
}

DNS_PORTS_DOT="40500 40501 40502 40503"
DNS_PORTS_DOH="40508 40509 40510 40511"
# Контрольная зона должна быть стабильной и DNSSEC-подписанной, но не
# зависеть от доступности заблокированных в России ресурсов. torproject.org
# здесь намеренно не используется: его блокировка дала бы ложный отказ DNS.
DNS_HEALTH_DOMAIN="${DNS_HEALTH_DOMAIN:-example.com}"
# Health decision log is deliberately bounded. Detailed per-port messages
# still go to syslog; this file keeps only compact rankings and decisions.
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-/opt/var/log/unblock_dns_health.log}"
DNS_HEALTH_LOG_MAX="${DNS_HEALTH_LOG_MAX:-131072}"
DNS_HEALTH_LOG_KEEP="${DNS_HEALTH_LOG_KEEP:-200}"

# Результат:
#   0 — NOERROR + A + DNSSEC AD, без AA;
#   2 — DNS-ответ есть, но AD отсутствует (insecure fallback);
#   1 — DNS не прошёл проверку или похож на подмену.
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

probe_dns_port() {
    _pdp_port="$1"
    if dns_health_probe "$_pdp_port"; then
        logger -t "unblock_dnsmasq" \
            "DNS health: port=$_pdp_port level=DNSSEC_OK rtt=${DNS_LAST_RTT_MS}ms reason=$DNS_LAST_REASON domain=$DNS_HEALTH_DOMAIN"
        return 0
    else
        _pdp_rc=$?
    fi
    if [ "$_pdp_rc" -eq 2 ]; then
        logger -t "unblock_dnsmasq" \
            "DNS health: port=$_pdp_port level=DNS_OK_NO_DNSSEC rtt=${DNS_LAST_RTT_MS}ms reason=$DNS_LAST_REASON domain=$DNS_HEALTH_DOMAIN"
        return 2
    fi
    logger -t "unblock_dnsmasq" \
        "DNS health: port=$_pdp_port level=DNS_FAILED rtt=${DNS_LAST_RTT_MS}ms reason=${DNS_LAST_REASON:-unknown} status=${DNS_LAST_STATUS:-EMPTY} flags=${DNS_LAST_FLAGS:-none} domain=$DNS_HEALTH_DOMAIN"
    return 1
}

# Keep a compact, bounded file for post-reboot diagnostics. rotate_logs.sh
# also processes this file from cron; the inline check prevents unbounded
# growth between cron runs.
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
    printf '%s unblock_dnsmasq %s\n' "$_dhl_now" "$*" \
        >> "$DNS_HEALTH_LOG" 2>/dev/null || true
    dns_health_log_rotate
}

DNS_METRICS_FILE="$(mktemp /tmp/unblock.dns.metrics.XXXXXX)"
cleanup_dns_metrics() {
    cleanup
    rm -f "$DNS_METRICS_FILE" "${DNS_METRICS_FILE}.ranked" "${DNS_METRICS_FILE}.remaining" "${DNS_METRICS_FILE}.next"
}
trap cleanup_dns_metrics EXIT INT TERM HUP

# BusyBox sort on some Keenetic builds accepts the options but does not
# apply a numeric field key. Select the minimum explicitly with awk and
# repeatedly remove it. This is portable across the router's BusyBox ash/awk
# and keeps secure ports before insecure ports.
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
    if [ -n "$DNS_PRIMARY" ] && [ -f "$DNS_METRICS_FILE" ]; then
        DNS_PRIMARY_RTT_MS="$(awk -F'|' -v p="$DNS_PRIMARY" \
            '$1 == p { print $3; exit }' "$DNS_METRICS_FILE")"
    fi
}

# Проверяем сначала все DoT, затем все DoH. После полного набора проверок
# рабочие порты ранжируются по измеренному Query time. Если DNSSEC-порты
# есть, insecure-порты не попадают в client-plane список и используются
# только отдельным fallback-путём после tunnel-DNS.
probe_all_dns_ports() {
    : > "$DNS_METRICS_FILE"
    for _dh_port in $DNS_PORTS_DOT; do
        if probe_dns_port "$_dh_port"; then
            printf '%s|secure|%s|dot\n' "$_dh_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE"
        else
            _dh_rc=$?
            [ "$_dh_rc" -eq 2 ] && printf '%s|insecure|%s|dot\n' "$_dh_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE"
        fi
    done
    for _dh_port in $DNS_PORTS_DOH; do
        if probe_dns_port "$_dh_port"; then
            printf '%s|secure|%s|doh\n' "$_dh_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE"
        else
            _dh_rc=$?
            [ "$_dh_rc" -eq 2 ] && printf '%s|insecure|%s|doh\n' "$_dh_port" "$DNS_LAST_RTT_MS" >> "$DNS_METRICS_FILE"
        fi
    done

    _dns_sorted="${DNS_METRICS_FILE}.ranked"
    rank_dns_metrics "$DNS_METRICS_FILE" "$_dns_sorted"
    DNS_SECURE_PORTS="$(awk -F'|' '$2 == "secure" { print $1 }' "$_dns_sorted" \
        | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    DNS_INSECURE_PORTS="$(awk -F'|' '$2 == "insecure" { print $1 }' "$_dns_sorted" \
        | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    DNS_RANKING="$(awk -F'|' '{ printf "%s:%s,", $1, $3 }' "$_dns_sorted" \
        | sed 's/,$//')"
    if [ -n "$DNS_SECURE_PORTS" ]; then
        set_dns_working_order "$DNS_SECURE_PORTS"
    else
        set_dns_working_order "$DNS_INSECURE_PORTS"
    fi
    dns_health_file_log \
        "ranking=${DNS_RANKING:-none} primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} secure=${DNS_SECURE_PORTS:-none} insecure=${DNS_INSECURE_PORTS:-none}"
}

DNS_SECURE_PORTS=""
DNS_INSECURE_PORTS=""
DNS_WORKING_PORTS=""
DNS_PRIMARY=""
DNS_BACKUP_PORTS=""
DNS_PRIMARY_RTT_MS=""
DNS_RANKING=""
probe_all_dns_ports
DNS_INITIAL_SECURE_PORTS="$DNS_SECURE_PORTS"
DNS_INITIAL_INSECURE_PORTS="$DNS_INSECURE_PORTS"
DNS_INITIAL_WORKING_PORTS="$DNS_WORKING_PORTS"
DNS_INITIAL_PRIMARY="$DNS_PRIMARY"
DNS_INITIAL_BACKUP_PORTS="$DNS_BACKUP_PORTS"
DNS_INITIAL_PRIMARY_RTT_MS="$DNS_PRIMARY_RTT_MS"
DNS_INITIAL_RANKING="$DNS_RANKING"

# Проверяет выбранный transport именно через client-plane DNS. Наличие
# процесса и iptables-правила недостаточно: хотя бы один системный DoH/DoT
# local port должен реально ответить после REDIRECT. Если Xray не отвечает,
# цикл снимает его DNS REDIRECT и пробует Trojan, затем Hysteria.
try_tunnel_dns() {
    DNS_TUNNEL_READY=0
    DNS_TUNNEL_PROTOCOL=""
    for _tt_proto in xray trojan hysteria; do
        tunnel_protocol_active "$_tt_proto" || start_tunnel_protocol "$_tt_proto" || continue
        tunnel_dns_prepare "$_tt_proto" || continue
        DNS_TUNNEL_PROTOCOL="$_tt_proto"
        probe_all_dns_ports
        if [ -n "$DNS_WORKING_PORTS" ]; then
            DNS_TUNNEL_READY=1
            logger -t "unblock_dnsmasq" \
                "DNS tunnel client-plane: protocol=$_tt_proto ports=$DNS_WORKING_PORTS primary=$DNS_PRIMARY"
            return 0
        fi
    done
    DNS_TUNNEL_PROTOCOL=""
    DNS_TUNNEL_READY=0
    # Восстанавливаем локальные результаты, полученные до tunnel-проб.
    DNS_SECURE_PORTS="$DNS_INITIAL_SECURE_PORTS"
    DNS_INSECURE_PORTS="$DNS_INITIAL_INSECURE_PORTS"
    DNS_WORKING_PORTS="$DNS_INITIAL_WORKING_PORTS"
    DNS_PRIMARY="$DNS_INITIAL_PRIMARY"
    DNS_BACKUP_PORTS="$DNS_INITIAL_BACKUP_PORTS"
    DNS_PRIMARY_RTT_MS="$DNS_INITIAL_PRIMARY_RTT_MS"
    DNS_RANKING="$DNS_INITIAL_RANKING"
    # Принудительно удалить DNS endpoint REDIRECT, не выключая сам сервис.
    if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        DNS_TUNNEL_DISABLE=1 type=iptable table=nat \
            /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    fi
    return 1
}

DNS_TUNNEL_READY=0
if [ -z "$DNS_INITIAL_SECURE_PORTS" ]; then
    try_tunnel_dns || true
fi

# Tunnel state has priority over the fact that the tunnel makes a local
# listener answer with AD. Otherwise a successful tunnel check would be
# mislabeled LOCAL_DNSSEC and the fallback chain would be invisible.
if [ "$DNS_TUNNEL_READY" -eq 1 ]; then
    DNS_MODE="TUNNEL_DNS"
    DNS_PRIMARY_LEVEL="TUNNEL_DNS"
elif [ -n "$DNS_INITIAL_SECURE_PORTS" ]; then
    DNS_SECURE_PORTS="$DNS_INITIAL_SECURE_PORTS"
    DNS_INSECURE_PORTS="$DNS_INITIAL_INSECURE_PORTS"
    DNS_WORKING_PORTS="$DNS_INITIAL_WORKING_PORTS"
    DNS_PRIMARY="$DNS_INITIAL_PRIMARY"
    DNS_BACKUP_PORTS="$DNS_INITIAL_BACKUP_PORTS"
    DNS_PRIMARY_RTT_MS="$DNS_INITIAL_PRIMARY_RTT_MS"
    DNS_RANKING="$DNS_INITIAL_RANKING"
    DNS_MODE="LOCAL_DNSSEC"
    DNS_PRIMARY_LEVEL="DNSSEC_OK"
elif [ -n "$DNS_INSECURE_PORTS" ]; then
    DNS_MODE="DNS_OK_NO_DNSSEC"
    DNS_PRIMARY_LEVEL="DNS_OK_NO_DNSSEC"
elif [ -z "$DNS_PRIMARY" ]; then
    DNS_PRIMARY="40500"
    DNS_PRIMARY_LEVEL="DNS_UNAVAILABLE"
    DNS_MODE="DNS_UNAVAILABLE"
fi

update_dnsmasq_upstreams() {
    [ -f "$DNSMASQ_CONF" ] || return 0
    _udu_ports=""
    _udu_add_port() {
        case " $_udu_ports " in
            *" $1 "*) ;;
            *) _udu_ports="${_udu_ports}${_udu_ports:+ }$1" ;;
        esac
    }

    # Всегда используем системные локальные DoH/DoT listeners. В tunnel
    # режиме их внешние TCP/443 и TCP/853 соединения уже REDIRECT-ятся в
    # выбранный transport. Старый raw DNS listener Xray не используется.
    for _udu_port in $DNS_WORKING_PORTS; do
        _udu_add_port "$_udu_port"
    done
    _udu_add_port 40500

    _udu_tmp="${DNSMASQ_CONF}.upstream.$$"
    awk -v b="$DNS_UPSTREAM_BEGIN" -v e="$DNS_UPSTREAM_END" \
        -v ports="$_udu_ports" '
        function emit() {
            print b
            print "strict-order"
            n = split(ports, a, " ")
            for (i = 1; i <= n; i++) {
                if (a[i] != "") print "server=127.0.0.1#" a[i]
            }
            print e
            inserted = 1
        }
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; emit(); next }
        !skip { print }
        END { if (!inserted) emit() }
    ' "$DNSMASQ_CONF" > "$_udu_tmp"
    chmod 0644 "$_udu_tmp" 2>/dev/null || true
    mv -f "$_udu_tmp" "$DNSMASQ_CONF"
}

update_dnsmasq_upstreams

logger -t "unblock_dnsmasq" \
    "DNS primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} backups=${DNS_BACKUP_PORTS:-none} ranking=${DNS_RANKING:-none} mode=$DNS_MODE level=$DNS_PRIMARY_LEVEL tunnel=${DNS_TUNNEL_PROTOCOL:-none} health_domain=$DNS_HEALTH_DOMAIN"
dns_health_file_log \
    "decision=final mode=$DNS_MODE level=$DNS_PRIMARY_LEVEL primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} backups=${DNS_BACKUP_PORTS:-none} ranking=${DNS_RANKING:-none} tunnel=${DNS_TUNNEL_PROTOCOL:-none}"

# ── Закрепление адресов прокси-серверов в /opt/etc/hosts ─────────────
# Адрес VLESS/Hysteria в конфиге может быть задан доменом. При блокировке
# DoT/DoH этот домен становится неразрешимым, туннель не поднимается, а
# DNS через туннель — тем более: замкнутый круг. Поэтому пока штатный DNS
# работает, домен резолвится заранее и его IP закрепляется в /opt/etc/hosts
# (dnsmasq читает этот файл штатно). При аварии xray получает адрес
# локально, без обращения к сети.
#
# Пиннинг применяется ТОЛЬКО к доменам прокси-серверов. Обычные сайты
# закреплять нельзя — это сломало бы балансировку CDN.
PIN_BEGIN="# --- KeenZOO pinned (не редактировать вручную) ---"
PIN_END="# --- end KeenZOO pinned ---"
# Секция NDM bootstrap находится в уже существующем /opt/etc/hosts;
# отдельный state/status-файл не создаётся.
NDM_PIN_BEGIN="# --- KeenZOO NDM bootstrap (управляется проектом) ---"
NDM_PIN_END="# --- end KeenZOO NDM bootstrap ---"
NDM_ENDPOINT_HOSTS="${NDM_ENDPOINT_HOSTS:-dns11.quad9.net dns.google cloudflare-dns.com opennic1.eth-services.de opennic2.eth-services.de}"

HOSTS_FILE="${HOSTS_FILE:-/opt/etc/hosts}"

# Значения дублируют bot_config.py (pin_server_hosts, bootstrap_resolvers).
# Shell-скрипты проекта не разбирают Python-конфиг, а держат константы у
# себя — так же, как порты в 100-redirect.sh. Отключить пиннинг можно
# переменной окружения: PIN_ENABLED=0 /opt/bin/unblock_dnsmasq.sh
PIN_ENABLED="${PIN_ENABLED:-1}"

# Bootstrap-резолверы используются только через прямой TCP-DNS-запрос,
# когда локальные DoT/DoH ещё не поднялись. Это не замена шифрованному
# DNS: результат принимается только как текущий кандидат и затем
# проверяется TCP-доступность endpoint. Можно переопределить список
# переменной BOOTSTRAP_RESOLVERS.
BOOTSTRAP_RESOLVERS="${BOOTSTRAP_RESOLVERS:-9.9.9.9 8.8.8.8 1.1.1.1}"

# Проверка и bootstrap endpoint NDM без отдельного скрипта и state-файла.
# Результат хранится только в уже предусмотренном /opt/etc/hosts и
# потребляется dnsmasq через addn-hosts. NDM получает его через локальный
# DNS Override после перезапуска dnsmasq.
# Проверка NDM endpoint по уровням:
#   TCP -> TLS -> HTTP. Для DoT на 853 проверяется только TLS, потому что
#   это не HTTPS и отправлять туда HTTP-запрос некорректно.
# Возврат 0 означает, что транспорт пригоден для bootstrap:
#   HTTP 2xx/3xx, либо ожидаемый 400/405 на пустой DoH-запрос,
#   либо успешный TLS для DoT. 403/5xx не считаются рабочим DNS.
ndm_endpoint_reachable() {
    _ner_host="$1"
    _ner_ip="$2"
    case "$_ner_host" in
        opennic*.eth-services.de) _ner_port=853 ;;
        *) _ner_port=443 ;;
    esac

    if [ "$_ner_port" = "853" ]; then
        if command -v openssl >/dev/null 2>&1 \
            && openssl s_client -connect "${_ner_ip}:853" \
                -servername "$_ner_host" -verify_return_error \
                </dev/null >/dev/null 2>&1; then
            logger -t "unblock_dnsmasq" \
                "NDM probe: host=$_ner_host level=TLS_OK"
            return 0
        fi
        logger -t "unblock_dnsmasq" \
            "NDM probe: host=$_ner_host level=TLS_UNAVAILABLE"
        return 1
    fi

    _ner_trace="$(mktemp /tmp/ndm_probe.XXXXXX 2>/dev/null || true)"
    _ner_code=""
    _ner_rc=1
    if command -v curl >/dev/null 2>&1; then
        _ner_rc=0
        if [ -n "$_ner_trace" ]; then
            _ner_code="$(curl -sS -v --noproxy '*' \
                --connect-timeout 4 --max-time 7 \
                --resolve "${_ner_host}:443:${_ner_ip}" \
                -o /dev/null -w '%{http_code}' \
                "https://${_ner_host}:443/dns-query" \
                2>"$_ner_trace")" || _ner_rc=$?
        else
            _ner_code="$(curl -sS --noproxy '*' \
                --connect-timeout 4 --max-time 7 \
                --resolve "${_ner_host}:443:${_ner_ip}" \
                -o /dev/null -w '%{http_code}' \
                "https://${_ner_host}:443/dns-query" \
                2>/dev/null)" || _ner_rc=$?
        fi
    fi

    _ner_tcp=0
    _ner_tls=0
    if [ -n "$_ner_trace" ]; then
        grep -q 'Connected to' "$_ner_trace" 2>/dev/null && _ner_tcp=1
        grep -qE 'SSL connection using|TLSv[0-9]' \
            "$_ner_trace" 2>/dev/null && _ner_tls=1
    fi

    if [ "$_ner_rc" -eq 0 ]; then
        case "$_ner_code" in
            2*|3*)
                rm -f "$_ner_trace"
                return 0
                ;;
            400|405)
                logger -t "unblock_dnsmasq" \
                    "NDM probe: host=$_ner_host level=HTTP_REACHED code=$_ner_code"
                rm -f "$_ner_trace"
                return 0
                ;;
            401|403|407)
                logger -t "unblock_dnsmasq" \
                    "NDM probe: host=$_ner_host level=HTTP_DENIED code=$_ner_code"
                rm -f "$_ner_trace"
                return 1
                ;;
            4*)
                logger -t "unblock_dnsmasq" \
                    "NDM probe: host=$_ner_host level=HTTP_REJECTED code=$_ner_code"
                rm -f "$_ner_trace"
                return 1
                ;;
            5*)
                logger -t "unblock_dnsmasq" \
                    "NDM probe: host=$_ner_host level=HTTP_UPSTREAM code=$_ner_code"
                rm -f "$_ner_trace"
                return 1
                ;;
        esac
    fi

    if [ "$_ner_tls" -eq 1 ]; then
        logger -t "unblock_dnsmasq" \
            "NDM probe: host=$_ner_host level=HTTP_TIMEOUT_AFTER_TLS"
    elif [ "$_ner_tcp" -eq 1 ]; then
        logger -t "unblock_dnsmasq" \
            "NDM probe: host=$_ner_host level=TLS_TIMEOUT_AFTER_TCP"
    else
        logger -t "unblock_dnsmasq" \
            "NDM probe: host=$_ner_host level=TCP_UNAVAILABLE"
    fi
    rm -f "$_ner_trace"
    return 1
}

ndm_fresh_addresses() {
    _nfa_host="$1"
    # Используется общий порядок local DNSSEC -> tunnel-DNS -> pin ->
    # insecure/40500/provider/bootstrap, а не прямой bootstrap на первом
    # шаге. Старый pin уже доступен через ndm_pinned_lookup.
    resolve_name_a "$_nfa_host" 2>/dev/null | sort -u
}

update_ndm_bootstrap_hosts() {
    _unh_body="$(mktemp /tmp/ndm_hosts.XXXXXX)" || return 0
    : > "$_unh_body"

    for _unh_host in $NDM_ENDPOINT_HOSTS; do
        _unh_ips="$(ndm_fresh_addresses "$_unh_host")"
        _unh_ok=""
        for _unh_ip in $_unh_ips; do
            if ndm_endpoint_reachable "$_unh_host" "$_unh_ip"; then
                _unh_ok="${_unh_ok}${_unh_ok:+ }$_unh_ip"
            fi
        done
        if [ -n "$_unh_ok" ]; then
            for _unh_ip in $_unh_ok; do
                printf '%s %s\n' "$_unh_ip" "$_unh_host" >> "$_unh_body"
            done
            logger -t "unblock_dnsmasq" \
                "NDM endpoint refreshed: $_unh_host -> $_unh_ok"
        else
            # При DPI/HTTP 403 не стираем последний рабочий runtime-пин.
            # Старый адрес не объявляется рабочим заново, но сохраняется
            # до следующего успешного bootstrap, чтобы временная блокировка
            # не превращалась в потерю всех NDM endpoint-ов.
            _unh_old="$(ndm_pinned_lookup "$_unh_host" || true)"
            if [ -n "$_unh_old" ]; then
                for _unh_ip in $_unh_old; do
                    printf '%s %s\n' "$_unh_ip" "$_unh_host" >> "$_unh_body"
                done
                logger -t "unblock_dnsmasq" \
                    "NDM endpoint preserved: $_unh_host level=PREVIOUS_PIN"
            else
                logger -t "unblock_dnsmasq" \
                    "NDM endpoint not verified: $_unh_host"
            fi
        fi
    done

    _unh_hosts_tmp="${HOSTS_FILE}.ndm.$$"
    if [ -f "$HOSTS_FILE" ]; then
        awk -v b="$NDM_PIN_BEGIN" -v e="$NDM_PIN_END" '
            $0 == b { skip=1; next }
            $0 == e { skip=0; next }
            !skip
        ' "$HOSTS_FILE" > "$_unh_hosts_tmp" 2>/dev/null \
            || : > "$_unh_hosts_tmp"
    else
        : > "$_unh_hosts_tmp"
    fi
    {
        printf '%s\n' "$NDM_PIN_BEGIN"
        awk '!seen[$0]++' "$_unh_body"
        printf '%s\n' "$NDM_PIN_END"
    } >> "$_unh_hosts_tmp"
    chmod 0644 "$_unh_hosts_tmp" 2>/dev/null || true
    mv -f "$_unh_hosts_tmp" "$HOSTS_FILE"
    rm -f "$_unh_body"
}

# Домен сервера из конфига xray: берём address внутри vnext.
# python3 в shell-скриптах проекта не используется, поэтому разбор
# выполняется sed — структура конфига фиксирована.
xray_server_host() {
    [ -f /opt/etc/xray/config.json ] || return 0
    sed -n 's/.*"address"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        /opt/etc/xray/config.json \
        | grep -vE '^(127\.|0\.0\.0\.0|::1?$|localhost$)' \
        | head -1
}

# Домен сервера hysteria: значение "server" вида host:port.
hysteria_server_host() {
    [ -f /opt/etc/hysteria/config.json ] || return 0
    sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        /opt/etc/hysteria/config.json \
        | head -1 \
        | sed 's/:[0-9]*$//'
}

# Домен сервера trojan: значение "remote_addr".
# Важно требовать ИМЕННО remote_addr: в том же конфиге есть "local_addr"
# со значением 0.0.0.0, и нестрогий шаблон вытащил бы его.
trojan_server_host() {
    [ -f /opt/etc/trojan/config.json ] || return 0
    sed -n 's/.*"remote_addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        /opt/etc/trojan/config.json \
        | grep -vE '^(127\.|0\.0\.0\.0|::1?$|localhost$)' \
        | head -1
}

# Протоколы, использующие endpoint. Адреса не зашиваются: функция каждый
# раз читает актуальные runtime-конфиги, поэтому при смене DNS-IP в hosts
# сообщение всё равно связывает новый адрес с правильным ключом.
protocol_for_host() {
    _pfh_host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    _pfh_result=""

    _pfh_xray="$(xray_server_host || true)"
    _pfh_xray="$(printf '%s' "$_pfh_xray" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    [ -n "$_pfh_xray" ] && [ "$_pfh_host" = "$_pfh_xray" ] \
        && _pfh_result="VLESS"

    _pfh_trojan="$(trojan_server_host || true)"
    _pfh_trojan="$(printf '%s' "$_pfh_trojan" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    if [ -n "$_pfh_trojan" ] && [ "$_pfh_host" = "$_pfh_trojan" ]; then
        _pfh_result="${_pfh_result}${_pfh_result:+/}Trojan"
    fi

    _pfh_hysteria="$(hysteria_server_host || true)"
    _pfh_hysteria="$(printf '%s' "$_pfh_hysteria" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    if [ -n "$_pfh_hysteria" ] && [ "$_pfh_host" = "$_pfh_hysteria" ]; then
        _pfh_result="${_pfh_result}${_pfh_result:+/}Hysteria"
    fi

    printf '%s' "${_pfh_result:-proxy}"
}

# Ранее закреплённые адреса домена из собственной секции hosts.
# Это ШАГ 2 цепочки: пока прошлый пин жив, чужие DNS вообще не нужны.
pinned_hosts_lookup() {
    _ph_host="$1"
    [ -f "$HOSTS_FILE" ] || return 1

    # Читается только своя секция: строки, добавленные пользователем
    # вручную, к прокси-серверу отношения не имеют и доверия не требуют.
    awk -v b="$PIN_BEGIN" -v e="$PIN_END" -v h="$_ph_host" '
        $0 == b { inside = 1; next }
        $0 == e { inside = 0; next }
        inside && $2 == h { print $1 }
    ' "$HOSTS_FILE" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

# Провайдерский DNS и одноразовый bootstrap идут только после local
# DNSSEC, tunnel-DNS, старого pin и insecure local DNS. Это сохраняет
# заданную цепочку отказоустойчивости и не маскирует отсутствие DNSSEC.
provider_resolver_list() {
    sed -n 's/^[[:space:]]*nameserver[[:space:]]\{1,\}\([0-9.]\{7,\}\).*/\1/p' \
        /tmp/resolv.conf 2>/dev/null | grep -v '^127\.' | head -2
}

resolve_name_a() {
    _rna_name="$1"
    _rna_out=""

    # 1. Только DNSSEC-проверенные локальные DoT/DoH-порты.
    for _rna_port in $DNS_SECURE_PORTS; do
        _rna_out="$(dig +short +timeout=3 +tries=1 A "$_rna_name" \
            @localhost -p "$_rna_port" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
        [ -n "$_rna_out" ] && break
    done

    # 2. DoH через активный туннель. Старые pins для DoH endpoint-ов
    # позволяют выполнить этот шаг даже при полном отказе локального DNS.
    if [ -z "$_rna_out" ] && [ "$DNS_TUNNEL_READY" -eq 1 ]; then
        _rna_out="$(tunnel_dns_lookup "$_rna_name" || true)"
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=TUNNEL_DNS protocol=${DNS_TUNNEL_PROTOCOL:-unknown}"
    fi

    # Старый pin — это не новый DNS-ответ, а уже сохраненный адрес,
    # использующийся для продолжения работы туннеля.
    if [ -z "$_rna_out" ]; then
        _rna_out="$(pinned_hosts_lookup "$_rna_name" || true)"
        [ -z "$_rna_out" ] && _rna_out="$(ndm_pinned_lookup "$_rna_name" || true)"
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=PREVIOUS_PIN"
    fi

    # 3. Валидный ответ без AD используется только после tunnel-DNS.
    if [ -z "$_rna_out" ]; then
        for _rna_port in $DNS_INSECURE_PORTS; do
            _rna_out="$(dig +short +timeout=3 +tries=1 A "$_rna_name" \
                @localhost -p "$_rna_port" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            [ -n "$_rna_out" ] && break
        done
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=DNS_OK_NO_DNSSEC"
    fi

    # 4. Аварийный локальный порт, затем DNS провайдера.
    if [ -z "$_rna_out" ]; then
        _rna_out="$(dig +short +timeout=3 +tries=1 A "$_rna_name" \
            @localhost -p 40500 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=40500 level=DNS_UNAVAILABLE"
    fi
    if [ -z "$_rna_out" ]; then
        for _rna_ns in $(provider_resolver_list); do
            _rna_out="$(dig +short +timeout=3 +tries=1 +tcp A "$_rna_name" \
                "@$_rna_ns" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            [ -n "$_rna_out" ] && break
        done
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=PROVIDER_DNS"
    fi

    # 5. Холодный старт: внешний bootstrap разрешается только после всех
    # предыдущих уровней и не считается DNSSEC-проверенным.
    if [ -z "$_rna_out" ]; then
        for _rna_ns in $BOOTSTRAP_RESOLVERS; do
            _rna_out="$(dig +short +time=3 +tries=1 +tcp A "$_rna_name" \
                "@$_rna_ns" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            if [ -n "$_rna_out" ]; then
                logger -t "unblock_dnsmasq" \
                    "DNS resolve: $_rna_name source=COLD_START_BOOTSTRAP resolver=$_rna_ns"
                break
            fi
        done
    fi

    [ -n "$_rna_out" ] || return 1
    printf '%s\n' "$_rna_out"
}

resolve_pin_host() {
    _rp_host="$1"
    resolve_name_a "$_rp_host"
}

# Порт сервера протокола: нужен, чтобы проверять именно рабочий порт,
# а не гадать. Возвращает пусто, если определить не удалось.
proto_port_for_host() {
    _ppf_host="$1"
    # xray: "address": "<host>" и рядом "port": N
    if [ -f /opt/etc/xray/config.json ]; then
        _ppf_p="$(tr -d ' \n' < /opt/etc/xray/config.json 2>/dev/null \
            | sed -n "s/.*\"address\":\"${_ppf_host}\",\"port\":\([0-9]*\).*/\1/p" \
            | head -1)"
        [ -n "$_ppf_p" ] && { printf '%s' "$_ppf_p"; return 0; }
    fi
    # hysteria: "server": "<host>:<port>"
    if [ -f /opt/etc/hysteria/config.json ]; then
        _ppf_p="$(sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"'"${_ppf_host}"':\([0-9]*\)".*/\1/p' \
            /opt/etc/hysteria/config.json 2>/dev/null | head -1)"
        [ -n "$_ppf_p" ] && { printf '%s' "$_ppf_p"; return 0; }
    fi
    # trojan: "remote_addr" + "remote_port"
    if [ -f /opt/etc/trojan/config.json ]; then
        if grep -q "\"remote_addr\"[[:space:]]*:[[:space:]]*\"${_ppf_host}\"" \
            /opt/etc/trojan/config.json 2>/dev/null
        then
            _ppf_p="$(sed -n 's/.*"remote_port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
                /opt/etc/trojan/config.json 2>/dev/null | head -1)"
            [ -n "$_ppf_p" ] && { printf '%s' "$_ppf_p"; return 0; }
        fi
    fi
    printf '443'
}

# Уведомление в Telegram. Токен и chat_id берутся так же, как в
# check_updates.sh, — отдельного механизма не заводим.
pin_notify() {
    _pn_msg="$1"
    _pn_kind="${2:-warn}"

    # Канал 1 — веб-панель. Основной: Telegram с роутера часто
    # недоступен (в журнале — SSLError к api.telegram.org), и тогда
    # уведомление о недоступности само осталось бы недоставленным.
    # Панель читает этот файл и показывает плашку.
    _pn_state_file="/tmp/keenzoo_pin_status.json"
    _pn_ts="$(date +%s 2>/dev/null || echo 0)"
    # Кавычки и обратные слэши экранируются: текст попадает в JSON.
    _pn_esc="$(printf '%s' "$_pn_msg" \
        | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')"
    printf '{"kind":"%s","ts":%s,"message":"%s"}\n' \
        "$_pn_kind" "$_pn_ts" "$_pn_esc" \
        > "${_pn_state_file}.tmp" 2>/dev/null \
        && mv -f "${_pn_state_file}.tmp" "$_pn_state_file" 2>/dev/null \
        || true

    # Канал 2 — Telegram. Токен читается так же, как в check_updates.sh.
    _pn_token="$(grep "^token" /opt/etc/bot/bot_config.py 2>/dev/null \
        | sed "s/.*= *['\"]//;s/['\"].*//" | head -1)"
    _pn_chat=""
    for _pn_f in /opt/var/run/bot_chat_id_notify.txt \
        /opt/var/run/bot_chat_id.txt; do
        [ -f "$_pn_f" ] || continue
        _pn_chat="$(cat "$_pn_f" 2>/dev/null || true)"
        [ -n "$_pn_chat" ] && break
    done
    [ -n "$_pn_token" ] && [ -n "$_pn_chat" ] || return 0
    if command -v curl >/dev/null 2>&1; then
        curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${_pn_token}/sendMessage" \
            -d "chat_id=${_pn_chat}" -d "text=${_pn_msg}" \
            >/dev/null 2>&1 || true
    fi
}

# Проверка доступности закреплённых адресов.
# Повторные уведомления подавляются: сообщение уходит только при СМЕНЕ
# состояния, иначе крон в 06:00 писал бы в чат каждый день.
#
# Важно: эта функция доказывает только доступность TCP endpoint с роутера.
# Она НЕ делает TLS/SNI/Reality handshake и не должна объявлять сервер
# недоступным из-за того, что curl дождался закрытия уже установленного
# соединения.
#
# Прежняя версия использовала curl telnet и трактовала любой ненулевой код,
# кроме 7, как неприменимый, а затем всё равно возвращала 1. В частности,
# curl мог успешно напечатать "Connected to ...", получить timeout 28 при
# ожидании данных от молчащего TLS/Reality endpoint и превратить это в
# ложное «сервер недоступен». Дополнительная ошибка была в том, что при
# коде 7 до fallback nc выполнение сразу завершалось.
#
# Теперь «недоступен» возвращается только после явного отказа TCP-подключения
# (curl без строки Connected to либо неудачный nc). Timeout после уже
# установленного TCP считается успехом. Если проверить нечем, результат
# неизвестен и также не превращается в тревогу.
# Код возврата: 0 — доступен или недостаточно доказательств отказа,
# 1 — TCP-подключение явно не установлено.
tcp_probe() {
    _tp_ip="$1"
    _tp_port="$2"
    _tp_trace="$(mktemp /tmp/unblock_tcp.XXXXXX 2>/dev/null || true)"

    # curl есть в установленной схеме. -v нужен только для отличия
    # успешного connect от timeout уже после connect; TLS здесь намеренно
    # не проверяется, поэтому SNI/Reality не искажают результат.
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$_tp_trace" ]; then
            if curl -sS -v --noproxy '*' \
                --connect-timeout 4 --max-time 5 \
                -o /dev/null "telnet://${_tp_ip}:${_tp_port}" \
                >/dev/null 2>"$_tp_trace"; then
                _tp_rc=0
            else
                _tp_rc=$?
            fi

            if grep -q 'Connected to' "$_tp_trace" 2>/dev/null; then
                rm -f "$_tp_trace"
                return 0
            fi
            rm -f "$_tp_trace"
        else
            if curl -sS --noproxy '*' \
                --connect-timeout 4 --max-time 5 \
                -o /dev/null "telnet://${_tp_ip}:${_tp_port}" \
                >/dev/null 2>&1; then
                return 0
            else
                _tp_rc=$?
            fi
        fi

        # rc=7 означает отказ curl установить соединение. Fallback всё
        # равно выполняется: некоторые сборки curl/BusyBox дают 7 для
        # неприменимого telnet-протокола, а не для реального отказа.
        # rc=28 без строки Connected to не доказывает отказ: это может быть
        # фильтрация или timeout проверки, поэтому ниже он станет unknown.
        _tp_curl_hard=0
        [ "${_tp_rc:-0}" = "7" ] && _tp_curl_hard=1
    else
        _tp_curl_hard=0
    fi

    # nc — дополнительный способ, если установлен. Не используем -z:
    # в BusyBox он отсутствует в части сборок.
    if command -v nc >/dev/null 2>&1; then
        if printf '\n' | nc -w 4 "$_tp_ip" "$_tp_port" \
            >/dev/null 2>&1; then
            return 0
        else
            _tp_nc_rc=$?
        fi
        [ "$_tp_nc_rc" = "0" ] && return 0
        [ "$_tp_curl_hard" = "1" ] && return 1
        return 0
    fi

    # curl rc=7 — единственный жёсткий результат в этой ветке: curl
    # установил, что TCP-соединение не создано. После двух таких проб
    # check_pinned_reachable может показать endpoint как недоступный.
    # Остальные коды (прежде всего timeout 28) остаются неизвестными.
    [ "${_tp_curl_hard:-0}" = "1" ] && return 1
    return 0
}

check_pinned_reachable() {
    _cpr_body="$1"
    _cpr_state="/tmp/keenzoo_pin_unreach"
    _cpr_bad=""

    printf '%s' "$_cpr_body" \
        | awk -F "$(printf '\t')" '!seen[$1 FS $2]++' \
        | while IFS="$(printf '\t')" read -r _ip _host; do
        [ -n "$_ip" ] && [ -n "$_host" ] || continue

        _proto="$(protocol_for_host "$_host")"
        # Hysteria2 работает поверх QUIC (UDP). TCP-порт у такого сервера
        # закрыт штатно, и TCP-проба всегда давала бы «недоступен».
        # Проверить UDP из shell нечем — пропускаем чистый Hysteria
        # endpoint. Если тот же host используется ещё и VLESS/Trojan,
        # проверка остаётся для этих TCP-протоколов.
        [ "$_proto" = "Hysteria" ] && continue

        _port="$(proto_port_for_host "$_host")"
        # Один отказ не является достаточным доказательством: повторяем
        # TCP-пробу после короткой паузы. tcp_probe сама учитывает уже
        # установленное соединение и не требует TLS/SNI handshake.
        if ! tcp_probe "$_ip" "$_port"; then
            sleep 1
            tcp_probe "$_ip" "$_port" || \
                printf '%s: TCP endpoint unavailable — %s:%s (%s)\n' \
                    "$_proto" "$_ip" "$_port" "$_host"
        fi
    done > "${_cpr_state}.now" 2>/dev/null || true

    if [ -s "${_cpr_state}.now" ]; then
        _cpr_bad="$(awk '{if (NR > 1) printf "; "; printf "%s", $0}' \
            "${_cpr_state}.now")"
        logger -t "unblock_dnsmasq" \
            "pin: level=TCP_UNAVAILABLE после двух проб: $_cpr_bad; TLS/SNI/Reality/key не проверялись"
        # Уведомляем только если список изменился с прошлого раза.
        if ! cmp -s "${_cpr_state}.now" "$_cpr_state" 2>/dev/null; then
            pin_notify "⚠️ ${_cpr_bad}; проверен только TCP endpoint с роутера; TLS/SNI/Reality/ключ не проверялись." warn
            cp -f "${_cpr_state}.now" "$_cpr_state" 2>/dev/null || true
        fi
    else
        # Всё доступно: если раньше были сбои — сообщаем о восстановлении.
        if [ -s "$_cpr_state" ]; then
            pin_notify "✅ Серверы обхода снова доступны." ok
            rm -f "$_cpr_state"
        fi
    fi
    rm -f "${_cpr_state}.now"
    return 0
}

update_pinned_hosts() {
    [ "$PIN_ENABLED" = "1" ] || return 0

    _pin_body=""
    # Trojan включён в пиннинг на тех же основаниях, что xray и hysteria:
    # его remote_addr задан доменом, а стартует он как S22 — раньше
    # S56dnsmasq, то есть на момент запуска локального резолвера ещё нет.
    for _pin_host in "$(xray_server_host)" "$(hysteria_server_host)" \
        "$(trojan_server_host)"; do
        [ -n "$_pin_host" ] || continue
        # Адрес уже задан IP — пиннинг не нужен, это идеальный случай.
        is_ip "$_pin_host" && continue
        is_domain_core "$_pin_host" || continue

        if _pin_ips="$(resolve_pin_host "$_pin_host")"; then
            for _pin_ip in $_pin_ips; do
                _pin_body="${_pin_body}${_pin_ip}	${_pin_host}
"
            done
        else
            # Домен не разрешился — переносим его ПРЕЖНИЙ закреплённый
            # адрес в новую секцию. Без этого пин терялся: секция
            # переписывается целиком, и выживали только те домены,
            # которые удалось разрешить прямо сейчас. Защита ниже
            # ("_pin_body пуст — не трогаем") срабатывала лишь когда не
            # разрешился НИ ОДИН домен. В журнале это выглядело так:
            # два домена из трёх не разрешились, третий разрешился — и
            # dnsmasq прочитал "/opt/etc/hosts - 1 names" вместо трёх.
            # Туннели к потерянным серверам остались без адреса, хотя
            # рабочие IP были известны с прошлого запуска.
            # "|| true" обязателен: скрипт работает под set -e, а
            # pinned_hosts_lookup возвращает 1, когда прежнего адреса
            # нет (нет файла hosts или домен в секции не найден).
            # Без этого присваивание из $(...) обрывало ВЕСЬ скрипт —
            # проверено запуском: unblock_dnsmasq.sh завершался с rc=1
            # сразу после первого неразрешённого домена, не создав ни
            # unblock.dnsmasq, ни секции пина.
            _pin_old="$(pinned_hosts_lookup "$_pin_host" || true)"
            if [ -n "$_pin_old" ]; then
                for _pin_ip in $_pin_old; do
                    _pin_body="${_pin_body}${_pin_ip}	${_pin_host}
"
                done
                logger -t "unblock_dnsmasq" \
                    "pin: $_pin_host не разрешён, оставлен прежний адрес"
            else
                logger -t "unblock_dnsmasq" \
                    "pin: не удалось разрешить $_pin_host, прежнего адреса нет"
            fi
        fi
    done

    # Разрешить не удалось — прежний пин НЕ трогаем: устаревший адрес
    # полезнее пустого.
    [ -n "$_pin_body" ] || return 0

    # Проверяем каждый закреплённый адрес TCP-коннектом. Эта проверка
    # сообщает только о недоступности IP:порт с самого роутера и не делает
    # вывод о ключе, TLS/SNI или Reality. Актуальность DNS проверяется выше
    # при построении _pin_body и не подменяется старым pin при успешном
    # bootstrap-ответе.
    check_pinned_reachable "$_pin_body"

    _pin_tmp="$(mktemp /tmp/hosts.XXXXXX)" || return 0

    # Чужие строки сохраняются: вырезается только собственная секция.
    if [ -f "$HOSTS_FILE" ]; then
        awk -v b="$PIN_BEGIN" -v e="$PIN_END" '
            $0 == b { skip = 1; next }
            $0 == e { skip = 0; next }
            !skip
        ' "$HOSTS_FILE" > "$_pin_tmp" 2>/dev/null || : > "$_pin_tmp"
    fi

    # Дубли снимаются: протоколы нередко делят один сервер (например
    # vless и trojan на общем домене), и тогда одна и та же пара
    # "IP<TAB>домен" попала бы в hosts несколько раз. Для dnsmasq это не
    # ошибка, но файл растёт и путает при чтении. sort -u не подходит:
    # он изменил бы порядок, а awk сохраняет первое вхождение.
    printf '%s\n' "$PIN_BEGIN" >> "$_pin_tmp"
    printf '%s' "$_pin_body" | awk '!seen[$0]++' >> "$_pin_tmp"
    printf '%s\n' "$PIN_END" >> "$_pin_tmp"

    # dnsmasq работает под nobody и молча перестанет читать файл,
    # если права окажутся строже 0644.
    chmod 0644 "$_pin_tmp" 2>/dev/null || true
    mv -f "$_pin_tmp" "$HOSTS_FILE"

    # Логируем только смену набора адресов, а не каждый запуск.
    _pin_sig="$(printf '%s' "$_pin_body" | md5sum 2>/dev/null | awk '{print $1}')"
    _pin_prev=""
    [ -f /tmp/keenzoo_pin.sig ] && _pin_prev="$(cat /tmp/keenzoo_pin.sig 2>/dev/null)"
    if [ "$_pin_sig" != "$_pin_prev" ]; then
        logger -t "unblock_dnsmasq" \
            "pin: $(printf '%s' "$_pin_body" | tr '\n' ' ')"
        printf '%s\n' "$_pin_sig" > /tmp/keenzoo_pin.sig 2>/dev/null || true
    fi
}

update_ndm_bootstrap_hosts
update_pinned_hosts

# Cold-start bootstrap мог только сейчас записать NDM/Proxy pins.
# Повторяем выбор tunnel-DNS после их появления, иначе первый запуск
# остановился бы на DNS_UNAVAILABLE и ждал бы следующего cron-цикла.
if [ -z "$DNS_SECURE_PORTS" ] && [ "$DNS_TUNNEL_READY" -eq 0 ]; then
    if try_tunnel_dns; then
        DNS_MODE="TUNNEL_DNS"
        DNS_PRIMARY_LEVEL="TUNNEL_DNS"
        update_dnsmasq_upstreams
        logger -t "unblock_dnsmasq" \
            "DNS tunnel activated after pins: protocol=$DNS_TUNNEL_PROTOCOL primary=$DNS_PRIMARY"
    fi
fi

# Проверяем, есть ли для домена или его родительской зоны уже
# заданный пользователем server=/zone/... в основном dnsmasq.conf.
# Такие правила имеют собственный порядок и не должны быть затёрты
# автоматически сгенерированными local DoT/DoH-портами.
dnsmasq_resource_server() {
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
            n = split(line, zones, "/")
            for (i = 1; i < n; i++) {
                if (zones[i] != "" && covered(zones[i])) {
                    found = 1
                    exit
                }
            }
        }
        END { exit(found ? 0 : 1) }
    ' "$DNSMASQ_CONF" 2>/dev/null
}

append_domain_rules() {
    _host="$1"
    _setname="$2"
    _dns_port="$3"

    # Одно правило ipset на домен: dnsmasq сам распространяет его на
    # поддомены. Все рабочие local DoT/DoH порты записываются в порядке
    # приоритета, если для ресурса нет более специфичного server=/zone/...
    # в основном dnsmasq.conf.
    printf 'ipset=/%s/%s\n' "$_host" "$_setname" >> "$TMP_OUT"
    if dnsmasq_resource_server "$_host" >/dev/null 2>&1; then
        logger -t "unblock_dnsmasq" \
            "DNS resource rule preserved: $_host from $DNSMASQ_CONF"
        return 0
    fi
    if [ "$_dns_port" = "9053" ]; then
        printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_dns_port" >> "$TMP_OUT"
    else
        for _adr_port in "$_dns_port" $DNS_BACKUP_PORTS; do
            [ -n "$_adr_port" ] || continue
            printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_adr_port" >> "$TMP_OUT"
        done
    fi
}

process_dnsmasq_list() {
    _file="$1"
    _setname="$2"
    _dns_port="$3"

    [ -f "$_file" ] || return 0

    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line="$(trim_comment "$raw_line")"
        [ -n "$line" ] || continue

        # Голые IP резолвить не нужно — их кладёт в ipset unblock_ipset.sh.
        if is_ip "$line"; then
            continue
        fi

        if is_cidr "$line"; then
            printf 'add %s %s\n' "$_setname" "$line" >> "$TMP_CIDR"
            continue
        fi

        # Диапазоны вида a.b.c.d-e.f.g.h тоже обрабатывает ipset-скрипт.
        case "$line" in
            *[0-9]-[0-9]*)
                if printf '%s' "$line" | grep -qE '^[0-9.]+-[0-9.]+$'; then
                    continue
                fi
                ;;
        esac

        _host="$(normalize_domain_mode "$line" 2>/dev/null || true)"
        if [ -z "$_host" ]; then
            logger -t "unblock_dnsmasq" "skip invalid entry: $line"
            continue
        fi

        append_domain_rules "$_host" "$_setname" "$_dns_port"
    done < "$_file"
}

# Протокол считается выключенным, если в его init-скрипте стоит
# ENABLED=no (ползунок в веб-панели). Для такого протокола список
# в конфиг dnsmasq НЕ попадает.
#
# Особенно важно для Tor: его доменам назначается собственный
# DNS-порт 9053, и при остановленном Tor туда никто не отвечает.
# dnsmasq продолжает слать запросы на мёртвый порт, ждёт таймаут и
# повторяет — очередь забивается, а домены ДРУГИХ протоколов
# перестают резолвиться вовремя и уходят напрямую мимо туннеля.
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

# Список обрабатывается только если протокол включён.
process_if_enabled() {
    _init="$1"
    _file="$2"
    _set="$3"
    _port="$4"

    if svc_enabled "$_init"; then
        process_dnsmasq_list "$_file" "$_set" "$_port"
    else
        logger -t "unblock_dnsmasq" \
            "skip $_set: протокол отключён"
    fi
}

process_if_enabled /opt/etc/init.d/S65shadowsocks \
    /opt/etc/unblock/shadowsocks.txt unblocksh "$DNS_PRIMARY"
process_if_enabled /opt/etc/init.d/S35tor \
    /opt/etc/unblock/tor.txt unblocktor 9053
process_if_enabled /opt/etc/init.d/S24xray \
    /opt/etc/unblock/vless.txt unblockvless "$DNS_PRIMARY"
process_if_enabled /opt/etc/init.d/S22trojan \
    /opt/etc/unblock/trojan.txt unblocktroj "$DNS_PRIMARY"
process_if_enabled /opt/etc/init.d/S57hysteria \
    /opt/etc/unblock/hysteria.txt unblockhysteria "$DNS_PRIMARY"
process_dnsmasq_list /opt/etc/unblock/bot.txt unblockrouter "$DNS_PRIMARY"

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    process_dnsmasq_list "$vpn_file_names" "$unblockvpn" "$DNS_PRIMARY"
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
exit 0

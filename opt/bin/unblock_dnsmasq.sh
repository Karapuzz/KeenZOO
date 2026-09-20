#!/bin/sh
# remove keeps data but disables cron/NDM reactivation until next install.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# A BusyBox executable does NOT imply that its timeout applet is compiled in.
# 125 = no usable deadline runner; 124 = deadline; 126/127 = not executed.
run_bounded() {
    _rb_seconds="$1"
    shift
    if command -v python3 >/dev/null 2>&1; then
    python3 - "$_rb_seconds" "$@" <<'PY_DEADLINE'
import os
import signal
import subprocess
import sys

proc = None

def stop_group():
    if proc is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass

def interrupted(sig, frame):
    raise SystemExit(128 + sig)

for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, interrupted)
try:
    proc = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        rc = proc.wait(timeout=float(sys.argv[1]))
    except subprocess.TimeoutExpired:
        rc = 124
except OSError as exc:
    rc = 127 if isinstance(exc, FileNotFoundError) else 126
finally:
    stop_group()
sys.exit(rc if rc >= 0 else 128 - rc)
PY_DEADLINE
        return $?
    fi
    # Early bootstrap may not have Python yet. Require a working kill-after
    # option rather than trusting either a symlink or a BusyBox version.
    if command -v timeout >/dev/null 2>&1 \
        && timeout -k 1 1 /bin/sh -c ':' >/dev/null 2>&1; then
        timeout -k 1 "$_rb_seconds" "$@"
        return $?
    fi
    if command -v busybox >/dev/null 2>&1 \
        && busybox timeout -k 1 1 /bin/sh -c ':' >/dev/null 2>&1; then
        busybox timeout -k 1 "$_rb_seconds" "$@"
        return $?
    fi
    return 125
}

# Keep runtime port lists in step with the existing deploy configuration.
# Parsing is intentionally simple and BusyBox-compatible; missing values keep
# the known Keenetic defaults.
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

PORT_SS="${PORT_SS:-$(config_number localportsh 1082)}"
PORT_TOR="${PORT_TOR:-$(config_number localporttor 9141)}"
PORT_VLESS="${PORT_VLESS:-$(config_number localportvless 10810)}"
PORT_TROJAN="${PORT_TROJAN:-$(config_number localporttrojan 10829)}"
PORT_HYSTERIA="${PORT_HYSTERIA:-$(config_number localporthysteria 10830)}"
config_list() {
    _cl_key="$1"
    _cl_default="$2"
    _cl_value="$(sed -n \
        "s/^[[:space:]]*${_cl_key}[[:space:]]*=[[:space:]]*\\[\\(.*\\)\\].*$/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | tr ',' ' ' | tr -cd '0-9 ' | sed 's/[[:space:]][[:space:]]*/ /g')"
    [ -n "$_cl_value" ] || _cl_value="$_cl_default"
    printf '%s\n' "$_cl_value"
}


config_words() {
    _cw_key="$1"
    _cw_default="$2"
    _cw_value="$(sed -n \
        "s/^[[:space:]]*${_cw_key}[[:space:]]*=[[:space:]]*\\[\\(.*\\)\\].*$/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null \
        | tr -d "'\"" | tr ',' ' ' | tr -s ' ' | sed 's/^ //;s/ $//')"
    [ -n "$_cw_value" ] || _cw_value="$_cw_default"
    printf '%s\n' "$_cw_value"
}

# Keep the protocol fallback order in the install-time Python configuration;
# every shell decision layer consumes this same ordered contract.
TUNNEL_PROTOCOL_PRIORITY="$(config_words tunnel_protocol_priority 'hysteria xray trojan')"

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

config_bool() {
    _cb_key="$1"
    _cb_default="$2"
    _cb_value="$(sed -n \
        -e "s/^[[:space:]]*${_cb_key}[[:space:]]*=[[:space:]]*True.*$/1/p" \
        -e "s/^[[:space:]]*${_cb_key}[[:space:]]*=[[:space:]]*False.*$/0/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    [ "$_cb_value" = "0" ] || [ "$_cb_value" = "1" ] || _cb_value="$_cb_default"
    printf '%s\n' "$_cb_value"
}
OUT_FILE="/opt/etc/unblock.dnsmasq"
CIDR_FILE="/opt/etc/unblock.dnsmasq.cidr"
# Existing lifecycle/event handlers use this mode to refresh the canonical DNS
# decision without rebuilding every resource list. No new daemon or state file
# is introduced.
DNS_HEALTH_ONLY="${DNS_HEALTH_ONLY:-0}"


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

DNSMASQ_CONF="/opt/etc/dnsmasq.conf"
DNS_UPSTREAM_BEGIN="# BEGIN KeenZOO managed DNS upstreams"
DNS_UPSTREAM_END="# END KeenZOO managed DNS upstreams"
DNSMASQ_IF_BEGIN="# BEGIN KeenZOO dynamic client interfaces"
DNSMASQ_IF_END="# END KeenZOO dynamic client interfaces"
DNSMASQ_LISTEN_BEGIN="# BEGIN KeenZOO dynamic listen addresses"
DNSMASQ_LISTEN_END="# END KeenZOO dynamic listen addresses"
DNSMASQ_DOMAIN_BEGIN="# BEGIN KeenZOO dynamic local domain"
DNSMASQ_DOMAIN_END="# END KeenZOO dynamic local domain"
IPSET_SUFFIX="${IPSET_SUFFIX:-}"

# All mutating DNS refreshes share the update lock. unblock_update.sh owns
# it for the full transaction; a direct WAN-hook/manual invocation acquires
# it here. This prevents concurrent writes without a new daemon.
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
        if [ "$_kz_lock_tries" -ge 60 ]; then
            logger -t "unblock_dnsmasq" "refresh deferred: update lock is busy" 2>/dev/null || true
            exit 75
        fi
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

TMP_OUT="$(mktemp /tmp/unblock.dnsmasq.XXXXXX)"
TMP_CIDR="$(mktemp /tmp/unblock.dnsmasq.cidr.XXXXXX)"

DNS_CONFIG_BACKUP=''
DNS_TX_READY=0
DNS_TX_DONE=0
cleanup() {
    _dns_exit_rc="${1:-$?}"
    if [ "$_dns_exit_rc" -ne 0 ] && [ "$DNS_TX_DONE" -eq 0 ]; then
        if [ "$DNS_TX_READY" -eq 1 ]; then
            for _dcr_name in main domains cidr; do
                case "$_dcr_name" in
                    main) _dcr_file="$DNSMASQ_CONF" ;;
                    domains) _dcr_file="$OUT_FILE" ;;
                    cidr) _dcr_file="$CIDR_FILE" ;;
                esac
                if [ -f "$DNS_CONFIG_BACKUP/$_dcr_name" ]; then
                    cp -p "$DNS_CONFIG_BACKUP/$_dcr_name" "${_dcr_file}.rollback.$$" \
                        && mv -f "${_dcr_file}.rollback.$$" "$_dcr_file" \
                        || logger -t unblock_dnsmasq "DNS file rollback failed: $_dcr_file"
                else
                    rm -f "$_dcr_file"
                fi
            done
            # This only restores the DNS files/listener; the parent update owns
            # ipset/netfilter rollback when invoked as a staged child.
            if [ "${KEENZOO_SKIP_DNSMASQ_RELOAD:-0}" != 1 ] \
                && [ -x /opt/etc/init.d/S56dnsmasq ]; then
                /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1 || true
            fi
        fi
        if command -v publish_dns_failure >/dev/null 2>&1; then
            publish_dns_failure || true
        fi
    fi
    [ -z "$DNS_CONFIG_BACKUP" ] || rm -rf "$DNS_CONFIG_BACKUP"
    rm -f "$TMP_OUT" "$TMP_CIDR" "${TMP_OUT}.sorted" "${TMP_CIDR}.sorted" \
        "${DNSMASQ_CONF}.upstream.$$" "${DNSMASQ_CONF}.tmp.$$" \
        "${OUT_FILE}.upstreams.$$"
    if [ "$LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$KEENZOO_LOCK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

DNS_CONFIG_BACKUP="$(mktemp -d /tmp/keenzoo.dns-config.XXXXXX)"
chmod 700 "$DNS_CONFIG_BACKUP"
for _dcb_pair in main domains cidr; do
    case "$_dcb_pair" in
        main) _dcb_file="$DNSMASQ_CONF" ;;
        domains) _dcb_file="$OUT_FILE" ;;
        cidr) _dcb_file="$CIDR_FILE" ;;
    esac
    [ ! -f "$_dcb_file" ] || cp -p "$_dcb_file" "$DNS_CONFIG_BACKUP/$_dcb_pair"
done
DNS_TX_READY=1

: > "$TMP_OUT"
: > "$TMP_CIDR"

# Обновляем управляемый блок В СУЩЕСТВУЮЩЕМ dnsmasq.conf.
# В Keenetic логическое имя NDM Wireguard0 соответствует kernel-имени
# nwg0; отсутствующий nwg1 нельзя держать статической строкой — dnsmasq
# печатает warning при каждом старте. Если nwg1 появится позже, следующий
# запуск обновления добавит его в этот же блок.
update_dynamic_interfaces() {
    [ -f "$DNSMASQ_CONF" ] || return 0

    # The same discovery policy is used by 100-redirect.sh: configured
    # client interfaces first, then currently existing LAN/WireGuard devices.
    # WAN names are deliberately not discovered by this pattern.
    _udi_ifaces="lo"
    # Address-carrying interfaces only: dnsmasq binds by address, so an
    # interface without one (driver-created VAPs ra1..ra14 on KN-1012)
    # would only trigger "interface X does not currently exist" warnings at
    # every dnsmasq start. A new interface enters the list as soon as it
    # receives an address (this function re-runs on every DNS refresh).
    # Some firmware ip variants return success even when a name filter is
    # ignored. Match exact names in one dump, not the command exit status.
    _udi_links="$(ip -o -4 addr show 2>/dev/null | awk '{print $2}' \
        | sed 's/@.*//' | tr '\n' ' ')"
    _udi_add_if() {
        [ -n "$1" ] || return 0
        case " $_udi_links " in *" $1 "*) ;; *) return 0 ;; esac
        case " $_udi_ifaces " in
            *" $1 "*) ;;
            *) _udi_ifaces="${_udi_ifaces} $1" ;;
        esac
    }
    _udi_cfg="$(sed -n \
        "s/^[[:space:]]*lan_ifaces[[:space:]]*=[[:space:]]*\\[\\(.*\\)\\]/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | tr -d "'\"" | tr ',' ' ' || true)"
    for _udi_if in $_udi_cfg; do _udi_add_if "$_udi_if"; done
    for _udi_if in $(ip -o -4 addr show 2>/dev/null \
        | awk '{print $2}' | sed 's/@.*//' \
        | grep -E '^(br|nwg|wg|wlan|wl|ra|guest)[A-Za-z0-9_.-]*$' || true); do
        _udi_add_if "$_udi_if"
    done

    # Prefer configured routerip only when it is actually assigned. Otherwise
    # use the first private address on a discovered client interface.
    _udi_router="${ROUTER_IP:-}"
    if [ -z "$_udi_router" ]; then
        _udi_router="$(sed -n \
            "s/^[[:space:]]*routerip[[:space:]]*=[[:space:]]*'\\([^']*\\)'.*/\\1/p" \
            /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    fi
    _udi_local=""
    if [ -n "$_udi_router" ] && ip -4 addr show 2>/dev/null \
        | grep -q "[[:space:]]$_udi_router/"; then
        _udi_local="$_udi_router"
    else
        for _udi_if in $_udi_ifaces; do
            [ "$_udi_if" = lo ] && continue
            _udi_local="$(ip -4 addr show "$_udi_if" 2>/dev/null \
                | awk '/inet /{print $2; exit}' | cut -d/ -f1)"
            [ -n "$_udi_local" ] && break
        done
    fi

    _udi_listen="listen-address=127.0.0.1"
    [ -n "$_udi_local" ] && _udi_listen="$_udi_listen|listen-address=$_udi_local"
    _udi_if_lines=""
    for _udi_if in $_udi_ifaces; do
        _udi_if_lines="${_udi_if_lines}${_udi_if_lines:+|}interface=$_udi_if"
    done

    # Derive a local network for dnsmasq's local domain from the actual
    # interface prefix. This removes the old 192.168.1.0/24 assumption.
    _udi_domain=""
    for _udi_if in $_udi_ifaces; do
        [ "$_udi_if" = lo ] && continue
        _udi_cidr="$(ip -4 addr show "$_udi_if" 2>/dev/null \
            | awk '/inet /{print $2; exit}')"
        [ -n "$_udi_cidr" ] || continue
        _udi_domain="$(printf '%s\n' "$_udi_cidr" | awk -F'[./]' '
            function ip2int(a,b,c,d){return (((a*256+b)*256+c)*256+d)}
            function oct(v){return int(v/256)}
            {
                ip=ip2int($1,$2,$3,$4); p=$5+0
                if (p < 0 || p > 32) exit 1
                block=2^(32-p); n=int(ip/block)*block
                a=int(n/16777216); n-=a*16777216
                b=int(n/65536); n-=b*65536
                c=int(n/256); d=n-c*256
                printf "%d.%d.%d.%d/%d", a,b,c,d,p
            }')"
        [ -n "$_udi_domain" ] && break
    done
    [ -n "$_udi_domain" ] || _udi_domain="192.168.1.0/24"

    _udi_tmp="${DNSMASQ_CONF}.tmp.$$"
    awk -v ib="$DNSMASQ_IF_BEGIN" -v ie="$DNSMASQ_IF_END" \
        -v lb="$DNSMASQ_LISTEN_BEGIN" -v le="$DNSMASQ_LISTEN_END" \
        -v db="$DNSMASQ_DOMAIN_BEGIN" -v de="$DNSMASQ_DOMAIN_END" \
        -v ifaces="$_udi_if_lines" -v listen="$_udi_listen" \
        -v domain="domain=local,$_udi_domain" '
        function emit_block(b,e,text,  n,a,i) {
            print b
            n = split(text,a,"|")
            for (i=1; i<=n; i++) if (a[i] != "") print a[i]
            print e
        }
        $0 == ib { skip=1; if (!seen_i) { emit_block(ib,ie,ifaces,0); seen_i=1 }; next }
        $0 == ie { skip=0; next }
        $0 == lb { skip=1; if (!seen_l) { emit_block(lb,le,listen,0); seen_l=1 }; next }
        $0 == le { skip=0; next }
        $0 == db { skip=1; if (!seen_d) { emit_block(db,de,domain,0); seen_d=1 }; next }
        $0 == de { skip=0; next }
        !skip { print }
        END {
            if (!seen_i) emit_block(ib,ie,ifaces,0)
            if (!seen_l) emit_block(lb,le,listen,0)
            if (!seen_d) emit_block(db,de,domain,0)
        }
    ' "$DNSMASQ_CONF" > "$_udi_tmp"
    chmod 0644 "$_udi_tmp" 2>/dev/null || true
    mv -f "$_udi_tmp" "$DNSMASQ_CONF"
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
            if (a == 192 && b == 0 && ($3 == 0 || $3 == 2)) bad=1
            if (a == 198 && b == 51 && $3 == 100) bad=1
            if (a == 203 && b == 0 && $3 == 113) bad=1
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
clear_tunnel_dns_set() {
    # The DNS owner clears stale endpoint addresses whenever no verified
    # tunnel-DNS decision survives. Otherwise a later generic netfilter hook
    # could accidentally revive an old redirect.
    ipset flush "$DNS_TUNNEL_SET" 2>/dev/null || true
    ipset flush "${DNS_TUNNEL_SET}_new" 2>/dev/null || true
}

remove_dns_tunnel_set_refs() {
    [ -n "$IPTABLES_DNS_BIN" ] || return 0
    for _rdts_port in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        for _rdts_remote in 443 853; do
            while "$IPTABLES_DNS_BIN" -w -t nat -D OUTPUT -p tcp \
                --dport "$_rdts_remote" -m set \
                --match-set "$DNS_TUNNEL_SET" dst \
                -j REDIRECT --to-port "$_rdts_port" >/dev/null 2>&1; do :; done
        done
        while "$IPTABLES_DNS_BIN" -w -t nat -D OUTPUT -p tcp \
            -m set --match-set "$DNS_TUNNEL_SET" dst \
            -j REDIRECT --to-port "$_rdts_port" >/dev/null 2>&1; do :; done
    done
}

ensure_dns_tunnel_sets() {
    _edts_stage="$1"
    if ipset create "$DNS_TUNNEL_SET" hash:net family inet \
        hashsize 1024 maxelem 65536 -exist 2>/dev/null \
        && ipset create "$_edts_stage" hash:net family inet \
            hashsize 1024 maxelem 65536 -exist 2>/dev/null; then
        return 0
    fi

    # Older releases used a smaller hash geometry, and some old installs used
    # hash:ip for this name. BusyBox ipset rejects -exist on such a mismatch.
    # Remove only DNS OUTPUT references, recreate both live/staging sets, and
    # let the caller populate them transactionally.
    dns_health_file_log \
        "DNS tunnel ipset incompatible; rebuilding set=$DNS_TUNNEL_SET"
    remove_dns_tunnel_set_refs
    ipset flush "$DNS_TUNNEL_SET" 2>/dev/null || true
    ipset flush "$_edts_stage" 2>/dev/null || true
    ipset destroy "$_edts_stage" 2>/dev/null || true
    ipset destroy "$DNS_TUNNEL_SET" 2>/dev/null || true
    ipset create "$DNS_TUNNEL_SET" hash:net family inet \
        hashsize 1024 maxelem 65536 -exist 2>/dev/null || return 1
    ipset create "$_edts_stage" hash:net family inet \
        hashsize 1024 maxelem 65536 -exist 2>/dev/null
}
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
# DNS-through-tunnel endpoint names and NDM bootstrap names are separate
# contracts. Both are hostnames only; their current IPs come from /opt/etc/hosts.
TUNNEL_DOH_HOSTS="${TUNNEL_DOH_HOSTS:-$(config_words tunnel_doh_hosts 'dns.google cloudflare-dns.com dns11.quad9.net')}"
DNS_ENDPOINT_HOSTS="${DNS_ENDPOINT_HOSTS:-$TUNNEL_DOH_HOSTS}"
HOSTS_FILE="${HOSTS_FILE:-/opt/etc/hosts}"
NDM_PIN_BEGIN="# --- KeenZOO NDM bootstrap (управляется проектом) ---"
NDM_PIN_END="# --- end KeenZOO NDM bootstrap ---"
DNS_TUNNEL_PROTOCOL="${DNS_TUNNEL_PROTOCOL:-}"

# Обязательные кэшируемые параметры задаются до health-check: функции
# ниже вызываются до генерации dnsmasq и используют только shell-переменные.
PIN_BEGIN="# --- KeenZOO pinned (не редактировать вручную) ---"
PIN_END="# --- end KeenZOO pinned ---"
PIN_ENABLED="${PIN_ENABLED:-$(config_bool pin_server_hosts 1)}"
# Pin age is a shared policy from bot_config.py. It must be initialized
# before tunnel_dns_prepare can consume NDM pins during cold start.
PIN_MAX_AGE="${PIN_MAX_AGE:-$(config_number pin_max_age 604800)}"
PIN_HARD_MAX_AGE="${PIN_HARD_MAX_AGE:-$(config_number pin_hard_max_age 2592000)}"
case "$PIN_MAX_AGE" in ''|*[!0-9]*) PIN_MAX_AGE=604800 ;; esac
case "$PIN_HARD_MAX_AGE" in ''|*[!0-9]*) PIN_HARD_MAX_AGE=2592000 ;; esac
[ "$PIN_HARD_MAX_AGE" -ge "$PIN_MAX_AGE" ] || PIN_HARD_MAX_AGE="$PIN_MAX_AGE"
NDM_ENDPOINT_HOSTS="${NDM_ENDPOINT_HOSTS:-$(config_words dns_endpoint_hosts 'dns11.quad9.net dns.google cloudflare-dns.com opennic1.eth-services.de opennic2.eth-services.de')}"
BOOTSTRAP_RESOLVERS="${BOOTSTRAP_RESOLVERS:-$(config_words bootstrap_resolvers '9.9.9.9 8.8.8.8 1.1.1.1')}"

managed_section_age() {
    _msa_begin="$1"
    _msa_end="$2"
    _msa_epoch="$(awk -v b="$_msa_begin" -v e="$_msa_end" '
        $0 == b { inside=1; next }
        $0 == e { inside=0 }
        inside && $0 ~ /^# generated-at=[0-9]+$/ {
            sub(/^# generated-at=/, "")
            print
            exit
        }
    ' "$HOSTS_FILE" 2>/dev/null | head -1)"
    case "$_msa_epoch" in
        ''|*[!0-9]*)
            # Legacy installs have no metadata. Use the mtime of the same
            # hosts file as a conservative migration timestamp.
            _msa_epoch="$(stat -c %Y "$HOSTS_FILE" 2>/dev/null || echo 0)"
            ;;
    esac
    _msa_now="$(date +%s 2>/dev/null || echo 0)"
    case "$_msa_epoch:$_msa_now" in *[!0-9:]*|0:*) return 1 ;; esac
    [ $((_msa_now - _msa_epoch)) -ge 0 ] || return 1
    printf '%s\n' $((_msa_now - _msa_epoch))
}

managed_section_usable() {
    _msu_age="$(managed_section_age "$1" "$2" || true)"
    case "$_msu_age" in ''|*[!0-9]*) return 1 ;; esac
    if [ "$_msu_age" -gt "$PIN_HARD_MAX_AGE" ]; then
        logger -t "unblock_dnsmasq" \
            "pin section expired age=${_msu_age}s begin=$1"
        return 1
    fi
    if [ "$_msu_age" -gt "$PIN_MAX_AGE" ]; then
        logger -t "unblock_dnsmasq" \
            "pin section stale age=${_msu_age}s begin=$1; retained only as recovery"
    fi
    return 0
}

ndm_pinned_lookup() {
    _nplh="$1"
    [ -f "$HOSTS_FILE" ] || return 1
    managed_section_usable "$NDM_PIN_BEGIN" "$NDM_PIN_END" || return 1
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

tunnel_protocol_intended() {
    _tpi_proto="$1"
    set -- $(tunnel_protocol_init "$_tpi_proto") || return 1
    _tpi_init="$1"
    _tpi_proc="$2"
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_tpi_init" 2>/dev/null && return 1
    pidof "$_tpi_proc" >/dev/null 2>&1
}

required_tunnel_protocol() {
    # Only a process with its real local listener can make direct DNS unsafe.
    # The old process-only test treated a stale/failed xray or trojan PID as
    # an active tunnel, discarded healthy local DNSSEC listeners and produced
    # DNS_UNAVAILABLE after reboot. A listener check also matches the service
    # readiness contract used by the init scripts and web panel.
    for _rtp in $TUNNEL_PROTOCOL_PRIORITY; do
        tunnel_protocol_active "$_rtp" || continue
        printf '%s\n' "$_rtp"
        return 0
    done
    return 1
}

active_tunnel_protocol() {
    for _atp in $TUNNEL_PROTOCOL_PRIORITY; do
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
    # Keep the init result and stderr visible in the bounded DNS log. rc.func
    # normally redirects the child stderr to /dev/null, which hid the reason
    # Hysteria exited during reboot and made fallback diagnosis impossible.
    _stp_diag="$(mktemp /tmp/keenzoo.tunnel.start.XXXXXX 2>/dev/null || true)"
    if [ -n "$_stp_diag" ]; then
        "$_stp_init" start >"$_stp_diag" 2>&1 || true
        _stp_text="$(tail -12 "$_stp_diag" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g')"
        [ -n "$_stp_text" ] && dns_health_file_log \
            "tunnel start proto=$_stp_proto output=$_stp_text"
        rm -f "$_stp_diag"
    else
        "$_stp_init" start >/dev/null 2>&1 || true
    fi
    _stp_wait=0
    while [ "$_stp_wait" -lt 15 ]; do
        tunnel_protocol_active "$_stp_proto" && return 0
        sleep 1
        _stp_wait=$((_stp_wait + 1))
    done
    return 1
}

# При отказе локального DNS пытаемся поднять tunnel service с помощью
# старого pin из /opt/etc/hosts. Проверка и запуск идут строго в порядке
# Xray/VLESS -> Trojan -> Hysteria.
ensure_active_tunnel_protocol() {
    _eatp="$(active_tunnel_protocol || true)"
    [ -n "$_eatp" ] && { printf '%s\n' "$_eatp"; return 0; }
    for _eatp in $TUNNEL_PROTOCOL_PRIORITY; do
        start_tunnel_protocol "$_eatp" || continue
        printf '%s\n' "$_eatp"
        return 0
    done
    return 1
}
tunnel_dns_prepare() {
    _tdp_proto="$1"
    _tdp_ips=""
    _tdp_stage="${DNS_TUNNEL_SET}_new"
    ensure_dns_tunnel_sets "$_tdp_stage" || return 1
    ipset flush "$_tdp_stage" 2>/dev/null || return 1

    for _tdp_host in $DNS_ENDPOINT_HOSTS; do
        for _tdp_ip in $(ndm_pinned_lookup "$_tdp_host" || true); do
            is_public_ipv4 "$_tdp_ip" || continue
            ipset add "$_tdp_stage" "$_tdp_ip" -exist 2>/dev/null || return 1
            _tdp_ips="${_tdp_ips}${_tdp_ips:+ }$_tdp_ip"
        done
    done
    [ -n "$_tdp_ips" ] || {
        dns_health_file_log "tunnel prepare proto=$_tdp_proto failed=NO_ENDPOINT_PINS"
        return 1
    }

    ipset swap "$DNS_TUNNEL_SET" "$_tdp_stage" 2>/dev/null || return 1
    if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        for _tdp_table in nat filter; do
            if ! DNS_TUNNEL_PROTOCOL="$_tdp_proto" \
                DNS_TUNNEL_VERIFIED=1 DNS_TUNNEL_BLOCK_RAW_DNS=1 \
                DNS_ONLY=1 type=iptable table="$_tdp_table" \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1; then
                dns_health_file_log "tunnel prepare proto=$_tdp_proto failed=NETFILTER table=$_tdp_table"
                for _tdp_off_table in filter nat; do
                    DNS_TUNNEL_DISABLE=1 DNS_TUNNEL_BLOCK_RAW_DNS=0 \
                        DNS_ONLY=1 type=iptable table="$_tdp_off_table" \
                        /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
                done
                ipset swap "$DNS_TUNNEL_SET" "$_tdp_stage" 2>/dev/null || true
                return 1
            fi
        done
    fi

    _tdp_port="$PORT_VLESS"
    case "$_tdp_proto" in
        trojan) _tdp_port="$PORT_TROJAN" ;;
        hysteria) _tdp_port="$PORT_HYSTERIA" ;;
    esac
    [ -n "$IPTABLES_DNS_BIN" ] || {
        ipset swap "$DNS_TUNNEL_SET" "$_tdp_stage" 2>/dev/null || true
        return 1
    }
    _tdp_rule_ok=0
    for _tdp_remote_port in 443 853; do
        if "$IPTABLES_DNS_BIN" -w -t nat -C OUTPUT -p tcp \
            --dport "$_tdp_remote_port" \
            -m set --match-set "$DNS_TUNNEL_SET" dst \
            -j REDIRECT --to-port "$_tdp_port" >/dev/null 2>&1; then
            _tdp_rule_ok=$((_tdp_rule_ok + 1))
        fi
    done
    if [ "$_tdp_rule_ok" -ne 2 ]; then
        dns_health_file_log "tunnel prepare proto=$_tdp_proto failed=REDIRECT_NOT_INSTALLED"
        ipset swap "$DNS_TUNNEL_SET" "$_tdp_stage" 2>/dev/null || true
        return 1
    fi
    ipset flush "$_tdp_stage" 2>/dev/null || true
    return 0
}

prepare_tunnel_dns() {
    _ptd_seen=""
    _ptd_order="${DNS_TUNNEL_PROTOCOL:-} $TUNNEL_PROTOCOL_PRIORITY"
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

DNS_PORTS_DOT="${DNS_PORTS_DOT:-$(config_list dnsovertls_ports "40500 40501 40502 40503")}"
DNS_PORTS_DOH="${DNS_PORTS_DOH:-$(config_list dnsoverhttps_ports "40508 40509 40510 40511")}"
# Контрольная зона должна быть стабильной и DNSSEC-подписанной, но не
# зависеть от доступности заблокированных в России ресурсов. torproject.org
# здесь намеренно не используется: его блокировка дала бы ложный отказ DNS.
DNS_HEALTH_DOMAIN="${DNS_HEALTH_DOMAIN:-$(config_string dns_health_domain example.com)}"
# Health decision log is deliberately bounded. Detailed per-port messages
# still go to syslog; this file keeps only compact rankings and decisions.
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-$(config_string dns_health_log /opt/var/log/unblock_dns_health.log)}"
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
    for _dhp_attempt in 1 2; do
        _dhp_out="$(dig -4 +dnssec +noall +comments +answer +stats \
            +time=2 +tries=1 "$DNS_HEALTH_DOMAIN" A \
            @127.0.0.1 -p "$_dhp_port" 2>/dev/null || true)"
        _dhp_status="$(printf '%s\n' "$_dhp_out" \
            | sed -n 's/.*status:[[:space:]]*\([^,;]*\).*/\1/p' | head -1)"
        [ "$_dhp_status" != NOERROR ] || break
    done
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
    # AA is orthogonal to DNSSEC: only AD distinguishes validated answers.
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
    _dhl_epoch="$(date +%s 2>/dev/null || echo 0)"
    # A truncated previous write must not concatenate with the next epoch.
    if [ -s "$DNS_HEALTH_LOG" ] && [ -n "$(tail -c 1 "$DNS_HEALTH_LOG" 2>/dev/null)" ]; then
        printf '\n' >> "$DNS_HEALTH_LOG" || return 1
    fi
    printf '%s unblock_dnsmasq epoch=%s %s\n' "$_dhl_now" "$_dhl_epoch" "$*" \
        >> "$DNS_HEALTH_LOG" 2>/dev/null || return 1
    dns_health_log_rotate
}

DNS_METRICS_FILE="$(mktemp /tmp/unblock.dns.metrics.XXXXXX)"
cleanup_dns_metrics() {
    _cdm_rc=$?
    cleanup "$_cdm_rc"
    rm -f "$DNS_METRICS_FILE" "${DNS_METRICS_FILE}.ranked" "${DNS_METRICS_FILE}.remaining" "${DNS_METRICS_FILE}.next"
    return "$_cdm_rc"
}
trap cleanup_dns_metrics EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

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

# v4 delegates ONLY resolver selection/forwarding to the bounded controller.
# All existing domain/ipset/interface/pin generation stays in this owner.
DNS_POLICY_V4=1
v4_load_dns() {
    _v4_state="$(python3 /opt/etc/bot/utils.py --dns-shell)" || return 1
    eval "$_v4_state"
}
v4_start_dns() {
    for _v4_table in filter nat; do
        DNS_ONLY=1 type=iptable table="$_v4_table" \
            /opt/etc/ndm/netfilter.d/100-redirect.sh || return 1
    done
    python3 /opt/etc/bot/utils.py --dns-start || return 1
    _v4_wait=0
    while [ "$_v4_wait" -lt 60 ]; do
        v4_load_dns || return 1
        [ "$DNS_MODE" != DNS_UNAVAILABLE ] && return 0
        sleep 1
        _v4_wait=$((_v4_wait + 1))
    done
    # Keep the controller alive for cold-start pins and subsequent recovery.
    return 0
}
DNS_SECURE_PORTS=""
DNS_INSECURE_PORTS=""
DNS_WORKING_PORTS=""
DNS_PRIMARY=""
DNS_BACKUP_PORTS=""
DNS_PRIMARY_RTT_MS=""
DNS_RANKING=""
v4_start_dns
DNS_INITIAL_SECURE_PORTS="$DNS_SECURE_PORTS"
# Keep the pre-tunnel DNSSEC listeners available for one narrowly-scoped
# cold-start operation: resolving only proxy/DNS endpoint names needed to
# create fresh pins. They are never published as dnsmasq upstreams while a
# tunnel is required, and no ordinary hostname may use this escape hatch.
DNS_BOOTSTRAP_SECURE_PORTS="$DNS_INITIAL_SECURE_PORTS"
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
    for _tt_proto in $TUNNEL_PROTOCOL_PRIORITY; do
        tunnel_protocol_active "$_tt_proto" || start_tunnel_protocol "$_tt_proto" || continue
        tunnel_dns_prepare "$_tt_proto" || continue
        DNS_TUNNEL_PROTOCOL="$_tt_proto"
        probe_all_dns_ports
        if [ -n "$DNS_WORKING_PORTS" ]; then
            DNS_TUNNEL_READY=1
            # A tunnel selected by the fallback chain is now the active DNS
            # plane too; mark it required so snapshot consumers keep raw DNS
            # fail-closed and accept TUNNEL_DNS as a valid canonical state.
            DNS_TUNNEL_REQUIRED=1
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
        for _dns_off_table in filter nat; do
            DNS_TUNNEL_DISABLE=1 DNS_TUNNEL_BLOCK_RAW_DNS=0 \
                DNS_ONLY=1 type=iptable table="$_dns_off_table" \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
        done
    fi
    clear_tunnel_dns_set
    return 1
}

# Live mode already belongs to the v4 controller.

select_dns_mode() {
    if [ "${DNS_POLICY_V4:-0}" = 1 ]; then v4_load_dns; return $?; fi
    # Tunnel state has priority over the fact that the tunnel makes a local
    # listener answer with AD. Otherwise a successful tunnel check would be
    # mislabeled LOCAL_DNSSEC and the fallback chain would be invisible.
    if [ "$DNS_TUNNEL_READY" -eq 1 ]; then
        DNS_MODE="TUNNEL_DNS"
        DNS_PRIMARY_LEVEL="TUNNEL_DNS"
        return 0
    fi

    # If a tunnel is active but its DNS plane cannot be prepared, fail closed
    # instead of sending the resolver directly to the ISP/provider. This is
    # the only safe result for the no-DNS-leak requirement.
    if [ "$DNS_TUNNEL_REQUIRED" -eq 1 ]; then
        DNS_SECURE_PORTS=""
        DNS_INSECURE_PORTS=""
        DNS_WORKING_PORTS=""
        DNS_PRIMARY=""
        DNS_BACKUP_PORTS=""
        DNS_PRIMARY_RTT_MS=""
        DNS_MODE="DNS_UNAVAILABLE"
        DNS_PRIMARY_LEVEL="DNS_UNAVAILABLE"
        return 0
    fi

    if [ -n "$DNS_INITIAL_SECURE_PORTS" ]; then
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
    else
        DNS_PRIMARY="40500"
        DNS_PRIMARY_LEVEL="DNS_UNAVAILABLE"
        DNS_MODE="DNS_UNAVAILABLE"
    fi
}

select_dns_mode

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
    # 40500 is a final local fallback only when no tunnel is active. Never
    # add it to the upstream set while tunnel DNS is required: that would
    # silently reintroduce a direct DNS path.
    if [ "${DNS_POLICY_V4:-0}" != 1 ] && [ "$DNS_TUNNEL_REQUIRED" -eq 0 ] && [ -z "$DNS_WORKING_PORTS" ]; then
        _udu_add_port 40500
    fi

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
        # Older project templates put strict-order outside the managed block.
        # Normalize the legacy duplicate without changing ordered selection.
        /^[[:space:]]*strict-order[[:space:]]*(#.*)?$/ { next }
        !skip { print }
        END { if (!inserted) emit() }
    ' "$DNSMASQ_CONF" > "$_udu_tmp"
    chmod 0644 "$_udu_tmp" 2>/dev/null || true
    mv -f "$_udu_tmp" "$DNSMASQ_CONF"
}

reload_dnsmasq() {
    [ "${KEENZOO_SKIP_DNSMASQ_RELOAD:-0}" = "1" ] && return 0
    [ -f "$DNSMASQ_CONF" ] || return 0
    if command -v dnsmasq >/dev/null 2>&1; then
        dnsmasq --test -C "$DNSMASQ_CONF" >/dev/null 2>&1 || {
            logger -t "unblock_dnsmasq" "reload skipped: dnsmasq config test failed" 2>/dev/null || true
            return 1
        }
    fi
    _rdm_pids="$(pidof dnsmasq 2>/dev/null || true)"
    if [ "${1:-config}" = hosts ]; then
        [ -n "$_rdm_pids" ] || return 0
        # SIGHUP reloads hosts, NOT dnsmasq.conf / conf-file directives.
        kill -HUP $_rdm_pids 2>/dev/null || return 1
    else
        if [ -n "$_rdm_pids" ] && [ -n "${DNS_CONFIG_BACKUP:-}" ] \
            && cmp -s "$DNS_CONFIG_BACKUP/main" "$DNSMASQ_CONF" \
            && { cmp -s "$DNS_CONFIG_BACKUP/domains" "$OUT_FILE" \
                 || { [ ! -e "$DNS_CONFIG_BACKUP/domains" ] && [ ! -e "$OUT_FILE" ]; }; }; then
            return 0
        fi
        _rdm_action=restart
        [ -n "$_rdm_pids" ] || _rdm_action=start
        /opt/etc/init.d/S56dnsmasq "$_rdm_action" >/dev/null 2>&1 || return 1
        pidof dnsmasq >/dev/null 2>&1 || return 1
    fi
    return 0
}

dnsmasq_query_ready() {
    dig -4 +short +time=3 +tries=2 "$DNS_HEALTH_DOMAIN" A @127.0.0.1 -p 53 2>/dev/null \
        | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && return 0
    dns_health_file_log "dnsmasq client-plane failed=NO_IPV4_ANSWER port=53"
    return 1
}

write_final_dns_snapshot() {
    _dns_ports_log="$(printf '%s' "${DNS_WORKING_PORTS:-none}" | tr ' ' ',')"
    _dns_backups_log="$(printf '%s' "${DNS_BACKUP_PORTS:-none}" | tr ' ' ',')"
    _dns_secure_log="$(printf '%s' "${DNS_SECURE_PORTS:-none}" | tr ' ' ',')"
    _dns_insecure_log="$(printf '%s' "${DNS_INSECURE_PORTS:-none}" | tr ' ' ',')"
    dns_health_file_log \
        "decision=final mode=$DNS_MODE level=$DNS_PRIMARY_LEVEL required=$DNS_TUNNEL_REQUIRED verified=$DNS_TUNNEL_READY primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} ports=$_dns_ports_log secure=$_dns_secure_log insecure=$_dns_insecure_log backups=$_dns_backups_log ranking=${DNS_RANKING:-none} tunnel=${DNS_TUNNEL_PROTOCOL:-none} client=${DNS_CLIENT_STATE:-unknown}"
}


publish_dns_failure() {
    DNS_MODE=DNS_UNAVAILABLE
    DNS_PRIMARY_LEVEL=DNS_UNAVAILABLE
    DNS_TUNNEL_READY=0
    DNS_WORKING_PORTS=''
    DNS_SECURE_PORTS=''
    DNS_INSECURE_PORTS=''
    DNS_PRIMARY=''
    DNS_BACKUP_PORTS=''
    DNS_PRIMARY_RTT_MS=''
    DNS_CLIENT_STATE=failed
    write_final_dns_snapshot
}

# Update only generated local DNS server lines, not ipset/CIDR/resource lists,
# Tor (9053), foreign endpoints, or user overrides in the main config.
refresh_domain_upstreams() {
    [ -f "$OUT_FILE" ] || return 0
    _rdu_tmp="${OUT_FILE}.upstreams.$$"
    _rdu_managed="40500 40501 40502 40503 40508 40509 40510 40511 $DNS_PORTS_DOT $DNS_PORTS_DOH"
    if [ -r "$DNS_CONFIG_BACKUP/main" ]; then
        _rdu_managed="$_rdu_managed $(awk -v b="$DNS_UPSTREAM_BEGIN" -v e="$DNS_UPSTREAM_END" '
            $0==b {inside=1; next} $0==e {inside=0}
            inside && /^server=127\.0\.0\.1#[0-9]+$/ {
                sub(/^server=127\.0\.0\.1#/, ""); print
            }' "$DNS_CONFIG_BACKUP/main")"
    fi
    awk -v ports="$DNS_WORKING_PORTS" -v managed="$_rdu_managed" '
        BEGIN { n=split(ports,p," "); k=split(managed,m," "); for(i=1;i<=k;i++) own[m[i]]=1 }
        FILENAME==ARGV[1] {
            if ($0 ~ /^[[:space:]]*server=\//) {
                line=$0; sub(/^[[:space:]]*server=\//,"",line)
                zc=split(line,z,"/"); for(i=1;i<zc;i++) overrides[tolower(z[i])]=1
            }
            next
        }
        /^server=\/[^\/]+\/127\.0\.0\.1#[0-9]+$/ {
            split($0,a,"/"); port=a[3]; sub(/^127\.0\.0\.1#/,"",port)
            if (port != "9053" && (port in own)) {
                zone=tolower(a[2]); covered=0
                for(o in overrides) if(o!="" && (zone==o ||
                    (length(zone)>length(o) && substr(zone,length(zone)-length(o))=="." o))) covered=1
                if (!seen[zone]++ && !covered) for(i=1;i<=n;i++) if(p[i]!="")
                    print "server=/" a[2] "/127.0.0.1#" p[i]
                next
            }
        }
        { print }
    ' "$DNSMASQ_CONF" "$OUT_FILE" > "$_rdu_tmp" || return 1
    chmod 0644 "$_rdu_tmp" || return 1
    mv -f "$_rdu_tmp" "$OUT_FILE"
}

finish_dns_apply() {
    if [ "${KEENZOO_SKIP_DNSMASQ_RELOAD:-0}" = 1 ]; then
        # Only the parent orchestrator can use an uncommitted decision, in a
        # private rollback directory. Never expose staged success to the UI.
        [ "${KEENZOO_DNS_STAGE:-0}" = 1 ] || return 1
        DNS_CLIENT_STATE=staged
    else
        reload_dnsmasq || return 1
        dnsmasq_query_ready || return 1
        DNS_CLIENT_STATE=ok
    fi
    write_final_dns_snapshot || return 1
    DNS_TX_DONE=1
}

# Do not publish/apply the preliminary decision. Bootstrap pins and retry
# the selected tunnel first, including health-only/WAN/UI refreshes.

logger -t "unblock_dnsmasq" \
    "DNS primary=${DNS_PRIMARY:-none} primary_rtt=${DNS_PRIMARY_RTT_MS:-none} backups=${DNS_BACKUP_PORTS:-none} ranking=${DNS_RANKING:-none} mode=$DNS_MODE level=$DNS_PRIMARY_LEVEL tunnel=${DNS_TUNNEL_PROTOCOL:-none} health_domain=$DNS_HEALTH_DOMAIN"

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

HOSTS_FILE="${HOSTS_FILE:-/opt/etc/hosts}"

# BOOTSTRAP_RESOLVERS was parsed above from bot_config.py. It is used only
# for cold-start pin candidates, never as a DNSSEC result.

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
ndm_dot_tls_probe() {
    if command -v openssl >/dev/null 2>&1; then
        run_bounded 7 openssl s_client -connect "${2}:853" \
            -servername "$1" -verify_return_error -verify_hostname "$1" \
            </dev/null >/dev/null 2>&1
        return $?
    fi
    command -v python3 >/dev/null 2>&1 || return 127
    # Python ssl uses the CA store and checks SNI/hostname, not just TCP connect.
    # Pass code with -c: run_bounded deliberately closes child stdin.
    run_bounded 7 python3 -c '
import ipaddress, socket, ssl, sys
host, address = sys.argv[1:]
ipaddress.IPv4Address(address)
context = ssl.create_default_context()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
    raw.settimeout(3)
    raw.connect((address, 853))
    with context.wrap_socket(raw, server_hostname=host):
        pass
' "$1" "$2" </dev/null >/dev/null 2>&1
}

ndm_endpoint_reachable() {
    _ner_host="$1"
    _ner_ip="$2"
    case "$_ner_host" in
        opennic*.eth-services.de) _ner_port=853 ;;
        *) _ner_port=443 ;;
    esac

    if [ "$_ner_port" = "853" ]; then
        if ndm_dot_tls_probe "$_ner_host" "$_ner_ip"; then
            logger -t "unblock_dnsmasq" \
                "NDM probe: host=$_ner_host level=TLS_OK"
            return 0
        else
            _ner_probe_rc=$?
        fi
        case "$_ner_probe_rc" in
            125|126|127)
                logger -t "unblock_dnsmasq" \
                    "NDM probe: host=$_ner_host level=PROBE_UNAVAILABLE rc=$_ner_probe_rc"
                return 1 ;;
        esac
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
        grep -qE 'SSL connection using (TLS|SSL)' \
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

    case "$_ner_rc" in
        51|60) _ner_level=TLS_VERIFY_FAILED ;;
        35) _ner_level=TLS_HANDSHAKE_FAILED ;;
        28)
            if [ "$_ner_tls" -eq 1 ]; then _ner_level=HTTP_TIMEOUT_AFTER_TLS
            elif [ "$_ner_tcp" -eq 1 ]; then _ner_level=TLS_TIMEOUT_AFTER_TCP
            else _ner_level=TCP_TIMEOUT; fi
            ;;
        6) _ner_level=DNS_RESOLUTION_FAILED ;;
        7) _ner_level=TCP_CONNECT_FAILED ;;
        *) _ner_level=TRANSPORT_FAILURE ;;
    esac
    logger -t "unblock_dnsmasq" \
        "NDM probe: host=$_ner_host level=$_ner_level rc=$_ner_rc"
    rm -f "$_ner_trace"
    return 1
}

ndm_fresh_addresses() {
    _nfa_host="$1"
    # Используется общий порядок local DNSSEC -> tunnel-DNS -> pin ->
    # insecure/40500/provider/bootstrap, а не прямой bootstrap на первом
    # шаге. Старый pin уже доступен через ndm_pinned_lookup.
    resolve_name_a "$_nfa_host" 2>/dev/null | sort -u | head -8
}

update_ndm_bootstrap_hosts() {
    _unh_body="$(mktemp /tmp/ndm_hosts.XXXXXX 2>/dev/null || true)"
    [ -n "$_unh_body" ] || return 1
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
                "NDM endpoint candidate verified: $_unh_host -> $_unh_ok"
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
                    "NDM endpoint not verified: $_unh_host; no previous pin, endpoint skipped"
            fi
        fi
    done

    # Commit verified endpoints independently. A missing OPTIONAL endpoint
    # (OpenNIC in the incident logs) must not discard Google/Quad9/Cloudflare.
    # Failed endpoints retain their previous pins above; an entirely empty
    # candidate still leaves the old managed section untouched.
    [ -s "$_unh_body" ] || {
        rm -f "$_unh_body"
        return 0
    }

    _unh_hosts_tmp="${HOSTS_FILE}.ndm.$$"
    if [ -f "$HOSTS_FILE" ]; then
        if ! awk -v b="$NDM_PIN_BEGIN" -v e="$NDM_PIN_END" '
            $0 == b { skip=1; next }
            $0 == e { skip=0; next }
            !skip
        ' "$HOSTS_FILE" > "$_unh_hosts_tmp" 2>/dev/null; then
            rm -f "$_unh_hosts_tmp" "$_unh_body"
            return 1
        fi
    elif ! : > "$_unh_hosts_tmp"; then
        rm -f "$_unh_hosts_tmp" "$_unh_body"
        return 1
    fi
    if ! {
        printf '%s\n' "$NDM_PIN_BEGIN"
        printf '# generated-at=%s\n' "$(date +%s)"
        awk '!seen[$0]++' "$_unh_body"
        printf '%s\n' "$NDM_PIN_END"
    } >> "$_unh_hosts_tmp"; then
        rm -f "$_unh_hosts_tmp" "$_unh_body"
        return 1
    fi
    if ! chmod 0644 "$_unh_hosts_tmp" 2>/dev/null; then
        rm -f "$_unh_hosts_tmp" "$_unh_body"
        return 1
    fi
    if ! mv -f "$_unh_hosts_tmp" "$HOSTS_FILE" 2>/dev/null; then
        rm -f "$_unh_hosts_tmp" "$_unh_body"
        return 1
    fi
    rm -f "$_unh_body"
    logger -t "unblock_dnsmasq" "NDM bootstrap section committed"
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

# Shadowsocks использует массив server, но для пиннинга нужен только первый
# endpoint: это необязательный сервис и его адрес также не должен зависеть
# от DNS в момент раннего старта.
shadowsocks_server_host() {
    [ -f /opt/etc/shadowsocks.json ] || return 0
    sed -n 's/.*"server"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p' \
        /opt/etc/shadowsocks.json \
        | grep -vE '^(127\.|0\.0\.0\.0|::1?$|localhost$|\{\{)' \
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

    _pfh_ss="$(shadowsocks_server_host || true)"
    _pfh_ss="$(printf '%s' "$_pfh_ss" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    if [ -n "$_pfh_ss" ] && [ "$_pfh_host" = "$_pfh_ss" ]; then
        _pfh_result="${_pfh_result}${_pfh_result:+/}Shadowsocks"
    fi

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
    managed_section_usable "$PIN_BEGIN" "$PIN_END" || return 1

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
ROUTER_IP="${ROUTER_IP:-$(sed -n \
    "s/^[[:space:]]*routerip[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" \
    /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)}"

bootstrap_host_allowed() {
    _bha_host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
    [ -n "$_bha_host" ] || return 1
    for _bha_known in $DNS_ENDPOINT_HOSTS $NDM_ENDPOINT_HOSTS \
        "$(xray_server_host || true)" "$(hysteria_server_host || true)" \
        "$(trojan_server_host || true)" "$(shadowsocks_server_host || true)"; do
        _bha_known="$(printf '%s' "$_bha_known" | tr '[:upper:]' '[:lower:]' \
            | sed 's/:[0-9][0-9]*$//' | sed 's/\.$//')"
        [ -n "$_bha_known" ] || continue
        [ "$_bha_host" = "$_bha_known" ] && return 0
    done
    return 1
}

provider_resolver_list() {
    # Keenetic normally exposes /etc/resolv.conf. Some firmware builds keep
    # a generated copy in /tmp, but the project must not depend on that file.
    # Read both, validate every IPv4 octet, drop loopback/unspecified values
    # and keep a small deterministic list for the last fallback only.
    for _pr_file in /etc/resolv.conf /tmp/resolv.conf; do
        [ -f "$_pr_file" ] || continue
        awk -v r="$ROUTER_IP" '
            function valid_ip(v, a, i) {
                if (split(v, a, ".") != 4) return 0
                for (i = 1; i <= 4; i++) {
                    if (a[i] !~ /^[0-9]+$/ || a[i] > 255) return 0
                }
                if (a[1] == 127 || a[1] == 0) return 0
                if (v == r) return 0
                return 1
            }
            /^[[:space:]]*nameserver[[:space:]]+/ {
                ip = $2
                if (valid_ip(ip)) print ip
            }
        ' "$_pr_file" 2>/dev/null
    done | awk '!seen[$0]++' | head -3
}

resolve_name_a() {
    if [ "${DNS_POLICY_V4:-0}" = 1 ]; then
        _v4_name="$1"
        _v4_a="$(dig -4 +short +time=2 +tries=1 "$_v4_name" A @127.0.0.1 -p 40512 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
        if [ -n "$_v4_a" ]; then printf '%s\n' "$_v4_a"; return 0; fi
        # Only endpoint/pin cold start may use bootstrap outside the facade.
        bootstrap_host_allowed "$_v4_name" || return 1
        for _v4_ns in $BOOTSTRAP_RESOLVERS; do
            _v4_a="$(dig -4 +short +time=2 +tries=1 "$_v4_name" A "@$_v4_ns" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            if [ -n "$_v4_a" ]; then printf '%s\n' "$_v4_a"; return 0; fi
        done
        return 1
    fi
    _rna_name="$1"
    _rna_out=""

    # 1. Только DNSSEC-проверенные локальные DoT/DoH-порты.
    for _rna_port in $DNS_SECURE_PORTS; do
        _rna_out="$(dig +short +timeout=3 +tries=1 A "$_rna_name" \
            @localhost -p "$_rna_port" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
        [ -n "$_rna_out" ] && break
    done

    # 2. Старые pins для proxy/DNS endpoint-ов уже были использованы
    # tunnel_dns_prepare для построения DNS tunnel path. Само разрешение
    # выполняется только через системные localhost DoH/DoT listeners ниже;
    # прямой curl/DoH resolver здесь намеренно запрещён.

    # Старый pin — это не новый DNS-ответ, а уже сохраненный адрес,
    # использующийся для продолжения работы туннеля.
    if [ -z "$_rna_out" ]; then
        _rna_out="$(pinned_hosts_lookup "$_rna_name" || true)"
        [ -z "$_rna_out" ] && _rna_out="$(ndm_pinned_lookup "$_rna_name" || true)"
        [ -n "$_rna_out" ] && \
            logger -t "unblock_dnsmasq" \
                "DNS resolve: $_rna_name source=PREVIOUS_PIN"
    fi

    # A listener can exist before its endpoint and DNS redirect are ready.
    # During that cold-start window it is safe to ask only the already-tested
    # local DNSSEC listeners for the small allow-list of proxy/DNS endpoint
    # names needed to create pins. This is not a general direct-DNS fallback:
    # the result is never published as an upstream while the tunnel is
    # required, insecure/provider/bootstrap resolvers remain forbidden, and
    # ordinary names do not pass bootstrap_host_allowed().
    if [ -z "$_rna_out" ] \
        && [ "$DNS_TUNNEL_REQUIRED" -eq 1 ] \
        && [ "$DNS_TUNNEL_READY" -ne 1 ] \
        && bootstrap_host_allowed "$_rna_name"; then
        for _rna_port in $DNS_BOOTSTRAP_SECURE_PORTS; do
            _rna_out="$(dig +short +timeout=3 +tries=1 A "$_rna_name" \
                @localhost -p "$_rna_port" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            [ -n "$_rna_out" ] && {
                logger -t "unblock_dnsmasq" \
                    "DNS resolve: $_rna_name source=COLD_START_BOOTSTRAP_DNSSEC port=$_rna_port"
                break
            }
        done
    fi

    # If a tunnel is active but its client-plane was not verified, this is
    # the terminal fail-closed state. No insecure local listener, 40500,
    # provider resolver or public bootstrap resolver may be queried in this
    # state. The narrowly-scoped DNSSEC pin bootstrap above is the only
    # exception, and it has already been attempted before this guard.
    if [ "$DNS_TUNNEL_REQUIRED" -eq 1 ] && [ "$DNS_TUNNEL_READY" -ne 1 ]; then
        logger -t "unblock_dnsmasq" \
            "DNS resolve: $_rna_name source=FAIL_CLOSED reason=tunnel-client-plane-unavailable"
        [ -n "$_rna_out" ] || return 1
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

    # An active tunnel never falls through to a direct 40500/provider/
    # bootstrap query: that would leak DNS outside the tunnel. The external
    # cold-start chain below is available only when no tunnel is active.
    if [ "$DNS_TUNNEL_REQUIRED" -eq 1 ]; then
        [ -n "$_rna_out" ] || logger -t "unblock_dnsmasq" \
            "DNS resolve: $_rna_name source=FAIL_CLOSED reason=tunnel-DNS-query-failed"
        [ -n "$_rna_out" ] || return 1
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
    # shadowsocks: first server in the array + server_port.
    if [ -f /opt/etc/shadowsocks.json ]; then
        if grep -q "\"server\"[[:space:]]*:[[:space:]]*\[[[:space:]]*\"${_ppf_host}\"" \
            /opt/etc/shadowsocks.json 2>/dev/null; then
            _ppf_p="$(sed -n 's/.*"server_port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
                /opt/etc/shadowsocks.json 2>/dev/null | head -1)"
            [ -n "$_ppf_p" ] && { printf '%s' "$_ppf_p"; return 0; }
        fi
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
        rm -f "${_cpr_state}.now"
        # A failed candidate must never replace the last working pin.
        return 1
    fi
    # Всё доступно: если раньше были сбои — сообщаем о восстановлении.
    if [ -s "$_cpr_state" ]; then
        pin_notify "✅ Серверы обхода снова доступны." ok
        rm -f "$_cpr_state"
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
    # Shadowsocks добавлен сюда же: его конфиг может содержать hostname,
    # а сервис также стартует до dnsmasq.
    for _pin_host in "$(xray_server_host)" "$(hysteria_server_host)" \
        "$(trojan_server_host)" "$(shadowsocks_server_host)"; do
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
    if ! check_pinned_reachable "$_pin_body"; then
        logger -t "unblock_dnsmasq" \
            "pin: candidate rejected; previous verified hosts section preserved"
        return 0
    fi

    _pin_tmp="$(mktemp /tmp/hosts.XXXXXX 2>/dev/null || true)"
    [ -n "$_pin_tmp" ] || return 1

    # Чужие строки сохраняются: вырезается только собственная секция.
    if [ -f "$HOSTS_FILE" ]; then
        if ! awk -v b="$PIN_BEGIN" -v e="$PIN_END" '
            $0 == b { skip = 1; next }
            $0 == e { skip = 0; next }
            !skip
        ' "$HOSTS_FILE" > "$_pin_tmp" 2>/dev/null; then
            rm -f "$_pin_tmp"
            return 1
        fi
    elif ! : > "$_pin_tmp"; then
        rm -f "$_pin_tmp"
        return 1
    fi

    # Дубли снимаются: протоколы нередко делят один сервер (например
    # vless и trojan на общем домене), и тогда одна и та же пара
    # "IP<TAB>домен" попала бы в hosts несколько раз. Для dnsmasq это не
    # ошибка, но файл растёт и путает при чтении. sort -u не подходит:
    # он изменил бы порядок, а awk сохраняет первое вхождение.
    if ! {
        printf '%s\n' "$PIN_BEGIN"
        printf '# generated-at=%s\n' "$(date +%s)"
        printf '%s' "$_pin_body" | awk '!seen[$0]++'
        printf '%s\n' "$PIN_END"
    } >> "$_pin_tmp"; then
        rm -f "$_pin_tmp"
        return 1
    fi

    # dnsmasq работает под nobody и молча перестанет читать файл,
    # если права окажутся строже 0644.
    if ! chmod 0644 "$_pin_tmp" 2>/dev/null; then
        rm -f "$_pin_tmp"
        return 1
    fi
    if ! mv -f "$_pin_tmp" "$HOSTS_FILE" 2>/dev/null; then
        rm -f "$_pin_tmp"
        return 1
    fi

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

# dnsmasq must see the newly written /opt/etc/hosts pins before a fallback
# client is started. Without this reload Hysteria/Xray can still ask the old
# resolver and fail before its listener appears, recreating the boot loop.
reload_dnsmasq hosts || true

# Cold-start bootstrap мог только сейчас записать NDM/Proxy pins.
# Повторяем выбор tunnel-DNS после их появления, иначе первый запуск
# остановился бы на DNS_UNAVAILABLE и ждал бы следующего события.
if [ "${DNS_POLICY_V4:-0}" != 1 ] && [ "$DNS_TUNNEL_READY" -eq 0 ] \
    && { [ -z "$DNS_INITIAL_SECURE_PORTS" ] || [ "$DNS_TUNNEL_REQUIRED" -eq 1 ]; }; then
    if try_tunnel_dns; then
        DNS_TUNNEL_REQUIRED=1
        select_dns_mode
        logger -t "unblock_dnsmasq" \
            "DNS tunnel activated after pins: protocol=$DNS_TUNNEL_PROTOCOL primary=$DNS_PRIMARY"
    else
        select_dns_mode
        logger -t "unblock_dnsmasq" \
            "DNS tunnel unavailable after pins: mode=$DNS_MODE"
    fi
fi

# Pins may make tunnel-DNS available after the first decision. Publish the
# final post-pin state as the last bounded snapshot record consumed by
# unblock_ipset.sh; a stale pre-pin DNS_UNAVAILABLE record must not win.
select_dns_mode
update_dnsmasq_upstreams
refresh_domain_upstreams
if [ "$DNS_MODE" = DNS_UNAVAILABLE ]; then
    # Keep the intentionally empty fail-closed upstream selection. Do not
    # restore a previous direct path when the required tunnel is unavailable.
    DNS_TX_DONE=1
    reload_dnsmasq || true
    publish_dns_failure
    # В staged-транзакции unblock_update.sh rc=75 — это EX_TEMPFAIL
    # (среда недоступна), а не сбой генерации: update переводит всё в defer.
    # В живом режиме остаётся exit 1: событийный повтор и так наступит.
    [ "${KEENZOO_DNS_STAGE:-0}" = "1" ] && exit 75
    exit 1
fi
if [ "$DNS_HEALTH_ONLY" = "1" ]; then
    finish_dns_apply || exit 1
    exit 0
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
            return h == d || (length(h)>length(d) && substr(h,length(h)-length(d))=="." d)
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
    # DNS_UNAVAILABLE with an active tunnel deliberately has no direct
    # upstream. Do not emit server=/zone/127.0.0.1# (invalid dnsmasq syntax);
    # ipset population will consume the same fail-closed snapshot.
    if [ -z "$_dns_port" ]; then
        logger -t "unblock_dnsmasq" \
            "DNS resource upstream omitted: $_host mode=$DNS_MODE"
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
            if is_public_cidr "$line"; then
                printf 'add %s %s\n' "$_setname" "$line" >> "$TMP_CIDR"
            else
                logger -t "unblock_dnsmasq" "skip non-public network: $line"
            fi
            continue
        fi

        # Диапазоны вида a.b.c.d-e.f.g.h тоже обрабатывает ipset-скрипт.
        case "$line" in
            *[0-9]-[0-9]*)
                if printf '%s' "$line" | grep -qE '^[0-9.]+-[0-9.]+$'; then
                    if is_public_range "$line"; then
                        continue
                    fi
                    logger -t "unblock_dnsmasq" "skip non-public range: $line"
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
    # Preserve first occurrence order. sort -u reordered generated
    # server=/domain/... lines and could defeat DNS ranking for a zone.
    awk '!seen[$0]++' "$TMP_OUT" > "${TMP_OUT}.sorted"
    mv -f "${TMP_OUT}.sorted" "$OUT_FILE"
else
    : > "$OUT_FILE"
fi

if [ -s "$TMP_CIDR" ]; then
    LC_ALL=C sort -u "$TMP_CIDR" > "${TMP_CIDR}.sorted"
    mv -f "${TMP_CIDR}.sorted" "$CIDR_FILE"

    # The orchestrated update stages domains and CIDRs together. Do not mutate
    # live sets while dnsmasq.conf is being generated; standalone invocations
    # retain the historical direct-apply behavior.
    if [ "${KEENZOO_STAGE_CIDR:-0}" != "1" ]; then
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
    fi
else
    rm -f "$CIDR_FILE"
fi

# Apply the final config only after dynamic interfaces, upstreams, pins and
# generated resource rules have all been written.
finish_dns_apply || exit 1
exit 0

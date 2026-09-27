#!/bin/sh
# remove keeps data but disables cron/NDM reactivation until next install.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# dns4.2.31 (полный аудит, остаточное наблюдение): паритет с
# S99generator/S99unblock — интерпретатор ищем по тем же путям.
# Голый «python3» пропускает версионированные сборки без симлинка
# (только python3.11/3.12/3.13): вызов тогда молча не срабатывает.
# Дубль 8 строк осознан — общий lib менял бы структуру проекта.
find_python() {
    for _p in /opt/bin/python3 /usr/bin/python3 /opt/bin/python3.11 \
              /opt/bin/python3.12 /opt/bin/python3.13; do
        [ -x "$_p" ] && { printf '%s\n' "$_p"; return 0; }
    done
    _p="$(command -v python3 2>/dev/null || true)"
    [ -n "$_p" ] && { printf '%s\n' "$_p"; return 0; }
    return 1
}
# Худший случай ровно прежний: голый «python3».
KZ_PY="$(find_python || echo python3)"

# Keep the tunnel listener ports in step with the existing deploy
# configuration. Parsing is intentionally simple and BusyBox-compatible;
# missing values keep the known Keenetic defaults.
config_number() {
    # Раунд 7, N-16: в ветке двойных кавычек до сед обязаны дойти
    # одинарные `\(`/`\)`/`\1` (прежние `\\(` группами не были).
    _cn_key="$1"
    _cn_default="$2"
    _cn_value="$(sed -n \
        -e "s/^[[:space:]]*${_cn_key}[[:space:]]*=[[:space:]]*'\\([0-9][0-9]*\\)'.*$/\\1/p" \
        -e 's/^[[:space:]]*'"${_cn_key}"'[[:space:]]*=[[:space:]]*"\([0-9][0-9]*\)".*/\1/p' \
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
        -e 's/^[[:space:]]*'"${_cs_key}"'[[:space:]]*=[[:space:]]*"\([^"\\]*\)".*/\1/p' \
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
    # Раунд 4, П-14: самая частая функция списка (по вызову на строку) —
    # без форков внешних команд, чистой подстановкой. Сначала отбрасываем
    # всё с первого «#», затем хвостовые пробельные.
    # Раунд 5, R-2: класс ДОЛЖЕН быть [[:space:]], а не «пробел+таб»:
    # прежний снимал и \r, иначе списки с окончаниями CRLF (правка в
    # Windows/WinSCP) теряли КАЖДУЮ строку — is_ip/is_domain_core
    # отвергают значение с хвостовым CR, а unblock_dnsmasq.sh,
    # unblock_update.sh и панель CR снимают (расхождение было тихим:
    # статус «done» при domains=0).
    _tc_value="${1%%#*}"
    while [ "${_tc_value%[[:space:]]}" != "$_tc_value" ]; do
        _tc_value="${_tc_value%[[:space:]]}"
    done
    printf '%s' "$_tc_value"
}

# ── Валидация записей ────────────────────────────────────────────────────
# awk BusyBox не поддерживает интервалы {n,m} в регулярных выражениях
# надёжно, поэтому проверки октетов выполняются арифметикой, а домены —
# посимвольным разбором меток.

is_ip() {
    # dns4.2.40 П-12 (аудит-3): чистый ash вместо форка awk на каждый
    # адрес — правила те же (4 октета, цифры, без ведущих нулей, <=255).
    # Эквивалентность доказана векторным харнессом (82+81+40 векторов,
    # включая границы зарезервированных диапазонов) под busybox ash и dash.
    case "$1" in
        '' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    _ii_ip="$1"; _ii_ifs="$IFS"; IFS=.
    # shellcheck disable=SC2086
    set -- $_ii_ip
    IFS="$_ii_ifs"
    [ $# -eq 4 ] || return 1
    for _ii_o in "$1" "$2" "$3" "$4"; do
        case "$_ii_o" in
            0 | [1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
            *) return 1 ;;
        esac
        [ "$_ii_o" -le 255 ] || return 1
    done
    return 0
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
# dns4.2.24 (аудит A6 N5): набор зарезервированных сетей. ПРАВИТЬ СИНХРОННО:
# is_public_ipv4 в ДРУГОМ файле (пара: unblock_dnsmasq.sh) и
# _RESERVED_NETS в /opt/etc/bot/generator.py.
is_public_ipv4() {
    # dns4.2.40 П-12 (аудит-3): чистый ash вместо форка awk на каждый
    # адрес — набор зарезервированных сетей тот же; эквивалентность
    # доказана векторным харнессом под busybox ash и dash.
    is_ip "$1" || return 1
    _ipv_ip="$1"; _ipv_ifs="$IFS"; IFS=.
    # shellcheck disable=SC2086
    set -- $_ipv_ip
    IFS="$_ipv_ifs"
    case "$1.$2.$3" in
        0.*.* | 10.*.* | 127.*.* | 169.254.* | 192.168.* | 198.18.* | 198.19.* | \
        192.0.0 | 192.0.2 | 192.88.99 | 192.175.48 | 198.51.100 | 203.0.113) return 1 ;;
    esac
    [ "$1" -ge 224 ] && return 1
    [ "$1" -eq 100 ] && [ "$2" -ge 64 ] && [ "$2" -le 127 ] && return 1
    [ "$1" -eq 172 ] && [ "$2" -ge 16 ] && [ "$2" -le 31 ] && return 1
    return 0
}


# Validate the complete CIDR/range interval, not only its first address.
# dns4.2.24 (аудит A6 N5): набор зарезервированных сетей. ПРАВИТЬ СИНХРОННО:
# с dns4.2.40 этот файл — ЕДИНСТВЕННЫЙ носитель is_public_cidr/
# is_public_range (копия из unblock_dnsmasq.sh удалена как мёртвый код);
# пара is_public_ipv4 — в unblock_dnsmasq.sh, _RESERVED_NETS — в
# /opt/etc/bot/utils.py.
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
                overlap(first,last,3227017984,3227018239) ||
                overlap(first,last,3232235520,3232301055) ||
                overlap(first,last,3232706560,3232706815) ||
                overlap(first,last,3323068416,3323199487) ||
                overlap(first,last,3325256704,3325256959) ||
                overlap(first,last,3405803776,3405804031) ||
                overlap(first,last,3758096384,4294967295)) exit 1
            exit 0
        }
    '
}

# dns4.2.24 (аудит A6 N5): набор зарезервированных сетей. ПРАВИТЬ СИНХРОННО:
# см. комментарий у is_public_cidr выше (с dns4.2.40 единственный
# носитель is_public_range — этот файл).
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
                overlap(first,last,3227017984,3227018239) ||
                overlap(first,last,3232235520,3232301055) ||
                overlap(first,last,3232706560,3232706815) ||
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
KEENZOO_DNS_SNAPSHOT_MAX_AGE="${KEENZOO_DNS_SNAPSHOT_MAX_AGE:-$(config_number dns_snapshot_max_age 21600)}"  # was 90000=25h (dns4.2.21)
case "$KEENZOO_DNS_SNAPSHOT_MAX_AGE" in
    ''|*[!0-9]*) KEENZOO_DNS_SNAPSHOT_MAX_AGE=21600 ;;  # was 90000 (dns4.2.21)
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
    # shellcheck disable=SC2046 # контролируемый вывод (путь+имя)
    set -- $(tunnel_protocol_init "$_tpa_proto") || return 1
    _tpa_init="$1"
    _tpa_proc="$2"
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_tpa_init" 2>/dev/null && return 1
    pidof "$_tpa_proc" >/dev/null 2>&1 || return 1
    tunnel_listener_ready "$_tpa_proto"
}


is_domain_core() {
    # dns4.2.40 П-12 (аудит-3): чистый ash, правила те же (метки 1-63,
    # алфавит/цифры/дефис без дефиса на краях, до 253 символов, минимум
    # две метки, TLD не полностью числовой). Регистр нормализуется у
    # вызывающих; здесь принимаем и A-Z.
    _idc_s="$1"
    case "$_idc_s" in
        '' | *[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
        *.*) ;;
        *) return 1 ;;
    esac
    [ ${#_idc_s} -le 253 ] || return 1
    _idc_ifs="$IFS"; IFS=.
    # shellcheck disable=SC2086
    set -- $_idc_s
    IFS="$_idc_ifs"
    _idc_l=""
    for _idc_l in "$@"; do
        case "$_idc_l" in -* | *-) return 1 ;; esac
        [ ${#_idc_l} -le 63 ] || return 1
    done
    case "$_idc_l" in *[!0-9]*) return 0 ;; esac
    return 1
}

normalize_domain_target() {
    _value="$1"
    # Нижний регистр — только когда есть заглавные; хвостовая точка —
    # подстановкой (раунд 4, П-15: без лишних форков на каждый домен).
    case "$_value" in
        *[A-Z]*) _value="$(printf '%s' "$_value" | tr '[:upper:]' '[:lower:]')" ;;
    esac
    _value="${_value%.}"
    # Ведущие точки снимаем, как панель и unblock_dnsmasq.sh: раньше домен
    # с ведущей точкой молча отбрасывался, хотя панель его принимала
    # (раунд 4, L-9).
    while [ "${_value#.}" != "$_value" ]; do
        _value="${_value#.}"
    done

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

# Раунд 4, П-12б: кэш зон «server=/зона/…#порт» из dnsmasq.conf. Строится
# ОДИН раз за прогон (один проход awk по файлу) перед фоновыми заданиями
# dig; дальше каждый домен читает готовый кэш, а не перечитывает
# dnsmasq.conf двумя awk. Формат строки кэша: «<зона> <upstream>», зона в
# нижнем регистре и без хвостовой точки; нормализация upstream повторяет
# прежнюю: ::1#порт исключается, 127.0.0.1#порт → LOCAL#порт, к голому
# хосту дописывается #53, остальные записи проходят как есть.
build_dnsmasq_zone_cache() {
    DNSMASQ_ZONE_CACHE="${TMP_BASE}/dnsmasq_zones.txt"
    : > "$DNSMASQ_ZONE_CACHE"
    [ -f "$DNSMASQ_CONF" ] || return 0
    awk '
        function normzone(z) {
            z = tolower(z)
            while (z ~ /\.$/) sub(/\.$/, "", z)
            return z
        }
        function normup(u) {
            if (u ~ /^::1#[0-9][0-9]*$/) return ""
            if (u ~ /^127\.0\.0\.1#[0-9][0-9]*$/) {
                sub(/^127\.0\.0\.1#/, "LOCAL#", u)
                return u
            }
            if (u ~ /^[^#]+$/) return u "#53"
            return u
        }
        /^[[:space:]]*server=\/[^#]/ {
            line = $0
            sub(/^[[:space:]]*server=\//, "", line)
            n = split(line, fields, "/")
            if (n < 2) next
            up = normup(fields[n])
            if (up == "") next
            for (i = 1; i < n; i++) {
                if (fields[i] != "") print normzone(fields[i]) " " up
            }
        }
    ' "$DNSMASQ_CONF" 2>/dev/null > "$DNSMASQ_ZONE_CACHE" \
        || : > "$DNSMASQ_ZONE_CACHE"
    return 0
}

# Возвращает upstream-ы домена из подготовленного кэша зон (раунд 4,
# П-12б) в порядке их появления в dnsmasq.conf. Это важно для .onion,
# OpenNIC и других зон, для которых общий local DNS-порт не является
# правильным resolver-ом. Формат результата: LOCAL#port или host#port.
# Пустой вывод означает, что домен не покрыт ни одним ресурсным правилом.
# Раунд 5, П-12в: поиск — чистым ash, без форка awk на каждый домен
# (правило совпадения прежнее: зона целиком или суффикс «.зона»; хост
# уже в нижнем регистре после normalize_domain_target).
dnsmasq_resource_servers() {
    _drs_host="$1"
    [ -n "${DNSMASQ_ZONE_CACHE:-}" ] || return 1
    [ -f "$DNSMASQ_ZONE_CACHE" ] || return 1
    while read -r _drs_zone _drs_up; do
        [ -n "$_drs_zone" ] || continue
        case "$_drs_host" in
            "$_drs_zone"|*".$_drs_zone") printf '%s\n' "$_drs_up" ;;
        esac
    done < "$DNSMASQ_ZONE_CACHE"
    return 0
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
        _v4_snapshot="$("$KZ_PY" /opt/etc/bot/utils.py --dns-shell)" || return 1
        # dns4.2.27 (внешний аудит, Q-02): разбор БЕЗ eval — построчно
        # с белым списком имён; синхронно с unblock_dnsmasq.sh.
        while IFS= read -r _v4_line; do
            _v4_key="${_v4_line%%=*}"
            _v4_val="${_v4_line#*=}"
            _v4_val="${_v4_val#\'}"
            _v4_val="${_v4_val%\'}"
            case "$_v4_key" in
                DNS_MODE) DNS_MODE="$_v4_val" ;;
                DNS_PRIMARY_LEVEL) DNS_PRIMARY_LEVEL="$_v4_val" ;;
                DNS_PRIMARY) DNS_PRIMARY="$_v4_val" ;;
                DNS_WORKING_PORTS) DNS_WORKING_PORTS="$_v4_val" ;;
                DNS_BACKUP_PORTS) DNS_BACKUP_PORTS="$_v4_val" ;;
                DNS_PRIMARY_RTT_MS) DNS_PRIMARY_RTT_MS="$_v4_val" ;;
                DNS_SECURE_PORTS) DNS_SECURE_PORTS="$_v4_val" ;;
                DNS_INSECURE_PORTS) DNS_INSECURE_PORTS="$_v4_val" ;;
                DNS_TUNNEL_REQUIRED) DNS_TUNNEL_REQUIRED="$_v4_val" ;;
                DNS_TUNNEL_READY) DNS_TUNNEL_READY="$_v4_val" ;;
                DNS_TUNNEL_PROTOCOL) DNS_TUNNEL_PROTOCOL="$_v4_val" ;;
                DNS_RANKING) DNS_RANKING="$_v4_val" ;;
            esac
        done <<EOF
$_v4_snapshot
EOF
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
    [ $((_snp_now - _snp_epoch)) -le "${KEENZOO_DNS_SNAPSHOT_MAX_AGE:-21600}" ] || return 1  # was 90000 (dns4.2.21)

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
    # EX_TEMPFAIL (75): снапшот DNS решения отсутствует/устарел/невалиден —
    # это отсутствие среды, а не сбой ipset-логики; ничего не меняли.
    echo "DNS snapshot unavailable; run unblock_update.sh later (rc=75)" >&2
    exit 75
fi

logger -t "unblock_ipset" \
    "DNS snapshot consumed: ports=$WORKING_DNS_PORTS primary=${DNS_PRIMARY:-none} \
mode=${DNS_HEALTH_MODE:-${DNS_MODE:-unknown}} tunnel=${DNS_TUNNEL_PROTOCOL:-none}"

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
                _rd_result="$(dig -4 +short +timeout=2 +tries=1 \
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
        # «Порт уже пробовали» — чистым ash, без форка grep на порт
        # (раунд 4, П-15).
        case " $_rd_tried " in
            *" $_rd_port "*) continue ;;
        esac
        _rd_tried="${_rd_tried}${_rd_tried:+ }${_rd_port}"
        _rd_result="$(dig -4 +short +timeout=2 +tries=1 \
            "$_rd_domain" @localhost -p "$_rd_port" 2>/dev/null || true)"
        if [ -n "$_rd_result" ]; then
            _rd_public="$(emit_public_dns_answers "$_rd_result")"
            if [ -n "$_rd_public" ]; then
                if [ -n "$DNS_INSECURE_PORTS" ] && [ -z "$DNS_SECURE_PORTS" ]; then
                    # Раунд 6, П-18: в режиме без DNSSEC не по строке syslog
                    # на каждый домен — домены копятся в файл прогона, на
                    # список пишется одна сводка (та же схема, что
                    # применена к «exhausted» в dns4.2.15). Вне контекста
                    # process_list (маркер не задан) поведение прежнее.
                    if [ -n "${KEENZOO_NODNSSEC_FILE:-}" ]; then
                        printf '%s\n' "$_rd_domain" >> "$KEENZOO_NODNSSEC_FILE" 2>/dev/null || true
                    else
                        logger -t "unblock_ipset" \
                            "DNS resolve: $_rd_domain source=DNS_OK_NO_DNSSEC"
                    fi
                fi
                printf '%s\n' "$_rd_public"
                return 0
            fi
        fi
    done

    # dns4.2.15: per-domain строка в syslog заменена сводкой на список —
    # детальная строка уходит в per-run stderr (→ /tmp/unblock_update.log),
    # домен фиксируется в счётчике списка. Без активного списка (контекст вне
    # process_list) поведение прежнее: logger на домен.
    if [ -n "${KEENZOO_EXHAUSTED_FILE:-}" ]; then
        printf '%s\n' "$_rd_domain" >> "$KEENZOO_EXHAUSTED_FILE" 2>/dev/null || true
        printf '%s\n' "unblock_ipset: DNS resolve: $_rd_domain source=DNSMASQ_SNAPSHOT exhausted ports=$DNS_WORKING_PORTS" >&2
    else
        logger -t "unblock_ipset" \
            "DNS resolve: $_rd_domain source=DNSMASQ_SNAPSHOT exhausted ports=$DNS_WORKING_PORTS"
    fi
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

    # Счётчик нерезолва списка (dns4.2.15): per-domain строки об «exhausted»
    # больше не идут в syslog по одной — они откладываются сюда и дополнительно
    # дублируются в stderr (крон складывает в /tmp/unblock_update.log), а в
    # syslog уходит одна сводка на список в конце process_list. Файл — единственное
    # субшелл-безопасное накопление из resilient_dig.
    KEENZOO_EXHAUSTED_FILE="${_pl_work}/exhausted.txt"
    : > "$KEENZOO_EXHAUSTED_FILE"
    # Раунд 6, П-18: накопление доменов, разрезолвленных в режиме без
    # DNSSEC, — одна сводка на список вместо строки на домен.
    KEENZOO_NODNSSEC_FILE="${_pl_work}/nodnssec.txt"
    : > "$KEENZOO_NODNSSEC_FILE"

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
        # Префикс «add <имя>» навешивается на разрешённые результаты одним
        # awk при слиянии, а не отдельным форком на каждый домен
        # (раунд 4, П-13).
        cat "$_pl_resdir"/* 2>/dev/null \
            | awk -v s="$_pl_setname_real" '{ print "add " s " " $0 }' || true
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
    # Код 2 отделяет временный отказ DNS-среды от реальных сбоев ipset (код 1):
    # вызывающий unblock_update.sh по коду 2 переводит транзакцию в defer
    # (rc=75), а не в error.
    if [ "$_pl_idx" -gt 0 ]; then
        _pl_ratio=$(( _pl_resolved * 100 / _pl_idx ))
        if [ "$_pl_ratio" -lt "$MIN_RESOLVE_RATIO" ]; then
            logger -t "unblock_ipset" \
                "DNS degraded for $_pl_setname_real: $_pl_resolved/$_pl_idx (${_pl_ratio}%), set not replaced"
            rm -rf "$_pl_work"
            return 2
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

    # Раунд 6, П-18: одна сводка на список вместо строки на домен.
    if [ -s "$KEENZOO_NODNSSEC_FILE" ]; then
        _pl_nodnssec="$(wc -l < "$KEENZOO_NODNSSEC_FILE" | tr -d ' ')"
        logger -t "unblock_ipset" \
            "DNS resolve summary: $_pl_setname_real source=DNS_OK_NO_DNSSEC domains=$_pl_nodnssec of $_pl_idx"
    fi

    if [ -s "$KEENZOO_EXHAUSTED_FILE" ]; then
        _pl_exhausted="$(wc -l < "$KEENZOO_EXHAUSTED_FILE" | tr -d ' ')"
        logger -t "unblock_ipset" \
            "DNS resolve exhausted summary: $_pl_setname_real unresolved=$_pl_exhausted of $_pl_idx (детали → /tmp/unblock_update.log)"
        # Раунд 6, N-15: детали нерезолва действительно доводим до
        # /tmp/unblock_update.log — раньше строки субшелла глушились
        # «2>/dev/null» у задания, а файл списка удалялся вместе с
        # рабочим каталогом. Сводка выше обещает детали — выполняем.
        sed "s/^/unblock_ipset: DNS resolve exhausted: $_pl_setname_real /" \
            "$KEENZOO_EXHAUSTED_FILE" >&2 2>/dev/null || true
    fi

    rm -rf "$_pl_work"
    return 0
}

FAILED=""
# DNS_FAILED накапливает наборы, которые не применить из-за временной
# недоступности DNS (код 2 process_list): это не сбой транзакции, а defer.
DNS_FAILED=""

run_list() {
    _rl_file="$1"
    _rl_set="$2"
    # Фильтр ONLY_SETS: пропускаем наборы, которые не запрашивали.
    # ВАЖНО: пропуск — это именно «не трогать». Набор остаётся как был,
    # его нельзя ни чистить, ни пересоздавать, иначе частичное
    # обновление обнулило бы соседние протоколы.
    set_selected "$_rl_set" || return 0
    # «_rl_rc=0 … || _rl_rc=$?» обязателен под set -eu: код 1/2 должен уйти
    # в case, а не завершить скрипт немедленно; сброс — от залипания кода
    # прошлой итерации при успехе.
    _rl_rc=0
    process_list "$_rl_file" "$_rl_set" || _rl_rc=$?
    case "$_rl_rc" in
        0) ;;
        2) DNS_FAILED="${DNS_FAILED}${DNS_FAILED:+ }${_rl_set}" ;;
        *) FAILED="${FAILED}${FAILED:+ }${_rl_set}" ;;
    esac
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

# Раунд 4, П-12б: разбор зон server=/…/ из dnsmasq.conf — один раз за
# прогон, до фоновых заданий dig (каждый домен дальше читает кэш).
build_dnsmasq_zone_cache

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

# Временный отказ DNS не является ошибкой транзакции: боевые наборы
# сохранены, обновление переводится в defer (rc=75, EX_TEMPFAIL — уже
# принятая конвенция проекта). При смешанном исходе реальный сбой (FAILED)
# обрабатывается выше и побеждает.
if [ -n "$DNS_FAILED" ]; then
    if [ "${OPTIONAL_VPN:-0}" = "1" ]; then
        logger -t "unblock_ipset" "optional VPN deferred by DNS: $DNS_FAILED"
        echo "optional VPN deferred: $DNS_FAILED" >&2
        exit 1
    fi
    logger -t "unblock_ipset" \
        "DNS temporarily unavailable or degraded for: $DNS_FAILED; sets kept, update deferred (rc=75)"
    echo "DNS temporarily unavailable for: $DNS_FAILED; update deferred (rc=75)" >&2
    exit 75
fi

exit 0
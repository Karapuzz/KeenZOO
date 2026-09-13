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

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    ipset create "${unblockvpn}${IPSET_SUFFIX}" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    run_list "$vpn_file_names" "$unblockvpn"
done

if [ -n "$FAILED" ]; then
    logger -t "unblock_ipset" "process_list failed: $FAILED"
    echo "process_list failed: $FAILED" >&2
    exit 1
fi

exit 0
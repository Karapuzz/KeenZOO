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

HOSTS_FILE="${HOSTS_FILE:-/opt/etc/hosts}"

# Значения дублируют bot_config.py (pin_server_hosts, bootstrap_resolvers).
# Shell-скрипты проекта не разбирают Python-конфиг, а держат константы у
# себя — так же, как порты в 100-redirect.sh. Отключить пиннинг можно
# переменной окружения: PIN_ENABLED=0 /opt/bin/unblock_dnsmasq.sh
PIN_ENABLED="${PIN_ENABLED:-1}"

# Резервные публичные резолверы. ПУСТО по умолчанию: сторонние DNS в
# схеме не участвуют. Порядок резолвинга — DoT/DoH роутера, затем ранее
# закреплённый адрес из hosts, затем DNS провайдера. Список нужен лишь
# как ручной запас: BOOTSTRAP_RESOLVERS="1.2.3.4" /opt/bin/unblock_dnsmasq.sh
BOOTSTRAP_RESOLVERS="${BOOTSTRAP_RESOLVERS:-}"

# Домен сервера из конфига xray: берём address внутри vnext.
# python3 в shell-скриптах проекта не используется, поэтому разбор
# выполняется sed — структура конфига фиксирована шаблоном.
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

# ШАГ 3: резолверы провайдера из /tmp/resolv.conf. Идут последними —
# провайдер видит запрос и на ТСПУ работает подмена ответов через НСДИ,
# поэтому обращаемся к ним, только когда не помогли ни DoT/DoH роутера,
# ни собственный пин.
provider_resolver_list() {
    sed -n 's/^[[:space:]]*nameserver[[:space:]]\{1,\}\([0-9.]\{7,\}\).*/\1/p' \
        /tmp/resolv.conf 2>/dev/null | grep -v '^127\.' | head -2

    # Необязательный ручной запас. По умолчанию список пуст: сторонние
    # публичные DNS (Quad9, AdGuard, Яндекс) в схеме не участвуют.
    if [ -n "$BOOTSTRAP_RESOLVERS" ]; then
        printf '%s\n' "$BOOTSTRAP_RESOLVERS" | tr ' ' '\n' | grep -v '^$'
    fi
}

# Все A-записи домена. Порядок строго: DoT/DoH роутера → сохранённый
# пин из hosts → DNS провайдера. У сервера может быть несколько адресов
# — закрепляем все, иначе при смене узла пин укажет на недоступный IP.
resolve_pin_host() {
    _rp_host="$1"
    _rp_out=""

    # ШАГ 1. Штатный шифрованный DNS роутера (DoT, при отказе DoH).
    # Единственный источник, которому доверяем полностью.
    if [ -n "${DNS_PRIMARY:-}" ]; then
        _rp_out="$(dig +short +timeout=3 +tries=1 A "$_rp_host" \
            @localhost -p "$DNS_PRIMARY" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
    fi

    # ШАГ 2. Прежде закреплённый адрес. Домены прокси-серверов меняют IP
    # редко, поэтому вчерашняя запись почти всегда рабочая — и получена
    # она была через доверенный DoT/DoH, а не от провайдера.
    if [ -z "$_rp_out" ]; then
        _rp_out="$(pinned_hosts_lookup "$_rp_host" || true)"
        if [ -n "$_rp_out" ]; then
            logger -t "unblock_dnsmasq" \
                "pin: $_rp_host — DoT/DoH недоступны, оставлен прежний адрес"
        fi
    fi

    # ШАГ 3. DNS провайдера — последняя попытка.
    if [ -z "$_rp_out" ]; then
        for _rp_ns in $(provider_resolver_list); do
            # +tcp: перехват НСДИ работает преимущественно по UDP/53,
            # поэтому запрос по TCP имеет больше шансов дойти.
            _rp_out="$(dig +short +timeout=3 +tries=1 +tcp A "$_rp_host" \
                "@$_rp_ns" 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            if [ -n "$_rp_out" ]; then
                logger -t "unblock_dnsmasq" \
                    "pin: $_rp_host разрешён резолвером провайдера $_rp_ns"
                break
            fi
        done
    fi

    [ -n "$_rp_out" ] || return 1
    printf '%s\n' "$_rp_out"
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
# Проверка TCP-доступности адреса.
#
# Прежняя версия звала "nc -z -w4". Это оказалось ненадёжно:
#   * апплет nc в BusyBox прошивки Keenetic может отсутствовать вовсе
#     (в self-test роутера его нет), а пакет netcat проект не ставит;
#   * даже там, где nc есть, ключ -z поддерживается не всеми сборками —
#     BusyBox 1.36 его в справке не перечисляет.
# В обоих случаях команда возвращает ненулевой код, и КАЖДЫЙ сервер
# объявлялся недоступным. Пользователь видел предупреждение про все три
# адреса сразу, хотя обход исправно работал.
#
# Теперь пробуем несколько способов и, если ни один не доступен,
# считаем результат НЕИЗВЕСТНЫМ (успех), а не отказом: ложная тревога
# вреднее молчания — она обесценивает уведомление.
# Код возврата: 0 — доступен либо проверить нечем, 1 — точно недоступен.
tcp_probe() {
    _tp_ip="$1"
    _tp_port="$2"

    # 1. curl: есть всегда (проект ставит его при развёртывании).
    #    --connect-timeout ограничивает именно установку соединения.
    if command -v curl >/dev/null 2>&1; then
        # Код возврата снимается СРАЗУ после команды, отдельным
        # присваиванием. Внутри "if ...; then" переменная $? содержала бы
        # код самого if (всегда 0) — проверено запуском: реальный отказ
        # с кодом 7 терялся, и tcp_probe всегда рапортовала об успехе.
        curl -s --connect-timeout 4 --max-time 5 \
            -o /dev/null "telnet://${_tp_ip}:${_tp_port}" >/dev/null 2>&1
        _tp_rc=$?
        [ "$_tp_rc" = "0" ] && return 0
        # 7 — соединение отвергнуто или таймаут: реальный отказ.
        # Прочие коды (например 2 — неизвестный протокол) означают, что
        # способ неприменим, и надо пробовать следующий.
        [ "$_tp_rc" = "7" ] && return 1
    fi

    # 2. nc — если апплет есть и понимает -w.
    if command -v nc >/dev/null 2>&1; then
        if echo | nc -w 4 "$_tp_ip" "$_tp_port" >/dev/null 2>&1; then
            return 0
        fi
    fi

    # Проверить нечем — не поднимаем ложную тревогу.
    return 0
}

check_pinned_reachable() {
    _cpr_body="$1"
    _cpr_state="/tmp/keenzoo_pin_unreach"
    _cpr_bad=""

    printf '%s' "$_cpr_body" | while IFS="$(printf '\t')" read -r _ip _host; do
        [ -n "$_ip" ] && [ -n "$_host" ] || continue

        # Hysteria2 работает поверх QUIC (UDP). TCP-порт у такого сервера
        # закрыт штатно, и TCP-проба всегда давала бы «недоступен».
        # Проверить UDP из shell нечем — пропускаем этот адрес.
        if [ "$_host" = "$(hysteria_server_host)" ]; then
            continue
        fi

        _port="$(proto_port_for_host "$_host")"
        tcp_probe "$_ip" "$_port" || \
            printf '%s:%s (%s)\n' "$_ip" "$_port" "$_host"
    done > "${_cpr_state}.now" 2>/dev/null || true

    if [ -s "${_cpr_state}.now" ]; then
        _cpr_bad="$(tr '\n' ' ' < "${_cpr_state}.now")"
        logger -t "unblock_dnsmasq" \
            "pin: сервер недоступен: $_cpr_bad"
        # Уведомляем только если список изменился с прошлого раза.
        if ! cmp -s "${_cpr_state}.now" "$_cpr_state" 2>/dev/null; then
            pin_notify "⚠️ Сервер обхода недоступен: ${_cpr_bad}
Адрес мог смениться. Обновите ключ в панели или боте." warn
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

    # Сохранённый адрес мог устареть: сервер сменил IP, а DoT/DoH были
    # недоступны и обновить пин не удалось. Внешне всё выглядит рабочим —
    # пин на месте, сервис запущен, — но туннель стучится в пустоту.
    # Проверяем каждый закреплённый адрес TCP-коннектом и предупреждаем
    # пользователя, чтобы он обновил ключ.
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

update_pinned_hosts

append_domain_rules() {
    _host="$1"
    _setname="$2"
    _dns_port="$3"
    _backup_port="$4"

    # Одно правило на домен: dnsmasq сам распространяет его на поддомены.
    printf 'ipset=/%s/%s\n' "$_host" "$_setname" >> "$TMP_OUT"
    printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_dns_port" >> "$TMP_OUT"
    if [ -n "$_backup_port" ]; then
        printf 'server=/%s/127.0.0.1#%s\n' "$_host" "$_backup_port" >> "$TMP_OUT"
    fi
}

process_dnsmasq_list() {
    _file="$1"
    _setname="$2"
    _dns_port="$3"

    [ -f "$_file" ] || return 0

    _backup_port=""
    if [ "$_dns_port" != "9053" ] && [ -n "$DNS_BACKUP" ] && [ "$DNS_BACKUP" != "$_dns_port" ]; then
        _backup_port="$DNS_BACKUP"
    fi

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

        append_domain_rules "$_host" "$_setname" "$_dns_port" "$_backup_port"
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

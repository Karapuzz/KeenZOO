#!/bin/sh
# /opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh
# Реакция на изменение состояния интерфейсов прошивки.
#   Клиентский VPN (выход в интернет через туннель) -> таблица маршрутизации,
#   fwmark-правило и список /opt/etc/unblock/vpn-<описание>-<id>.txt.
#   Серверный VPN (WireGuard для удалённого доступа к роутеру) -> НЕ создаёт
#   таблицу и список; его клиенты обслуживаются общими правилами обхода
#   из 100-redirect.sh (интерфейс входит в LAN_IFACE_PATTERNS).
# Оболочка: BusyBox ash.

set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

TAG="100-unblock-vpn.sh"
RT_TABLES="/opt/etc/iproute2/rt_tables"
BOT_CONFIG="/opt/etc/bot/bot_config.py"
RCI="localhost:79/rci"

sleep 1

rci_get() {
    curl -s --max-time 5 "${RCI}/$1" 2>/dev/null || true
}

check_allow_vpn_in_config="$(
    grep 'vpn_allowed' "$BOT_CONFIG" 2>/dev/null \
        | head -1 | sed 's/=/ /g' | tr -d '"' | awk '{print $2}' || true
)"

if [ -z "$check_allow_vpn_in_config" ]; then
    vpn_services="IKE|SSTP|OpenVPN|Wireguard|L2TP"
else
    vpn_services="$check_allow_vpn_in_config"
fi

# Нельзя искать VPN глобальным grep по show/interface: RCI возвращает
# интерфейсы вложенными блоками, и строка id соседнего блока WAN/Bridge
# ошибочно приклеивалась к найденному типу VPN. Сначала извлекаем id из
# собственных строк id, затем проверяем конфигурацию именно этого id.
rci_interface_ids() {
    rci_get "show/interface" | sed -nE \
        -e 's/.*[" ]id[" ]*[=:][ ]*"?([^",} ]+)"?.*/\1/p' \
        -e 's/^[[:space:]]*id[[:space:]]*[=:][[:space:]]*"?([^",} ]+)"?.*/\1/p' \
        | sed '/^$/d' | sort -u
}

interface_cfg() {
    rci_get "show/rc/interface/$1"
}

# Физические WAN, мосты и системные зоны никогда не являются клиентскими
# VPN policy-интерфейсами. Это явное исключение защищает даже при странном
# или неполном RCI-ответе.
is_forbidden_interface() {
    case "$1" in
        GigabitEthernet*|Ethernet*|Bridge*|ISP|Home|Guest|WifiMaster*|\
        WifiStation*|AccessPoint*|Mobile*|Cellular*|LTE*|Lte*|\
        Usb*|UsbModem*|CdcEthernet*|Qmi*|Mbim*|Modem*|Pppoe*) return 0 ;;
    esac
    return 1
}

is_vpn_interface() {
    _ivi_id="$1"
    is_forbidden_interface "$_ivi_id" && return 1

    _ivi_cfg="$(interface_cfg "$_ivi_id")"
    # Дополнительная защита для LTE/USB-модемов, чьи логические имена
    # различаются между моделями Keenetic. Они являются WAN, даже если RCI
    # отдал их рядом с VPN-блоком.
    _ivi_link_kind="$(printf '%s\n' "$_ivi_cfg" \
        | grep -Ei 'type|technology|kind|transport|device' | head -20 || true)"
    printf '%s\n' "$_ivi_link_kind" \
        | grep -Eiq 'ethernet|usb|mobile|cellular|lte|modem|qmi|mbim' \
        && return 1

    # ID Wireguard0 есть в NDM, тогда как kernel-имя его устройства в
    # приложенном выводе — nwg0. Не отбрасываем его из-за несовпадения имён.
    case "$_ivi_id" in
        Wireguard*|OpenVPN*|SSTP*|L2TP*|IKE*) return 0 ;;
    esac

    printf '%s\n' "$_ivi_cfg" \
        | grep -Eiq "${vpn_services}|wireguard|openvpn|sstp|l2tp|ike"
}

# Удаление ошибочно созданного состояния выполняется только после проверки
# policy table и правил. В частности, это чистит старый набор
# unblockvpn-Подключение_Ethernet-GigabitEthernet1, если он пережил старый
# запуск проекта.
remove_rt_table_name() {
    _rrtn_name="$1"
    _rrtn_tmp="${RT_TABLES}.tmp.$$"
    awk -v n="$_rrtn_name" '$2 != n' "$RT_TABLES" > "$_rrtn_tmp" 2>/dev/null \
        && mv -f "$_rrtn_tmp" "$RT_TABLES" || rm -f "$_rrtn_tmp"
}

purge_forbidden_vpn_file() {
    _pf_file="$1"
    _pf_base="$(basename "$_pf_file" .txt)"
    _pf_if="${_pf_base##*-}"
    is_forbidden_interface "$_pf_if" || return 0

    _pf_set="unblock${_pf_base}"
    _pf_table_name="$(printf '%s' "$_pf_if" | tr '[:upper:]' '[:lower:]')"
    _pf_table_id="$(grep -w "$_pf_table_name" "$RT_TABLES" 2>/dev/null \
        | awk '{print $1}' | head -n1 || true)"
    if [ -n "$_pf_table_id" ]; then
        _pf_mark="0xd${_pf_table_id}"
        _pf_routes="$(ip -4 route show table "$_pf_table_id" 2>/dev/null \
            | wc -l | awk '{print $1}')"
        _pf_rules="$(ip -4 rule show 2>/dev/null \
            | grep -cE "table $_pf_table_id|fwmark $_pf_mark" || true)"
        logger -t "$TAG" "prune forbidden VPN $_pf_if: table=$_pf_table_id routes=$_pf_routes rules=$_pf_rules set=$_pf_set"

        # Сначала снимаем iptables references, затем уничтожаем ipset.
        # Иначе ipset destroy может быть отвергнут ядром как busy.
        if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
            PURGE_VPN_SET="$_pf_set" PURGE_VPN_MARK="$_pf_mark" \
                type=iptable table=mangle \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
        fi
        ip -4 rule del from all table "$_pf_table_id" priority 1778 \
            >/dev/null 2>&1 || true
        ip -4 rule del fwmark "$_pf_mark" lookup "$_pf_table_id" priority 1778 \
            >/dev/null 2>&1 || true
        ip -4 route flush table "$_pf_table_id" >/dev/null 2>&1 || true
        remove_rt_table_name "$_pf_table_name"
    else
        logger -t "$TAG" "prune forbidden VPN $_pf_if: policy table absent, set=$_pf_set"
    fi

    ipset flush "$_pf_set" >/dev/null 2>&1 || true
    ipset destroy "${_pf_set}_new" >/dev/null 2>&1 || true
    ipset destroy "$_pf_set" >/dev/null 2>&1 || true
    rm -f "$_pf_file"
    logger -t "$TAG" "forbidden VPN state removed: $_pf_if / $_pf_set"
}

mkdir -p /opt/etc/iproute2
[ -f "$RT_TABLES" ] || : > "$RT_TABLES"
chmod 644 "$RT_TABLES"

# Убираем только заведомо запрещённые WAN/Bridge-файлы. Валидные client VPN
# не трогаются, даже если сейчас disconnected.
for _pf_file in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$_pf_file" ] || continue
    purge_forbidden_vpn_file "$_pf_file"
done

# unblock_update.sh вызывает этот скрипт в режиме только очистки перед
# сборкой списков, чтобы старый WAN-set не успел попасть в dnsmasq/ipset.
[ "${PRUNE_ONLY:-0}" = "1" ] && exit 0

vpn_check="$(
    for _rci_id in $(rci_interface_ids); do
        is_vpn_interface "$_rci_id" && printf '%s\n' "$_rci_id"
    done
)"

# ═════════════════════════════════════════════════════════════════════════
# Определение роли интерфейса: клиент (выход в интернет) или сервер (доступ)
# ═════════════════════════════════════════════════════════════════════════
# Роль определяется по роли самого интерфейса и маршрутизации. Endpoint
# peer НИКОГДА не используется как единственный признак client: у
# серверного WireGuard endpoint может появляться после handshake.
is_client_tunnel() {
    _ict_id="$1"
    _ict_cfg="$(interface_cfg "$_ict_id")"

    # KN-1012 не реализует RCI-запрос роли интерфейса: такой вызов
    # давал в журнале сообщение «not found». Роль определяется по
    # конфигурации и маршрутизации, без неподдерживаемого endpoint.

    # Listen-port/server/listen признаки относятся к локальному серверу
    # WireGuard. Allowed IP и endpoint peer здесь намеренно не проверяются:
    # у серверного WireGuard могут быть peers с endpoint после handshake.
    case "$_ict_id" in
        Wireguard*)
            if printf '%s\n' "$_ict_cfg" \
                | grep -Eiq 'listen[-_ ]?port|listen[=:]|server[=:]'; then
                return 1
            fi
            ;;
    esac

    _ict_global="$(rci_get "show/interface/${_ict_id}/global" \
        | tr -d '"' | tr -d ' ' | tr '[:upper:]' '[:lower:]')"
    [ "$_ict_global" = "true" ] && return 0

    _ict_defaultgw="$(rci_get "show/interface/${_ict_id}/defaultgw" \
        | tr -d '"' | tr -d ' ' | tr '[:upper:]' '[:lower:]')"
    [ "$_ict_defaultgw" = "true" ] && return 0

    # Неизвестная роль безопасно считается server/access: policy routing
    # нельзя включать на обычном интерфейсе и нельзя делать WAN-утечку.
    return 1
}

# Очистка состояния клиентского VPN при disconnected/down. Файл списка
# сохраняется: при следующем подключении он снова может быть заполнен, но
# policy rule, маршруты, mark и старые адреса не должны переживать туннель.
cleanup_client_vpn() {
    _cc_vpn="$1"
    _cc_table_name="$(printf '%s' "$_cc_vpn" | tr '[:upper:]' '[:lower:]')"
    _cc_table_id="$(grep -w "$_cc_table_name" "$RT_TABLES" 2>/dev/null \
        | awk '{print $1}' | head -n1 || true)"
    [ -n "$_cc_table_id" ] || return 0

    _cc_mark="0xd${_cc_table_id}"
    ip -4 rule del from all table "$_cc_table_id" priority 1778 \
        >/dev/null 2>&1 || true
    ip -4 rule del fwmark "$_cc_mark" lookup "$_cc_table_id" priority 1778 \
        >/dev/null 2>&1 || true
    ip -4 route flush table "$_cc_table_id" >/dev/null 2>&1 || true

    # Все списки, созданные для этого интерфейса, имеют суффикс -<id>.
    for _cc_list in /opt/etc/unblock/vpn-*-"$_cc_vpn".txt; do
        [ -f "$_cc_list" ] || continue
        _cc_set="unblock$(basename "$_cc_list" .txt)"
        ipset flush "$_cc_set" >/dev/null 2>&1 || true
    done

    logger -t "$TAG" "VPN $_cc_vpn OFF: policy rules, routes and ipset cleared"
    if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        type=iptable table=nat \
            /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
        type=iptable table=mangle \
            /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    fi
}

# RCI может на короткое время убрать интерфейс из show/interface раньше,
# чем hook передаст disconnected. Добавляем переданный id в обработку.
if [ "${1:-}" = "hook" ] && [ -n "${id:-}" ]; then
    # RCI иногда сообщает id до того, как он появился в show/interface,
    # но добавлять можно только структурно подтверждённый VPN id.
    if is_vpn_interface "$id"; then
        case " $vpn_check " in
            *" $id "*) ;;
            *) vpn_check="$vpn_check $id" ;;
        esac
    fi
fi

for vpn in $vpn_check; do
    [ "${1:-}" = "hook" ] || continue
    [ "${id:-}" = "$vpn" ] || continue

    case "${change:-}" in
        disconnected|down|stopped)
            # Серверный WireGuard не создаёт таблицу, поэтому наличие
            # записи в rt_tables безопасно отличает клиентский туннель.
            cleanup_client_vpn "$vpn"
            continue
            ;;
        connected) ;;
        *) continue ;;
    esac

    if ! is_client_tunnel "$vpn"; then
        # Серверный туннель (например, WireGuard для удалённого управления).
        # Никаких таблиц/списков — только сообщение в лог. Клиенты такого
        # туннеля получают обход через общие правила 100-redirect.sh.
        logger -t "$TAG" "VPN $vpn: серверный режим, policy routing пропущен"
        [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ] \
            && type=iptable table=nat /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 \
            || true
        continue
    fi

    vpn_table="$(printf '%s' "$vpn" | tr '[:upper:]' '[:lower:]')"

    if grep -qw "$vpn_table" "$RT_TABLES" 2>/dev/null; then
        logger -t "$TAG" "VPN $vpn: таблица уже есть"
    else
        get_last_fwmark_id="$(awk '{print $1}' "$RT_TABLES" 2>/dev/null | tail -1 || true)"
        if [ -n "$get_last_fwmark_id" ]; then
            counter_new=$((get_last_fwmark_id + 1))
        else
            counter_new=1001
        fi
        printf '%s %s\n' "$counter_new" "$vpn_table" >> "$RT_TABLES"
        logger -t "$TAG" "VPN $vpn: создана таблица $counter_new"
    fi

    sleep 1
    vpn_table_id="$(grep -w "$vpn_table" "$RT_TABLES" | awk '{print $1}' | head -n1)"
    [ -n "$vpn_table_id" ] || continue
    get_fwmark_id="0xd${vpn_table_id}"

    vpn_link_up="$(rci_get "show/interface/${vpn}/connected" | tr -d '"')"

    case "$vpn_link_up" in
        yes|up) ;;
        *)
            cleanup_client_vpn "$vpn"
            continue
            ;;
    esac

    sleep 2
    sleep 3
    vpn_ip="$(rci_get "show/interface/${vpn}/address" | tr -d '"')"
    [ -n "$vpn_ip" ] || { cleanup_client_vpn "$vpn"; continue; }

    vpn_dev="$(rci_get "show/interface/${vpn}/interface-name" | tr -d '"')"
    if [ -z "$vpn_dev" ]; then
        vpn_dev="$(ip -4 addr show 2>/dev/null \
            | awk -v a="$vpn_ip" '/^[0-9]+:/{dev=$2} $1=="inet" && $2 ~ "^"a"/" {gsub(":","",dev); print dev; exit}')"
    fi
    [ -n "$vpn_dev" ] || { cleanup_client_vpn "$vpn"; continue; }

    vpn_name="$(rci_get "show/interface/${vpn}/description" | tr -d '"' | tr ' ' '_')"
    [ -n "$vpn_name" ] || vpn_name="vpn"
    unblockvpn="unblockvpn-${vpn_name}-${vpn}"
    vpn_list="/opt/etc/unblock/vpn-${vpn_name}-${vpn}.txt"

    ip -4 route replace table "$vpn_table_id" default via "$vpn_ip" dev "$vpn_dev" 2>/dev/null || true
    ip -4 route show table main | grep -Ev '^default' | while read -r ROUTE; do
        [ -n "$ROUTE" ] || continue
        ip -4 route replace table "$vpn_table_id" $ROUTE 2>/dev/null || true
    done
    ip -4 rule del fwmark "$get_fwmark_id" lookup "$vpn_table_id" priority 1778 2>/dev/null || true
    ip -4 rule add fwmark "$get_fwmark_id" lookup "$vpn_table_id" priority 1778 2>/dev/null || true
    ip -4 route flush cache 2>/dev/null || true

    [ -f "$vpn_list" ] || : > "$vpn_list"
    chmod 0644 "$vpn_list"

    ipset create "$unblockvpn" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true

    logger -t "$TAG" "VPN $vpn ON: $vpn_name $vpn_ip via $vpn_dev"

    [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ] \
        && type=iptable table=nat /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 \
        || true
done

# ═════════════════════════════════════════════════════════════════════════
# Восстановление после смены канала (актуально для LTE/USB-модема)
# ═════════════════════════════════════════════════════════════════════════
# Все сервисы проекта, кроме hysteria, при старте лишь открывают локальный
# сокет и идут наружу по первому запросу клиента — разрыв WAN они
# переживают сами. Hysteria (без lazy) устанавливает QUIC-сессию сразу и
# при обрыве может завершиться. Перезапускать её было некому: в этом хуке
# init-скрипты не вызывались, а 100-redirect.sh при мёртвом сервисе лишь
# снимает его правила. Итог — UDP из hysteria.txt шёл напрямую до ручного
# вмешательства.
#
# Поднимаются ТОЛЬКО мёртвые сервисы: безусловный перезапуск рвал бы
# рабочие соединения при каждом изменении состояния интерфейса.

# Событие приходит пачками: в журнале зафиксировано до 8 срабатываний за
# минуту на одно переподключение. Без защиты сервисы перезапускались бы
# каскадом. Каталог-замок атомарен в BusyBox ash (mkdir), stale-замок
# старше 5 минут снимается.
WD_LOCK="/tmp/unblock_ifup.lockdir"
WD_STAMP="/tmp/unblock_ifup.stamp"
# Интервал больше, чем длится фоновая работа. Родитель завершается сразу
# (иначе прошивка убивает хук по таймауту) и снимает замок, поэтому от
# наложения двух фоновых веток защищает именно эта пауза: запуск пяти
# init-скриптов занимает до ~40 с (hysteria одна поднималась 17 с),
# плюс sleep 5 и переустановка правил.
WD_MIN_INTERVAL=90

if [ -d "$WD_LOCK" ]; then
    _wd_age_ok=0
    if [ -f "$WD_LOCK/ts" ]; then
        _wd_t="$(cat "$WD_LOCK/ts" 2>/dev/null || echo 0)"
        case "$_wd_t" in ''|*[!0-9]*) _wd_t=0 ;; esac
        _wd_now="$(date +%s 2>/dev/null || echo 0)"
        [ $((_wd_now - _wd_t)) -gt 300 ] && _wd_age_ok=1
    else
        _wd_age_ok=1
    fi
    if [ "$_wd_age_ok" = "1" ]; then
        rm -rf "$WD_LOCK" 2>/dev/null || true
    else
        exit 0
    fi
fi

mkdir "$WD_LOCK" 2>/dev/null || exit 0
date +%s > "$WD_LOCK/ts" 2>/dev/null || true
# Замок снимается при любом выходе, включая ошибку.
trap 'rm -rf "$WD_LOCK" 2>/dev/null || true' EXIT INT TERM

# Антидребезг: не чаще одного прогона в WD_MIN_INTERVAL секунд.
_wd_now="$(date +%s 2>/dev/null || echo 0)"
if [ -f "$WD_STAMP" ]; then
    _wd_prev="$(cat "$WD_STAMP" 2>/dev/null || echo 0)"
    case "$_wd_prev" in ''|*[!0-9]*) _wd_prev=0 ;; esac
    if [ $((_wd_now - _wd_prev)) -lt "$WD_MIN_INTERVAL" ]; then
        exit 0
    fi
fi

# Есть ли вообще выход в интернет: без маршрута по умолчанию поднимать
# сервисы бессмысленно — они снова упадут. Событие «интерфейс погас»
# отсекается здесь же.
if ! ip -4 route show default 2>/dev/null | grep -q .; then
    exit 0
fi

printf '%s' "$_wd_now" > "$WD_STAMP" 2>/dev/null || true

# Живость определяется так же, как в 100-redirect.sh: по argv[0] в /proc.
# Подстрочный поиск по всей командной строке принимал бы за живой сервис
# посторонний процесс (например "vi /opt/etc/hysteria/config.json").
wd_proc_alive() {
    _wd_p="$1"
    for _wd_d in /proc/[0-9]*; do
        # Читаем через cat: процесс может исчезнуть между раскрытием
        # маски и открытием файла, а сообщение оболочки о неудачном
        # перенаправлении "< файл" не подавляется через 2>/dev/null
        # у команды — оно попадало в журнал роутера как ошибка скрипта.
        _wd_a0="$(cat "$_wd_d/cmdline" 2>/dev/null | tr '\0' '\n' | head -1)"
        [ -n "$_wd_a0" ] || continue
        [ "${_wd_a0##*/}" = "$_wd_p" ] && return 0
    done
    return 1
}

# Отключённый в панели сервис (ENABLED=no) поднимать нельзя: это штатный
# признак того, что пользователь выключил протокол.
wd_revive() {
    _wd_init="/opt/etc/init.d/$1"
    _wd_procs="$2"

    [ -x "$_wd_init" ] || return 0
    grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_wd_init" 2>/dev/null && return 0
    wd_proc_alive "$_wd_procs" && return 0

    "$_wd_init" start >/dev/null 2>&1 || true
    WD_REVIVED=1
    logger -t "$TAG" "WAN up: перезапущен $1"
}

WD_REVIVED=0

# ВСЯ восстановительная работа выполняется в фоне.
#
# Раньше wd_revive вызывался синхронно, и хук не возвращал управление,
# пока не отработают все пять init-скриптов. Запуск одного сервиса через
# rc.func занимает секунды (hysteria в журнале — 17 с: она поднимает QUIC
# и ждёт появления процесса), пять подряд не укладывались в лимит
# прошивки, и ndm убивал хук:
#   ndm: Opkg::Manager: .../100-unblock-vpn.sh: timed out.
#   ndm: Process: "Opkg shell" has been killed.
# Обрыв приходился на середину: сервис стартовал, а переустановка правил
# уже не выполнялась — в таблицах не появлялось match-set, и в журнале
# бесконечно повторялось "hysteria не запущен".
#
# Замок снимается здесь же, в фоновом процессе, поэтому trap EXIT из
# основной ветки переносить не нужно: он сработает при выходе родителя,
# а дочерний процесс держит собственную копию пути и удалит каталог
# повторно — rm -rf к этому терпим.
(
    trap '' HUP

    wd_revive S57hysteria hysteria
    wd_revive S24xray     xray
    wd_revive S22trojan   trojan
    wd_revive S65shadowsocks ss-redir
    wd_revive S35tor      tor

    # Если сервис был поднят — правила перехвата для него ещё не созданы.
    # 100-redirect.sh намеренно пропускает мёртвые сервисы (правило на
    # неслушающий порт = чёрная дыра), поэтому на момент его прошлого
    # запуска правил для лежавшего сервиса не появилось. Без повторного
    # вызова они не возникнут до следующего события прошивки.
    #
    # Пауза нужна, чтобы сервис успел открыть слушающий сокет:
    # svc_enabled проверяет живость процесса, а стартует он не мгновенно.
    if [ "$WD_REVIVED" = "1" ]; then
        sleep 5
        if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
            type=iptable table=nat \
                /opt/etc/ndm/netfilter.d/100-redirect.sh \
                >/dev/null 2>&1 || true
            type=iptable table=mangle \
                /opt/etc/ndm/netfilter.d/100-redirect.sh \
                >/dev/null 2>&1 || true
            type=iptable table=filter \
                /opt/etc/ndm/netfilter.d/100-redirect.sh \
                >/dev/null 2>&1 || true
            logger -t "$TAG" "WAN up: правила перехвата переустановлены"
        fi
    fi
) >/dev/null 2>&1 </dev/null &

# Смена канала почти всегда означает новый внешний адрес, поэтому пин
# адресов серверов обновляется: к ним подключаются сами туннели, и
# устаревший IP рвёт связь. Это всего пара DNS-запросов.
#
# unblock_update.sh здесь НЕ вызывается намеренно. Списки обхода от
# разрыва канала не меняются, а полный прогон резолвит все домены из
# них (сотни запросов) и пересоздаёт 12 наборов ipset. На «моргающем»
# LTE это давало непрерывную череду обновлений и сообщения "locked"
# в панели. Наборы ipset живут в ядре и разрыв переживают, а новые
# адреса dnsmasq докладывает в них сам — по директивам ipset=/домен/набор
# при каждом запросе клиента. Списки обновляются штатно: cron в 06:00,
# S99unblock при загрузке и кнопка в панели.
# Запуск в фоне: хук не должен задерживать обработку события прошивкой.
(
    trap '' HUP
    # Сервисам нужно время подняться, а каналу — стабилизироваться.
    sleep 10
    [ -x /opt/bin/unblock_dnsmasq.sh ] \
        && /opt/bin/unblock_dnsmasq.sh >/dev/null 2>&1 || true
    logger -t "$TAG" "WAN up: endpoint pin and dnsmasq interfaces refreshed"
) >/dev/null 2>&1 </dev/null &

exit 0

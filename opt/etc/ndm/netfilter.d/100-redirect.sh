#!/bin/sh
# /opt/etc/ndm/netfilter.d/100-redirect.sh
# Перехват трафика для списков обхода.
#   TCP  -> nat/REDIRECT на локальные порты прокси.
#   UDP  -> mangle/TPROXY (vless, hysteria) либо nat/REDIRECT (shadowsocks).
# Оболочка: BusyBox ash (#!/bin/sh), без bash-измов.

set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# ─────────────────────────────────────────────────────────────────────
# IPv6: закрыть прокси-порты от внешней сети.
# ─────────────────────────────────────────────────────────────────────
# Перехват трафика (REDIRECT/TPROXY) реализован только для IPv4, но
# xray (Go) на "listen": "0.0.0.0" создаёт DUAL-STACK сокет и реально
# слушает :::10810 — то есть принимает и IPv6-подключения. Правила
# iptables на них не действуют, поэтому порт оставался открытым по
# IPv6. Здесь для ip6tables создаются только запрещающие правила:
# разрешён loopback и внутренние диапазоны (ULA fc00::/7,
# link-local fe80::/10), остальное отбрасывается.
if [ "${type:-}" = "ip6tables" ]; then
    [ "${table:-}" = "filter" ] || exit 0

    IPT6="$(command -v ip6tables 2>/dev/null || true)"
    [ -n "$IPT6" ] || exit 0
    IPT6="$IPT6 -w"

    for p6 in 1082 9141 10810 10829 10830 8080; do
        for pr6 in tcp udp; do
            while $IPT6 -D INPUT -p "$pr6" --dport "$p6" \
                -j DROP >/dev/null 2>&1
            do
                :
            done

            if ! $IPT6 -C INPUT -i lo -p "$pr6" \
                --dport "$p6" -j ACCEPT >/dev/null 2>&1
            then
                $IPT6 -I INPUT -i lo -p "$pr6" \
                    --dport "$p6" -j ACCEPT >/dev/null 2>&1 || true
            fi

            for n6 in ::1/128 fc00::/7 fe80::/10; do
                if ! $IPT6 -C INPUT -p "$pr6" --dport "$p6" \
                    -s "$n6" -j ACCEPT >/dev/null 2>&1
                then
                    $IPT6 -I INPUT -p "$pr6" --dport "$p6" \
                        -s "$n6" -j ACCEPT >/dev/null 2>&1 || true
                fi
            done

            $IPT6 -A INPUT -p "$pr6" --dport "$p6" \
                -j DROP >/dev/null 2>&1 || true
        done
    done
    exit 0
fi

# filter тоже обрабатывается: в нём живут правила доступа к веб-панели.
case "${table:-}" in
    mangle|nat|filter) ;;
    *) exit 0 ;;
esac

TAG="100-redirect.sh"

# На Keenetic нет logread, а вывод logger в syslog прошивки недоступен
# обычными средствами. Поэтому диагностика дублируется в файл.
REDIRECT_LOG="/opt/var/log/100-redirect.log"
mkdir -p /opt/var/log 2>/dev/null || true

# Хук вызывается при каждом изменении состояния интерфейсов, поэтому лог
# обязан быть самоограниченным: пишем ТОЛЬКО ошибки и держим файл в
# пределах 64 КБ, оставляя последние 100 строк. Иначе накопитель с
# Entware со временем переполнится.
REDIRECT_LOG_MAX=65536
REDIRECT_LOG_KEEP=100

log_msg() {
    logger -t "$TAG" "$*" 2>/dev/null || true

    _lsz="$(wc -c < "$REDIRECT_LOG" 2>/dev/null || echo 0)"
    case "$_lsz" in
        ''|*[!0-9]*) _lsz=0 ;;
    esac
    if [ "$_lsz" -gt "$REDIRECT_LOG_MAX" ]; then
        _ltmp="${REDIRECT_LOG}.tmp.$$"
        if tail -n "$REDIRECT_LOG_KEEP" "$REDIRECT_LOG" \
            > "$_ltmp" 2>/dev/null; then
            mv -f "$_ltmp" "$REDIRECT_LOG" 2>/dev/null || rm -f "$_ltmp"
        else
            rm -f "$_ltmp"
        fi
    fi

    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" \
        >> "$REDIRECT_LOG" 2>/dev/null || true
}
# Пакет Entware "iptables" ставит /opt/sbin/iptables, где есть только
# libxt_CT/libxt_conntrack — расширений TPROXY, socket и set в нём НЕТ.
# Так как /opt/sbin в PATH первым, правила молча не создавались
# ("Couldn't load target `TPROXY'"). Прошивочный iptables Keenetic их умеет.
# Проверка расширения по ВЫВОДУ, а не по коду возврата: iptables на
# неизвестную цель печатает общую справку и выходит с 0, поэтому
# "iptables -j TPROXY --help >/dev/null; echo $?" даёт 0 даже там, где
# TPROXY нет. Из-за этого выбирался ущербный /opt/sbin/iptables.
# Определение возможностей iptables.
#
# Заголовок справки — основной признак, но полагаться ТОЛЬКО на него нельзя:
# формат отличается между сборками (двоеточие, регистр, отступ), а часть
# расширений вкомпилирована в libiptext.so и печатает заголовок иначе.
# Проверено на KN-2311: libiptext.so содержит и "TPROXY target options:",
# и "set match options:", то есть пакет Entware способен на TPROXY и
# --match-set, хотя отдельных libxt_set.so/libxt_TPROXY.so в нём нет.
# Прежний детектор с жёстким "^" давал ложный отрицательный вердикт, и
# проект без нужды уходил в деградированный режим.
#
# Поэтому проверка двухуровневая: текст справки, а при неудаче — наличие
# характерных опций расширения в том же выводе.
ipt_has_target() {
    _iht_out="$("$1" -j "$2" --help 2>&1 || true)"
    printf '%s' "$_iht_out" | grep -qi "$2 target options" && return 0
    case "$2" in
        TPROXY)
            printf '%s' "$_iht_out" | grep -q -- '--on-port' && return 0
            ;;
    esac
    return 1
}

ipt_has_match() {
    _ihm_out="$("$1" -m "$2" --help 2>&1 || true)"
    printf '%s' "$_ihm_out" | grep -qi "$2 match options" && return 0
    case "$2" in
        set)
            printf '%s' "$_ihm_out" | grep -q -- '--match-set' && return 0
            ;;
    esac
    return 1
}

ipt_is_capable() {
    ipt_has_target "$1" TPROXY && ipt_has_match "$1" set
}

pick_iptables() {
    # Прошивочный iptables Keenetic содержит libxt_TPROXY/socket/set.
    # Пакет Entware iptables (1.4.21) несёт только CT/conntrack и при этом
    # перекрывает прошивочный в PATH (/opt/sbin идёт первым).
    # На Keenetic /usr/sbin/iptables отсутствует — прошивочный бинарник
    # лежит в других каталогах, поэтому список кандидатов широкий.
    # Прошивочный бинарник на разных моделях лежит по-разному: на KN-2311
    # его нет ни в /usr/sbin, ни в /sbin. Поэтому список расширен, а после
    # абсолютных путей выполняется поиск по всей файловой системе прошивки.
    for _c in /usr/sbin/iptables /sbin/iptables /bin/iptables \
        /usr/bin/iptables /usr/local/sbin/iptables \
        /tmp/sbin/iptables /tmp/usr/sbin/iptables \
        /opt/sbin/iptables /opt/bin/iptables; do
        [ -x "$_c" ] || continue
        if ipt_is_capable "$_c"; then
            printf '%s' "$_c"
            return 0
        fi
    done

    # Прошивочный iptables мог оказаться в нестандартном каталоге —
    # ищем любые экземпляры вне /opt и проверяем каждый.
    for _c in $(ls -d /usr/sbin/iptables* /sbin/iptables* /bin/iptables* \
        /tmp/sbin/iptables* 2>/dev/null); do
        case "$_c" in *-save|*-restore|*multi*) continue ;; esac
        [ -x "$_c" ] || continue
        if ipt_is_capable "$_c"; then
            printf '%s' "$_c"
            return 0
        fi
    done

    # По абсолютным путям не нашли — пробуем то, что даёт PATH.
    _c="$(command -v iptables 2>/dev/null || true)"
    if [ -n "$_c" ] && ipt_is_capable "$_c"; then
        printf '%s' "$_c"
        return 0
    fi

    # Ни один не умеет TPROXY. Берём первый существующий, иначе имя из
    # PATH — путь /usr/sbin/iptables на Keenetic не существует, и
    # возвращать его нельзя (получили бы "not found").
    for _c in /usr/sbin/iptables /sbin/iptables /bin/iptables \
        /usr/bin/iptables /opt/sbin/iptables; do
        [ -x "$_c" ] && { printf '%s' "$_c"; return 0; }
    done
    printf 'iptables'
}

IPT_BIN="$(pick_iptables)"
IPT="$IPT_BIN -w"

# ── Порты локальных прокси ───────────────────────────────────────────────
PORT_SS=1082
PORT_TOR=9141
PORT_VLESS=10810
PORT_TROJAN=10829
PORT_HYSTERIA=10830
# Порт веб-панели (generator.py). Держится здесь, чтобы
# правила доступа переустанавливались вместе с остальными.
PORT_WEB=8080

# ── TPROXY: отдельная метка и таблица маршрутизации ──────────────────────
# Маска гарантирует отсутствие пересечения с VPN-метками вида 0xd1001.
# Метка вынесена в старший бит (0x1000000). VPN-марки формируются как
# 0xd<table_id>, где table_id растёт от 1001; начиная с table_id=1100
# значение 0xd1100 задевало бы бит 0x100 и трафик VPN ошибочно уходил
# бы в TPROXY-таблицу. Бит 24 в марки вида 0xdXXXX не попадает никогда.
TPROXY_MARK="0x1000000"
TPROXY_MASK="0x1000000"

# Метка исходящих пакетов самого xray (sockopt.mark в outbound). Служит
# только для RETURN в OUTPUT, чтобы трафик прокси не заворачивался в него
# же. Значение не пересекается ни с TPROXY_MARK, ни с VPN-марками 0xdXXXX.
XRAY_MARK="0x2000000"
TPROXY_TABLE=100
TPROXY_RULE_PRIO=1770

# ── Внутренние (клиентские) интерфейсы ───────────────────────────────────
# Правила обхода обязаны действовать одинаково для LAN, Wi-Fi, гостевой
# сети и для клиентов, подключённых к роутеру по VPN (в т.ч. WireGuard
# сервер прошивки: nwg*, wg*). Список фильтруется по факту существования
# интерфейса, чтобы не плодить мёртвые правила.
LAN_IFACE_PATTERNS="br0 br1 br2 wlan0 wlan1 wlan2 wlan3 nwg0 nwg1 nwg2 wg0 wg1 tun0 tap0 ppp-l2tp0 sstp0"

lan_ifaces() {
    _li_out=""
    for _li_if in $LAN_IFACE_PATTERNS; do
        if ip link show "$_li_if" >/dev/null 2>&1; then
            _li_out="${_li_out}${_li_out:+ }${_li_if}"
        fi
    done
    [ -n "$_li_out" ] || _li_out="br0"
    printf '%s\n' "$_li_out"
}

LAN_IFACES="$(lan_ifaces)"

local_ip=$(
    ip -4 addr show br0 2>/dev/null \
        | awk '/inet /{print $2}' \
        | cut -d/ -f1 \
        | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
        | head -n1
)

# ═════════════════════════════════════════════════════════════════════════
# 8. Доступ к веб-панели: только из локальных сетей
# ═════════════════════════════════════════════════════════════════════════
# Правила ставятся здесь, а не только при старте панели: Keenetic
# пересоздаёт цепочки при смене состояния интерфейсов и вызывает этот хук,
# после чего разрешающие правила панели пропадали и она становилась
# недоступной из LAN до перезапуска S99generator.
# Разрешение выдаётся по ИСХОДНОЙ ПОДСЕТИ, а не по имени интерфейса:
# на Keenetic Wi-Fi-клиенты приходят через разные мосты (гостевая сеть,
# отдельный бридж 5 ГГц, имена вида wl0/ra0), угадать их нельзя.
if [ "${table:-}" = "filter" ]; then
    # Снять прежний DROP, чтобы добавить его последним.
    while $IPT -D INPUT -p tcp --dport "$PORT_WEB" \
        -j DROP >/dev/null 2>&1; do :; done

    for web_net in 127.0.0.0/8 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12; do
        if ! $IPT -C INPUT -p tcp --dport "$PORT_WEB" \
            -s "$web_net" -j ACCEPT >/dev/null 2>&1
        then
            $IPT -I INPUT -p tcp --dport "$PORT_WEB" \
                -s "$web_net" -j ACCEPT >/dev/null 2>&1 || true
        fi
    done

    $IPT -A INPUT -p tcp --dport "$PORT_WEB" -j DROP >/dev/null 2>&1 || true

    # ─────────────────────────────────────────────────────────────────
    # Прокси-порты: закрыть от WAN (defense-in-depth).
    # ─────────────────────────────────────────────────────────────────
    # ss-redir, tor, xray, trojan и hysteria слушают 0.0.0.0, потому что
    # принимают перехваченный трафик со всех внутренних интерфейсов.
    # Своих правил INPUT у них не было — защищал только межсетевой экран
    # прошивки. При случайном пробросе порта или его отключении роутер
    # превратился бы в открытый прокси-релей.
    #
    # Разрешение выдаётся тремя независимыми способами, чтобы ни один
    # легитимный путь не оказался отрезан:
    #   1) -i lo          — трафик самого роутера после REDIRECT/TPROXY
    #                       (bot.txt -> unblockrouter) приходит через lo;
    #   2) -i <LAN>       — перехваченный трафик клиентов;
    #   3) -s <подсеть>   — страховка на случай нестандартной
    #                       маршрутизации и нетипичных имён интерфейсов.
    # DROP добавляется последним и только если определён хотя бы один
    # внутренний интерфейс — иначе правило могло бы отрезать всё.
    for proxy_port in "$PORT_SS" "$PORT_TOR" "$PORT_VLESS" \
        "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        for proxy_proto in tcp udp; do
            # Снять прежний DROP, чтобы он снова оказался последним.
            while $IPT -D INPUT -p "$proxy_proto" \
                --dport "$proxy_port" -j DROP >/dev/null 2>&1
            do
                :
            done

            if ! $IPT -C INPUT -i lo -p "$proxy_proto" \
                --dport "$proxy_port" -j ACCEPT >/dev/null 2>&1
            then
                $IPT -I INPUT -i lo -p "$proxy_proto" \
                    --dport "$proxy_port" -j ACCEPT \
                    >/dev/null 2>&1 || true
            fi

            for proxy_if in $LAN_IFACES; do
                if ! $IPT -C INPUT -i "$proxy_if" -p "$proxy_proto" \
                    --dport "$proxy_port" -j ACCEPT >/dev/null 2>&1
                then
                    $IPT -I INPUT -i "$proxy_if" -p "$proxy_proto" \
                        --dport "$proxy_port" -j ACCEPT \
                        >/dev/null 2>&1 || true
                fi
            done

            for proxy_net in 127.0.0.0/8 192.168.0.0/16 \
                10.0.0.0/8 172.16.0.0/12; do
                if ! $IPT -C INPUT -p "$proxy_proto" \
                    --dport "$proxy_port" -s "$proxy_net" \
                    -j ACCEPT >/dev/null 2>&1
                then
                    $IPT -I INPUT -p "$proxy_proto" \
                        --dport "$proxy_port" -s "$proxy_net" \
                        -j ACCEPT >/dev/null 2>&1 || true
                fi
            done

            if [ -n "$LAN_IFACES" ]; then
                $IPT -A INPUT -p "$proxy_proto" \
                    --dport "$proxy_port" -j DROP \
                    >/dev/null 2>&1 \
                    || log_msg "INPUT DROP failed: $proxy_proto/$proxy_port"
            fi
        done
    done
fi

if [ "${table:-}" = "filter" ]; then
    # В таблице filter больше делать нечего.
    exit 0
fi

if [ -z "$local_ip" ]; then
    log_msg "br0 local_ip not found"
    exit 0
fi

ensure_set() {
    ipset create "$1" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
}

# ── Идемпотентные помощники (проверка через -C, без grep по iptables-save)
# Протокол считается выключенным, если в его init-скрипте стоит
# ENABLED=no (ползунок в веб-панели). Для такого протокола правила
# перехвата не создаются, а ранее созданные снимаются — иначе трафик
# уходил бы на порт остановленного сервиса и соединение просто рвалось.
svc_enabled() {
    _init="$1"
    [ -f "$_init" ] || return 0
    if grep -qE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*no' \
        "$_init" 2>/dev/null
    then
        return 1
    fi

    # Мало того, что сервис разрешён — он должен реально работать.
    # Правило на упавший сервис создаёт чёрную дыру: пакеты уходят на
    # порт, который никто не слушает, и клиент получает таймаут вместо
    # обхода (наблюдалось с hysteria: сервис dead, а 6 правил на
    # unblockhysteria стояли). Порт берётся из PROCS init-скрипта.
    _svc_proc="$(sed -n \
        's/^[[:space:]]*PROCS[[:space:]]*=[[:space:]]*\([^[:space:]#]*\).*/\1/p' \
        "$_init" 2>/dev/null | head -1)"
    [ -n "$_svc_proc" ] || return 0

    # Разбор /proc, без pgrep: он есть не во всех сборках BusyBox.
    # Сравнивается ИМЯ БИНАРНИКА (argv[0]), а не вся командная строка:
    # подстрочный поиск принимал за живой сервис любой процесс, где имя
    # встречается в аргументах — например "vi /opt/etc/hysteria/config.json"
    # или "tail -f .../hysteria.log". Тогда правила создавались для
    # мёртвого сервиса, то есть ровно та ошибка, ради которой делалась
    # проверка.
    # Результат кэшируется на время прогона: функция вызывается до 15 раз
    # (5 сервисов × 3 интерфейса), и каждый раз обходить весь /proc
    # слишком дорого — прошивка убивала хук по таймауту
    # ("100-redirect.sh: timed out", Opkg::Manager).
    # Имя процесса нормализуется: в имени переменной допустимы только
    # [A-Za-z0-9_], а PROCS бывает вида "ss-redir".
    _svc_key="$(printf '%s' "$_svc_proc" | tr -c 'A-Za-z0-9_' '_')"
    eval "_svc_cached=\"\${_SVC_ALIVE_${_svc_key}:-}\""
    case "$_svc_cached" in
        1) return 0 ;;
        0) return 1 ;;
    esac

    _svc_found=1
    for _svc_d in /proc/[0-9]*; do
        # Процесс мог завершиться между раскрытием маски и чтением файла.
        # Перенаправление "< файл" выполняет ОБОЛОЧКА, и её сообщение
        # "can't open ...: no such file" не подавляется через 2>/dev/null
        # у самой команды — в журнале роутера это выглядело как ошибка
        # скрипта. Читаем через cat с подавлением его собственного stderr.
        _svc_argv0="$(cat "$_svc_d/cmdline" 2>/dev/null \
            | tr '\0' '\n' | head -1)"
        [ -n "$_svc_argv0" ] || continue
        # argv[0] может быть как "hysteria", так и "/opt/bin/hysteria".
        if [ "${_svc_argv0##*/}" = "$_svc_proc" ]; then
            _svc_found=0
            break
        fi
    done

    # Имя процесса подставляется в имя переменной, поэтому из него
    # убирается всё, кроме [A-Za-z0-9_]: "ss-redir" дал бы недопустимое
    # имя и eval завершился бы ошибкой.
    _svc_key="$(printf '%s' "$_svc_proc" | tr -c 'A-Za-z0-9_' '_')"
    if [ "$_svc_found" = "0" ]; then
        eval "_SVC_ALIVE_${_svc_key}=1"
        return 0
    fi

    eval "_SVC_ALIVE_${_svc_key}=0"
    log_msg "$_svc_proc не запущен — правила перехвата не создаются"
    return 1
}

# Снимает правило REDIRECT с конкретного интерфейса.
nat_del_prerouting() {
    _proto="$1"
    _set="$2"
    _port="$3"
    _if="$4"
    while $IPT -t nat -D PREROUTING -i "$_if" -p "$_proto" \
        -m set --match-set "$_set" dst \
        -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    do
        :
    done
}

# Снимает правило TPROXY с конкретного интерфейса.
mangle_del_tproxy() {
    _set="$1"
    _port="$2"
    _if="$3"
    while $IPT -t mangle -D PREROUTING -i "$_if" -p udp \
        -m set --match-set "$_set" dst \
        -j TPROXY --on-ip 127.0.0.1 --on-port "$_port" \
        --tproxy-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
    do
        :
    done
}

nat_add_prerouting() {
    _proto="$1"
    _set="$2"
    _port="$3"
    _if="$4"
    if ! $IPT -t nat -C PREROUTING -i "$_if" -p "$_proto" \
        -m set --match-set "$_set" dst \
        -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    then
        $IPT -t nat -A PREROUTING -i "$_if" -p "$_proto" \
            -m set --match-set "$_set" dst \
            -j REDIRECT --to-port "$_port" >/dev/null 2>&1 || true
    fi
}

nat_del_prerouting_any() {
    # Удаляет старое правило без -i (наследие прежних версий).
    _proto="$1"
    _set="$2"
    _port="$3"
    while $IPT -t nat -D PREROUTING -p "$_proto" \
        -m set --match-set "$_set" dst \
        -j REDIRECT --to-port "$_port" >/dev/null 2>&1
    do
        :
    done
}

# Загрузка модуля netfilter при необходимости.
# Хук вызывается при каждой перестройке цепочек, в том числе при
# загрузке роутера, поэтому модули грузятся именно здесь: деплой
# выполняется однократно и после reboot не отработает.
# modprobe на Keenetic бесполезен — в /lib/modules нет modules.dep,
# поэтому используется insmod с полным путём к .ko.
load_kmod() {
    _km="$1"

    if lsmod 2>/dev/null | awk -v m="$_km" '$1==m {f=1} END{exit !f}'
    then
        return 0
    fi

    modprobe "$_km" >/dev/null 2>&1 && return 0

    _kdir="/lib/modules/$(uname -r)"
    [ -d "$_kdir" ] || return 1

    _kfile="$(find "$_kdir" -name "${_km}.ko" -print 2>/dev/null \
        | head -n1)"
    [ -n "$_kfile" ] || return 1

    insmod "$_kfile" >/dev/null 2>&1 || true

    lsmod 2>/dev/null | awk -v m="$_km" '$1==m {f=1} END{exit !f}'
}

# Цель TPROXY доступна только при загруженном xt_TPROXY. Проверяем по
# факту наличия цели в ядре и при отсутствии — догружаем модули.
ensure_tproxy_kmod() {
    if grep -qx 'TPROXY' /proc/net/ip_tables_targets 2>/dev/null; then
        return 0
    fi

    for _d in nf_defrag_ipv4 nf_tproxy_ipv4 nf_tproxy_core \
        nf_socket_ipv4 ip_set; do
        load_kmod "$_d" >/dev/null 2>&1 || true
    done
    for _m in xt_TPROXY xt_socket xt_set; do
        load_kmod "$_m" >/dev/null 2>&1 || true
    done

    if grep -qx 'TPROXY' /proc/net/ip_tables_targets 2>/dev/null; then
        log_msg "xt_TPROXY загружен вручную (insmod)"
        return 0
    fi
    return 1
}

mangle_add_tproxy() {
    _set="$1"
    _port="$2"
    _if="$3"

    # Набор обязан существовать: без него iptables отвергает правило
    # целиком ("Set ... doesn't exist" / "Can't open socket to ipset").
    if ! ipset list -n "$_set" >/dev/null 2>&1; then
        log_msg "TPROXY skip: ipset $_set отсутствует"
        return 0
    fi

    if ! $IPT -t mangle -C PREROUTING -i "$_if" -p udp \
        -m set --match-set "$_set" dst \
        -j TPROXY --on-ip 127.0.0.1 --on-port "$_port" \
        --tproxy-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
    then
        # Ошибка НЕ подавляется: раньше причина терялась в /dev/null и
        # отсутствие правил выглядело беспричинным.
        _err="$($IPT -t mangle -A PREROUTING -i "$_if" -p udp \
            -m set --match-set "$_set" dst \
            -j TPROXY --on-ip 127.0.0.1 --on-port "$_port" \
            --tproxy-mark "${TPROXY_MARK}/${TPROXY_MASK}" 2>&1)" \
            || {
                log_msg "TPROXY add failed: $_set/$_port/$_if: $_err"
                # Ошибка "No chain/target/match by that name" не говорит,
                # ЧТО именно отвергнуто: цель TPROXY или совпадение set.
                # Разделяем причины одной пробой на каждый прогон, чтобы
                # в журнале была не догадка, а факт.
                if [ "${_tproxy_diag:-0}" = "0" ]; then
                    _tproxy_diag=1
                    if $IPT -t mangle -I PREROUTING -p udp \
                        -d 127.0.0.2 --dport 1 \
                        -j TPROXY --on-ip 127.0.0.1 \
                        --on-port 12345 --tproxy-mark 1/1 \
                        >/dev/null 2>&1
                    then
                        $IPT -t mangle -D PREROUTING -p udp \
                            -d 127.0.0.2 --dport 1 \
                            -j TPROXY --on-ip 127.0.0.1 \
                            --on-port 12345 --tproxy-mark 1/1 \
                            >/dev/null 2>&1 || true
                        log_msg "diag: цель TPROXY работает; отвергается связка с -m set в mangle"
                    else
                        log_msg "diag: ядро НЕ поддерживает цель TPROXY (нет xt_TPROXY). UDP в туннель не пойдёт, TCP не затронут"
                    fi
                fi
            }
    fi
}

# ═════════════════════════════════════════════════════════════════════════
# 1. DNS клиентов -> локальный dnsmasq (только внутренние интерфейсы)
# ═════════════════════════════════════════════════════════════════════════
# Прежняя версия ставила DNAT без -i: правило применялось и к пакетам,
# пришедшим с WAN, то есть роутер становился открытым DNS-релеем.
for protocol in udp tcp; do
    while $IPT -t nat -D PREROUTING -p "$protocol" --dport 53 \
        -j DNAT --to-destination "$local_ip" >/dev/null 2>&1
    do
        :
    done
done

for iface in $LAN_IFACES; do
    for protocol in udp tcp; do
        if ! $IPT -t nat -C PREROUTING -i "$iface" -p "$protocol" --dport 53 \
            -j DNAT --to-destination "$local_ip" >/dev/null 2>&1
        then
            $IPT -t nat -I PREROUTING -i "$iface" -p "$protocol" --dport 53 \
                -j DNAT --to-destination "$local_ip" >/dev/null 2>&1 || true
        fi
    done
done

# ═════════════════════════════════════════════════════════════════════════
# 2. Подготовка ipset
# ═════════════════════════════════════════════════════════════════════════
for s in unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter; do
    ensure_set "$s"
done

# ═════════════════════════════════════════════════════════════════════════
# 3. Чистка устаревших/некорректных правил
# ═════════════════════════════════════════════════════════════════════════
# UDP через nat/REDIRECT для Tor/Trojan/Hysteria: это TCP-входы либо
# TPROXY-входы, REDIRECT ломал такой трафик.
nat_del_prerouting_any udp unblocktor "$PORT_TOR"
nat_del_prerouting_any udp unblocktroj "$PORT_TROJAN"
nat_del_prerouting_any udp unblockhysteria "$PORT_HYSTERIA"
nat_del_prerouting_any udp unblockvless "$PORT_VLESS"
# Старые правила без -i.
nat_del_prerouting_any tcp unblocksh "$PORT_SS"
nat_del_prerouting_any udp unblocksh "$PORT_SS"
nat_del_prerouting_any tcp unblocktor "$PORT_TOR"
nat_del_prerouting_any tcp unblockvless "$PORT_VLESS"
nat_del_prerouting_any tcp unblocktroj "$PORT_TROJAN"
nat_del_prerouting_any tcp unblockhysteria "$PORT_HYSTERIA"

# ═════════════════════════════════════════════════════════════════════════
# 4. TCP: nat/REDIRECT на локальные порты (по каждому внутр. интерфейсу)
# ═════════════════════════════════════════════════════════════════════════
# Пути init-скриптов: по ним читается состояние ползунка ENABLED.
INIT_SS="/opt/etc/init.d/S65shadowsocks"
INIT_TOR="/opt/etc/init.d/S35tor"
INIT_VLESS="/opt/etc/init.d/S24xray"
INIT_TROJ="/opt/etc/init.d/S22trojan"
INIT_HY="/opt/etc/init.d/S57hysteria"

for iface in $LAN_IFACES; do
    if svc_enabled "$INIT_SS"; then
        nat_add_prerouting tcp unblocksh    "$PORT_SS"    "$iface"
        # ss-redir запущен с -u и обрабатывает UDP через REDIRECT.
        nat_add_prerouting udp unblocksh    "$PORT_SS"    "$iface"
    else
        nat_del_prerouting tcp unblocksh    "$PORT_SS"    "$iface"
        nat_del_prerouting udp unblocksh    "$PORT_SS"    "$iface"
    fi

    if svc_enabled "$INIT_TOR"; then
        nat_add_prerouting tcp unblocktor   "$PORT_TOR"   "$iface"
    else
        nat_del_prerouting tcp unblocktor   "$PORT_TOR"   "$iface"
    fi

    if svc_enabled "$INIT_VLESS"; then
        nat_add_prerouting tcp unblockvless "$PORT_VLESS" "$iface"
    else
        nat_del_prerouting tcp unblockvless "$PORT_VLESS" "$iface"
    fi

    if svc_enabled "$INIT_TROJ"; then
        nat_add_prerouting tcp unblocktroj  "$PORT_TROJAN" "$iface"
    else
        nat_del_prerouting tcp unblocktroj  "$PORT_TROJAN" "$iface"
    fi

    if svc_enabled "$INIT_HY"; then
        nat_add_prerouting tcp unblockhysteria "$PORT_HYSTERIA" "$iface"
    else
        nat_del_prerouting tcp unblockhysteria "$PORT_HYSTERIA" "$iface"
    fi
done

# ═════════════════════════════════════════════════════════════════════════
# 5. UDP через TPROXY для VLESS (xray) и Hysteria2
# ═════════════════════════════════════════════════════════════════════════
# nat/REDIRECT для UDP не сохраняет оригинальный адрес назначения, поэтому
# dokodemo-door/udpTProxy получали пакеты без dst и трафик рвался.
# Корректная схема: mangle/TPROXY + метка + локальная таблица маршрутизации.
if ip rule show 2>/dev/null | grep -q "lookup $TPROXY_TABLE"; then
    :
else
    ip rule add fwmark "${TPROXY_MARK}/${TPROXY_MASK}" \
        lookup "$TPROXY_TABLE" priority "$TPROXY_RULE_PRIO" 2>/dev/null || true
fi

ip route replace local default dev lo table "$TPROXY_TABLE" 2>/dev/null || true

# Модули netfilter должны быть загружены ДО создания правил: на Keenetic
# xt_TPROXY.ko поставляется прошивкой, но автоматически не грузится.
ensure_tproxy_kmod || true

# Пакеты уже установленных TPROXY-сессий должны попадать на локальный сокет
# до правил TPROXY (иначе они уйдут в форвардинг).
if ! $IPT -t mangle -C PREROUTING -p udp -m socket \
    -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
then
    $IPT -t mangle -I PREROUTING -p udp -m socket \
        -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1 || true
fi

for iface in $LAN_IFACES; do
    if svc_enabled "$INIT_VLESS"; then
        mangle_add_tproxy unblockvless    "$PORT_VLESS"    "$iface"
    else
        mangle_del_tproxy unblockvless    "$PORT_VLESS"    "$iface"
    fi
    if svc_enabled "$INIT_HY"; then
        mangle_add_tproxy unblockhysteria "$PORT_HYSTERIA" "$iface"
    else
        mangle_del_tproxy unblockhysteria "$PORT_HYSTERIA" "$iface"
    fi
done

# ═════════════════════════════════════════════════════════════════════════
# 6. Трафик самого роутера (bot.txt -> unblockrouter)
# ═════════════════════════════════════════════════════════════════════════
if ! $IPT -t nat -C OUTPUT -o lo -j RETURN >/dev/null 2>&1; then
    $IPT -t nat -I OUTPUT -o lo -j RETURN >/dev/null 2>&1 || true
fi

for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    if ! $IPT -t nat -C OUTPUT -d "$net" -j RETURN >/dev/null 2>&1; then
        $IPT -t nat -A OUTPUT -d "$net" -j RETURN >/dev/null 2>&1 || true
    fi
done

# Защита от петли: пакеты, которые xray сам отправляет наружу, помечены
# XRAY_MARK (sockopt.mark в outbound). Без этого исключения правила ниже
# завернули бы исходящий трафик xray обратно в его же inbound.
if ! $IPT -t nat -C OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; then
    $IPT -t nat -I OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1 || true
fi
if ! $IPT -t mangle -C OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; then
    $IPT -t mangle -I OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1 || true
fi

# TCP роутера (bot.txt) -> xray/VLESS через nat/REDIRECT.
# Если VLESS отключён ползунком, правило снимается: иначе трафик самого
# роутера (в т.ч. бота к api.telegram.org) уходил бы на мёртвый порт.
if svc_enabled "$INIT_VLESS"; then
    if ! $IPT -t nat -C OUTPUT -p tcp \
        -m set --match-set unblockrouter dst \
        -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1
    then
        $IPT -t nat -A OUTPUT -p tcp \
            -m set --match-set unblockrouter dst \
            -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1 || true
    fi
else
    while $IPT -t nat -D OUTPUT -p tcp \
        -m set --match-set unblockrouter dst \
        -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1
    do
        :
    done
fi

# UDP роутера ранее уходил в ss-redir (PORT_SS) — это противоречило
# требованию "bot.txt только через xray". Снимаем такое правило.
while $IPT -t nat -D OUTPUT -p udp \
    -m set --match-set unblockrouter dst \
    -j REDIRECT --to-port "$PORT_SS" >/dev/null 2>&1
do
    :
done

# nat/REDIRECT для UDP непригоден: xray не восстановит исходный адрес
# назначения. Локальный UDP заворачивается меткой в таблицу 100 (local
# default dev lo), после чего пакет проходит PREROUTING и попадает в
# TPROXY-инбаунд vless-udp-tproxy — тот же путь, что и у UDP из LAN.
while $IPT -t nat -D OUTPUT -p udp \
    -m set --match-set unblockrouter dst \
    -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1
do
    :
done

if svc_enabled "$INIT_VLESS"; then
    if ! $IPT -t mangle -C OUTPUT -p udp \
        -m set --match-set unblockrouter dst \
        -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
    then
        $IPT -t mangle -A OUTPUT -p udp \
            -m set --match-set unblockrouter dst \
            -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" \
            >/dev/null 2>&1 \
            || log_msg "MARK(OUTPUT udp) add failed"
    fi
else
    while $IPT -t mangle -D OUTPUT -p udp \
        -m set --match-set unblockrouter dst \
        -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
    do
        :
    done
fi

# ═════════════════════════════════════════════════════════════════════════
# 7. VPN-интерфейсы прошивки: ipset -> fwmark -> policy routing
# ═════════════════════════════════════════════════════════════════════════
for vpn_file_name in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_name" ] || continue

    vpn_unblock_name="$(basename "$vpn_file_name" .txt)"
    unblockvpn="unblock${vpn_unblock_name}"
    vpn_type="$(printf '%s\n' "$unblockvpn" | sed 's/-/ /g' | awk '{print $NF}')"
    [ -n "$vpn_type" ] || continue

    vpn_link_up="$(curl -s --max-time 5 \
        "localhost:79/rci/show/interface/${vpn_type}/link" 2>/dev/null \
        | tr -d '"' || true)"

    # Ошибка одного интерфейса не должна прекращать обработку остальных.
    [ "$vpn_link_up" = "up" ] || continue

    vpn_type_lower="$(printf '%s' "$vpn_type" | tr '[:upper:]' '[:lower:]')"
    vpn_table_id="$(grep -w "$vpn_type_lower" /opt/etc/iproute2/rt_tables 2>/dev/null \
        | awk '{print $1}' | head -n1 || true)"

    [ -n "$vpn_table_id" ] || continue

    vpn_mark_id="0xd${vpn_table_id}"
    ensure_set "$unblockvpn"

    fastnat="$(curl -s --max-time 5 localhost:79/rci/show/version 2>/dev/null | grep ppe || true)"
    software="$(curl -s --max-time 5 localhost:79/rci/show/rc/ppe 2>/dev/null \
        | grep software -C1 | head -1 | awk '{print $2}' | tr -d ',' || true)"
    hardware="$(curl -s --max-time 5 localhost:79/rci/show/rc/ppe 2>/dev/null \
        | grep hardware -C1 | head -1 | awk '{print $2}' | tr -d ',' || true)"

    if [ -z "$fastnat" ] && [ "$software" = "false" ] && [ "$hardware" = "false" ]; then
        for proto in tcp udp; do
            if ! $IPT -t mangle -C PREROUTING -p "$proto" \
                -m set --match-set "$unblockvpn" dst \
                -j MARK --set-mark "$vpn_mark_id" >/dev/null 2>&1
            then
                $IPT -t mangle -A PREROUTING -p "$proto" \
                    -m set --match-set "$unblockvpn" dst \
                    -j MARK --set-mark "$vpn_mark_id" >/dev/null 2>&1 || true
            fi
        done
    else
        if ! $IPT -t mangle -C PREROUTING \
            -m conntrack --ctstate NEW \
            -m set --match-set "$unblockvpn" dst \
            -j CONNMARK --set-mark "$vpn_mark_id" >/dev/null 2>&1
        then
            $IPT -t mangle -A PREROUTING \
                -m conntrack --ctstate NEW \
                -m set --match-set "$unblockvpn" dst \
                -j CONNMARK --set-mark "$vpn_mark_id" >/dev/null 2>&1 || true
        fi
        if ! $IPT -t mangle -C PREROUTING -j CONNMARK --restore-mark >/dev/null 2>&1; then
            $IPT -t mangle -A PREROUTING -j CONNMARK --restore-mark >/dev/null 2>&1 || true
        fi
    fi

    # Успешная обработка VPN-интерфейса не логируется: хук срабатывает на
    # каждое изменение состояния, и такие записи быстро раздували файл.
    # В лог попадают только ошибки.
done

exit 0

#!/bin/sh
# remove keeps data but disables cron/NDM reactivation until next install.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
# /opt/etc/ndm/netfilter.d/100-redirect.sh
# Перехват трафика для списков обхода.
#   TCP  -> nat/REDIRECT на локальные порты прокси.
#   UDP  -> mangle/TPROXY (vless, hysteria) либо nat/REDIRECT (shadowsocks).
# Оболочка: BusyBox ash (#!/bin/sh), без bash-измов.

set -eu
DNS_POLICY_V4=1

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# dns4.2.23 (аудит A5 #3): единый список локальных/служебных сетей для
# RETURN/ACCEPT-правил этого файла. Раньше список копипастился в пяти
# местах, причём без link-local (169.254/16) и CGNAT (100.64/10 —
# частый адрес мобильного WAN на Keenetic): обращение роутера к таким
# адресам уходило бы в REDIRECT/TPROXY и получало петлю или чёрную дыру.
# Состав согласован с public-фильтрами is_public_* (unblock_ipset.sh,
# unblock_dnsmasq.sh) — править синхронно.
LOCAL_NETS="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"

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


# dns4.2.20: TUNNEL_PROTOCOL_PRIORITY удалён — выбор транспорта давно
# принадлежит DNS-слою (unblock_dnsmasq/utils), здесь значение не
# читалось (замечание аудита A2, SC2034).

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

# ─────────────────────────────────────────────────────────────────────
# IPv6: закрыть прокси-порты от внешней сети.
# ─────────────────────────────────────────────────────────────────────
# Перехват трафика (REDIRECT/TPROXY) реализован только для IPv4, но
# xray (Go) на "listen": "0.0.0.0" может создать dual-stack сокет. Если
# IPv6 случайно включили, прокси-порты не должны становиться доступными из
# LAN/WAN IPv6: эти правила закрывают их полностью, кроме loopback.
# Это только защита локальных портов; полноценный IPv4-only режим обязан
# дополнительно отключать IPv6 в KeeneticOS, а deploy проверяет это заранее.
if [ "${type:-}" = "ip6tables" ]; then
    [ "${table:-}" = "filter" ] || exit 0

    IPT6="$(command -v ip6tables 2>/dev/null || true)"
    [ -n "$IPT6" ] || exit 0
    IPT6="$IPT6 -w"

    for p6 in "$(config_number localportsh 1082)" "$(config_number localporttor 9141)" \
        "$(config_number localportvless 10810)" "$(config_number localporttrojan 10829)" \
        "$(config_number localporthysteria 10830)" "$(config_number web_port 8080)"; do
        for pr6 in tcp udp; do
            # Удаляем старые варианты, включая прежние разрешения ULA/
            # link-local, иначе они опередят новое fail-closed правило.
            while $IPT6 -D INPUT -p "$pr6" --dport "$p6" \
                -j DROP >/dev/null 2>&1; do :; done
            while $IPT6 -D INPUT -i lo -p "$pr6" \
                --dport "$p6" -j ACCEPT >/dev/null 2>&1; do :; done
            for n6 in fc00::/7 fe80::/10 ::1/128; do
                while $IPT6 -D INPUT -p "$pr6" --dport "$p6" \
                    -s "$n6" -j ACCEPT >/dev/null 2>&1; do :; done
            done

            # Сначала loopback, затем DROP для любого прочего IPv6.
            $IPT6 -I INPUT 1 -p "$pr6" --dport "$p6" \
                -j DROP >/dev/null 2>&1 || { printf "%s\n" "IPv6 proxy DROP failed: $p6/$pr6" >&2; exit 1; }
            $IPT6 -I INPUT 1 -i lo -p "$pr6" --dport "$p6" \
                -j ACCEPT >/dev/null 2>&1 || { printf "%s\n" "IPv6 loopback ACCEPT failed: $p6/$pr6" >&2; exit 1; }
        done
    done
    [ "${PURGE_PROJECT:-0}" = "1" ] && exit 0
    exit 0
fi

# Idempotent full removal path. It deliberately runs before the normal
# service-state reconciliation and therefore does not depend on a service
# still being enabled or alive. No new daemon/state file is introduced.
purge_project_netfilter() {

    while $IPT -t nat -D OUTPUT -j KZ_DNS_V4 >/dev/null 2>&1; do :; done
    $IPT -t nat -F KZ_DNS_V4 >/dev/null 2>&1 || true
    $IPT -t nat -X KZ_DNS_V4 >/dev/null 2>&1 || true
    for _v4_mark in 0x2000101 0x2000102 0x2000103; do
        while $IPT -D OUTPUT -p tcp --dport 53 -m mark --mark "$_v4_mark" -j REJECT >/dev/null 2>&1; do :; done
    done
    for _v4_proto in tcp udp; do
        while $IPT -t nat -D OUTPUT -p "$_v4_proto" --dport 53 -m mark --mark 0x2000104 -j RETURN >/dev/null 2>&1; do :; done
    done
    _pps_sets="unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter unblockdns"
    _pps_ports="$PORT_SS:$PORT_TOR:$PORT_VLESS:$PORT_TROJAN:$PORT_HYSTERIA"

    # DNS DNAT and client redirects, including rules without -i from older
    # releases. Include the historical interface names even when a device is
    # currently down; otherwise a reboot could leave an orphaned rule behind.
    _pps_all_ifaces="$LAN_IFACES $LAN_IFACE_PATTERNS"
    for _pps_if in $_pps_all_ifaces; do
        for _pps_proto in tcp udp; do
            while $IPT -t nat -D PREROUTING -i "$_pps_if" -p "$_pps_proto" \
                --dport 53 -j DNAT --to-destination "$local_ip" >/dev/null 2>&1; do :; done
        done
        while $IPT -t nat -D PREROUTING -i "$_pps_if" -p tcp \
            -m set --match-set unblockrouter dst -j REDIRECT \
            --to-port "$PORT_VLESS" >/dev/null 2>&1; do :; done
        for _pps_spec in \
            "tcp unblocksh $PORT_SS" "udp unblocksh $PORT_SS" \
            "tcp unblocktor $PORT_TOR" "tcp unblockvless $PORT_VLESS" \
            "tcp unblocktroj $PORT_TROJAN" "tcp unblockhysteria $PORT_HYSTERIA"; do
            set -- $_pps_spec
            while $IPT -t nat -D PREROUTING -i "$_pps_if" -p "$1" \
                -m set --match-set "$2" dst -j REDIRECT --to-port "$3" \
                >/dev/null 2>&1; do :; done
            while $IPT -t mangle -D PREROUTING -i "$_pps_if" -p udp \
                -m set --match-set "$2" dst -j TPROXY --on-ip 127.0.0.1 \
                --on-port "$3" --tproxy-mark "$TPROXY_MARK/$TPROXY_MASK" \
                >/dev/null 2>&1; do :; done
        done
    done

    for _pps_proto in tcp udp; do
        while $IPT -t nat -D PREROUTING -p "$_pps_proto" --dport 53 \
            -j DNAT --to-destination "$local_ip" >/dev/null 2>&1; do :; done
    done
    for _pps_spec in \
        "udp unblocktor $PORT_TOR" "udp unblocktroj $PORT_TROJAN" \
        "udp unblockhysteria $PORT_HYSTERIA" "udp unblockvless $PORT_VLESS" \
        "tcp unblocksh $PORT_SS" "udp unblocksh $PORT_SS" \
        "tcp unblocktor $PORT_TOR" "tcp unblockvless $PORT_VLESS" \
        "tcp unblocktroj $PORT_TROJAN" "tcp unblockhysteria $PORT_HYSTERIA"; do
        set -- $_pps_spec
        while $IPT -t nat -D PREROUTING -p "$1" \
            -m set --match-set "$2" dst -j REDIRECT --to-port "$3" \
            >/dev/null 2>&1; do :; done
        while $IPT -t mangle -D PREROUTING -p udp \
            -m set --match-set "$2" dst -j TPROXY --on-ip 127.0.0.1 \
            --on-port "$3" --tproxy-mark "$TPROXY_MARK/$TPROXY_MASK" \
            >/dev/null 2>&1; do :; done
    done

    # Dedicated router chain introduced by the protocol selector.
    while $IPT -t nat -D OUTPUT -p tcp -m set --match-set unblockrouter dst \
        -j KZ_ROUTER >/dev/null 2>&1; do :; done
    if $IPT -t nat -S KZ_ROUTER >/dev/null 2>&1; then
        $IPT -t nat -F KZ_ROUTER >/dev/null 2>&1 || return 1
        $IPT -t nat -X KZ_ROUTER >/dev/null 2>&1 || return 1
    fi
    for _pps_botport in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        while $IPT -t nat -D OUTPUT -p tcp -m set --match-set unblockrouter dst \
            -j REDIRECT --to-port "$_pps_botport" >/dev/null 2>&1; do :; done
    done
    # OUTPUT rules for bot.txt and tunnel-DNS, plus loop/mark exceptions.
    while $IPT -t nat -D OUTPUT -o lo -j RETURN >/dev/null 2>&1; do :; done
    for _pps_net in $LOCAL_NETS; do
        while $IPT -t nat -D OUTPUT -d "$_pps_net" -j RETURN \
            >/dev/null 2>&1; do :; done
    done
    while $IPT -t mangle -D OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; do :; done
    while $IPT -t nat -D OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; do :; done
    for _pps_port in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        for _pps_remote in 443 853; do
            while $IPT -t nat -D OUTPUT -p tcp --dport "$_pps_remote" \
                -m set --match-set unblockdns dst -j REDIRECT \
                --to-port "$_pps_port" >/dev/null 2>&1; do :; done
        done
    done
    while $IPT -t nat -D OUTPUT -p tcp -m set --match-set unblockrouter dst \
        -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1; do :; done
    for _pps_proto in tcp udp; do
        while $IPT -t nat -D OUTPUT -p "$_pps_proto" \
            -m set --match-set unblockrouter dst -j REDIRECT \
            --to-port "$PORT_VLESS" >/dev/null 2>&1; do :; done
        while $IPT -t nat -D OUTPUT -p "$_pps_proto" \
            -m set --match-set unblockrouter dst -j REDIRECT \
            --to-port "$PORT_SS" >/dev/null 2>&1; do :; done
        while $IPT -t mangle -D OUTPUT -p "$_pps_proto" \
            -m set --match-set unblockrouter dst -j MARK \
            --set-mark "$TPROXY_MARK/$TPROXY_MASK" >/dev/null 2>&1; do :; done
    done
    while $IPT -t mangle -D PREROUTING -p udp -m socket \
        -j MARK --set-mark "$TPROXY_MARK/$TPROXY_MASK" >/dev/null 2>&1; do :; done

    # Remove policy routing created by the UDP client plane.
    while ip rule del fwmark "$TPROXY_MARK/$TPROXY_MASK" \
        lookup "$TPROXY_TABLE" priority "$TPROXY_RULE_PRIO" >/dev/null 2>&1; do :; done
    while ip route del local default dev lo table "$TPROXY_TABLE" \
        >/dev/null 2>&1; do :; done

    # Filter rules protecting the panel and proxy listeners.
    for _pps_raw in tcp udp; do
        while $IPT -D OUTPUT -d 127.0.0.0/8 -p "$_pps_raw" --dport 53 \
            -j RETURN >/dev/null 2>&1; do :; done
        while $IPT -D OUTPUT -p "$_pps_raw" --dport 53 \
            -j DROP >/dev/null 2>&1; do :; done
    done
    while $IPT -D INPUT -p tcp --dport "$PORT_WEB" -j DROP >/dev/null 2>&1; do :; done
    for _pps_net in $LOCAL_NETS; do
        while $IPT -D INPUT -p tcp --dport "$PORT_WEB" -s "$_pps_net" \
            -j ACCEPT >/dev/null 2>&1; do :; done
    done
    while $IPT -D INPUT -i lo -p tcp --dport "$PORT_WEB" \
        -j ACCEPT >/dev/null 2>&1; do :; done
    for _pps_if in $LAN_IFACES; do
        while $IPT -D INPUT -i "$_pps_if" -p tcp --dport "$PORT_WEB" \
            -j ACCEPT >/dev/null 2>&1; do :; done
    done
    for _pps_port in "$PORT_SS" "$PORT_TOR" "$PORT_VLESS" \
        "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        for _pps_proto in tcp udp; do
            while $IPT -D INPUT -p "$_pps_proto" --dport "$_pps_port" \
                -j DROP >/dev/null 2>&1; do :; done
            while $IPT -D INPUT -i lo -p "$_pps_proto" \
                --dport "$_pps_port" -j ACCEPT >/dev/null 2>&1; do :; done
            for _pps_if in $LAN_IFACES; do
                while $IPT -D INPUT -i "$_pps_if" -p "$_pps_proto" \
                    --dport "$_pps_port" -j ACCEPT >/dev/null 2>&1; do :; done
            done
        done
    done

    # The rules are gone, so sets can safely be destroyed. Both live and
    # staging names are removed to prevent a later swap from resurrecting it.
    for _pps_set in $_pps_sets; do
        ipset flush "$_pps_set" >/dev/null 2>&1 || true
        ipset destroy "${_pps_set}_new" >/dev/null 2>&1 || true
        ipset destroy "$_pps_set" >/dev/null 2>&1 || true
    done
}

# filter тоже обрабатывается: в нём живут правила доступа к веб-панели.
case "${table:-}" in
    mangle|nat|filter) ;;
    *) exit 0 ;;
esac

TAG="100-redirect.sh"

# NDM может запускать этот hook одновременно с панелью и WAN-hook.
# Используем тот же atomic mkdir-lock, что и unblock_update.sh; при вызове
# из уже открытой update-транзакции nested lock не берём. Это не daemon и не
# новый постоянный файл — lock живёт только во время применения правил.
NETFILTER_LOCK_DIR="${KEENZOO_LOCK_DIR:-/tmp/unblock_update.lockdir}"
NETFILTER_LOCK_ACQUIRED=0

netfilter_lock_owner_live() {
    if [ ! -f "$NETFILTER_LOCK_DIR/pid" ]; then
        _nfl_mtime="$(stat -c %Y "$NETFILTER_LOCK_DIR" 2>/dev/null || echo 0)"
        _nfl_now="$(date +%s 2>/dev/null || echo 0)"
        case "$_nfl_mtime:$_nfl_now" in
            *[!0-9:]*|0:*) return 1 ;;
        esac
        [ $((_nfl_now - _nfl_mtime)) -lt 10 ] && return 0
        return 1
    fi
    _nfl_pid="$(cat "$NETFILTER_LOCK_DIR/pid" 2>/dev/null || true)"
    _nfl_saved="$(cat "$NETFILTER_LOCK_DIR/start" 2>/dev/null || true)"
    case "$_nfl_pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$_nfl_pid" 2>/dev/null || return 1
    if [ -n "$_nfl_saved" ] && [ -r "/proc/$_nfl_pid/stat" ]; then
        _nfl_now="$(awk '{print $22}' "/proc/$_nfl_pid/stat" 2>/dev/null || true)"
        [ -n "$_nfl_now" ] && [ "$_nfl_now" = "$_nfl_saved" ] || return 1
    fi
    return 0
}

netfilter_unlock() {
    if [ "$NETFILTER_LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$NETFILTER_LOCK_DIR"
    fi
}

if [ "${KEENZOO_UPDATE_LOCK_HELD:-0}" != "1" ]; then
    _nfl_tries=0
    while ! mkdir "$NETFILTER_LOCK_DIR" 2>/dev/null; do
        if ! netfilter_lock_owner_live; then
            rm -rf "$NETFILTER_LOCK_DIR" 2>/dev/null || true
            continue
        fi
        _nfl_tries=$((_nfl_tries + 1))
        if [ "$_nfl_tries" -ge 30 ]; then
            logger -t "$TAG" "netfilter apply deferred: shared lock is busy" 2>/dev/null || true
            # NDM may not retry a hook after exit 75. Queue one bounded,
            # one-shot retry in RAM so a concurrent list update cannot leave
            # NAT/TPROXY in a permanently partial state. This is not a daemon
            # or a persistent script; the marker disappears after the retry.
            if [ "${KEENZOO_NETFILTER_RETRY:-0}" != "1" ]; then
                _nfl_retry_marker="/tmp/keenzoo.netfilter.retry.${table:-all}"
                if mkdir "$_nfl_retry_marker" 2>/dev/null; then
                    (
                        trap 'rm -rf "$_nfl_retry_marker" 2>/dev/null || true' EXIT
                        trap 'exit 130' INT
                        trap 'exit 143' TERM
                        trap 'exit 129' HUP
                        _nfl_wait=0
                        while [ "$_nfl_wait" -lt 120 ]; do
                            if ! netfilter_lock_owner_live; then
                                KEENZOO_NETFILTER_RETRY=1 \
                                    type=iptable table="${table:-nat}" \
                                    "$0" >/dev/null 2>&1 || true
                                exit 0
                            fi
                            sleep 2
                            _nfl_wait=$((_nfl_wait + 1))
                        done
                    ) >/dev/null 2>&1 </dev/null &
                fi
            fi
            exit 75
        fi
        sleep 1
    done
    NETFILTER_LOCK_ACQUIRED=1
    printf '%s\n' "$$" > "$NETFILTER_LOCK_DIR/pid"
    awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$NETFILTER_LOCK_DIR/start" || true
fi
trap netfilter_unlock EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# На Keenetic нет logread, а вывод logger в syslog прошивки недоступен
# обычными средствами. Поэтому диагностика дублируется в файл.
REDIRECT_LOG="/opt/var/log/100-redirect.log"
mkdir -p /opt/var/log 2>/dev/null || true
# Create the file before the first wc/redirection. Some BusyBox builds emit
# "can't open ...: no such file" even when the parent directory exists.
: >> "$REDIRECT_LOG" 2>/dev/null || true

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
    _llines="$(wc -l < "$REDIRECT_LOG" 2>/dev/null || echo 0)"
    case "$_llines" in ''|*[!0-9]*) _llines=0 ;; esac
    if [ "$_lsz" -gt "$REDIRECT_LOG_MAX" ] || [ "$_llines" -gt "$REDIRECT_LOG_KEEP" ]; then
        _ltmp="${REDIRECT_LOG}.tmp.$$"
        _lbytes="${_ltmp}.bytes"
        if tail -n "$REDIRECT_LOG_KEEP" "$REDIRECT_LOG" > "$_ltmp" 2>/dev/null; then
            _ltmp_sz="$(wc -c < "$_ltmp" 2>/dev/null || echo 0)"
            case "$_ltmp_sz" in
                ''|*[!0-9]*) ;;
                *)
                    if [ "$_ltmp_sz" -gt "$REDIRECT_LOG_MAX" ]; then
                        tail -c "$REDIRECT_LOG_MAX" "$_ltmp" > "$_lbytes" 2>/dev/null \
                            && mv -f "$_lbytes" "$_ltmp"
                    fi
                    # Keep the inode stable for long-lived writers.
                    cat "$_ltmp" > "$REDIRECT_LOG" 2>/dev/null || true
                    ;;
            esac
        fi
        rm -f "$_ltmp" "$_lbytes"
    fi

    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" \
        >> "$REDIRECT_LOG" 2>/dev/null || true
    # Bound the just-written record as well; scheduled log rotation is only a
    # storage safeguard and is unrelated to DNS health polling.
    _lsz="$(wc -c < "$REDIRECT_LOG" 2>/dev/null || echo 0)"
    _llines="$(wc -l < "$REDIRECT_LOG" 2>/dev/null || echo 0)"
    if [ "$_lsz" -gt "$REDIRECT_LOG_MAX" ] || [ "$_llines" -gt "$REDIRECT_LOG_KEEP" ]; then
        _ltmp="${REDIRECT_LOG}.tmp.$$"
        tail -n "$REDIRECT_LOG_KEEP" "$REDIRECT_LOG" > "$_ltmp" 2>/dev/null \
            && cat "$_ltmp" > "$REDIRECT_LOG" 2>/dev/null || true
        rm -f "$_ltmp"
    fi
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
    # dns4.2.20: glob-цикл вместо $(ls -d …) — пути с пробелами больше
    # не разбиваются по IFS (замечание аудита A2, SC2045).
    for _c in /usr/sbin/iptables* /sbin/iptables* /bin/iptables* \
        /tmp/sbin/iptables*; do
        [ -e "$_c" ] || continue
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

# NDM invokes this hook separately for each table. Snapshot that one table
# before mutation and restore it on any mandatory failure. save/restore must
# come from the same xtables installation as the selected capable iptables;
# mixing an Entware helper with a firmware binary makes rollback unreliable.
iptables_aux() {
    _ia_kind="$1"
    _ia_dir="${IPT_BIN%/*}"
    [ "$_ia_dir" != "$IPT_BIN" ] || _ia_dir="."
    for _ia_c in "$_ia_dir/iptables-$_ia_kind" "$_ia_dir/$_ia_kind" \
        /usr/sbin/iptables-"$_ia_kind" /sbin/iptables-"$_ia_kind" \
        /bin/iptables-"$_ia_kind" /usr/bin/iptables-"$_ia_kind" \
        /tmp/sbin/iptables-"$_ia_kind" /tmp/usr/sbin/iptables-"$_ia_kind" \
        /opt/sbin/iptables-"$_ia_kind" /opt/bin/iptables-"$_ia_kind"; do
        [ -x "$_ia_c" ] && { printf '%s\n' "$_ia_c"; return 0; }
    done
    return 1
}

IPT_SAVE_BIN="${IPT_SAVE_BIN:-$(iptables_aux save 2>/dev/null || true)}"
IPT_RESTORE_BIN="${IPT_RESTORE_BIN:-$(iptables_aux restore 2>/dev/null || true)}"
NETFILTER_SNAPSHOT_NAT="/tmp/keenzoo-iptables-nat.$$.save"
NETFILTER_SNAPSHOT_MANGLE="/tmp/keenzoo-iptables-mangle.$$.save"
NETFILTER_SNAPSHOT_FILTER="/tmp/keenzoo-iptables-filter.$$.save"
NETFILTER_SNAPSHOT_NAT_READY=0
NETFILTER_SNAPSHOT_MANGLE_READY=0
NETFILTER_SNAPSHOT_FILTER_READY=0
TPROXY_RULE_ADDED=0
TPROXY_ROUTE_ADDED=0
if [ -z "$IPT_SAVE_BIN" ] || [ -z "$IPT_RESTORE_BIN" ]; then
    log_msg "matching iptables-save/restore binaries not found for $IPT_BIN"
    exit 1
fi
if [ "${table:-}" = "filter" ]; then
    "$IPT_SAVE_BIN" -t filter > "$NETFILTER_SNAPSHOT_FILTER" 2>/dev/null \
        && NETFILTER_SNAPSHOT_FILTER_READY=1 || {
        log_msg "filter snapshot failed"
        exit 1
    }
else
    "$IPT_SAVE_BIN" -t nat > "$NETFILTER_SNAPSHOT_NAT" 2>/dev/null \
        && NETFILTER_SNAPSHOT_NAT_READY=1 || {
        log_msg "nat snapshot failed"
        exit 1
    }
    if [ "${DNS_ONLY:-0}" != 1 ]; then
    "$IPT_SAVE_BIN" -t mangle > "$NETFILTER_SNAPSHOT_MANGLE" 2>/dev/null \
        && NETFILTER_SNAPSHOT_MANGLE_READY=1 || {
        log_msg "mangle snapshot failed"
        exit 1
    }
    fi
fi

netfilter_exit() {
    _nfe_rc=$?
    if [ "$_nfe_rc" -ne 0 ]; then
        [ "$TPROXY_RULE_ADDED" -eq 1 ] && \
            ip rule del fwmark "${TPROXY_MARK:-0x1000000}/${TPROXY_MASK:-0x1000000}" \
                lookup "${TPROXY_TABLE:-100}" priority "${TPROXY_RULE_PRIO:-1770}" \
                >/dev/null 2>&1 || true
        [ "$TPROXY_ROUTE_ADDED" -eq 1 ] && \
            ip route del local default dev lo table "${TPROXY_TABLE:-100}" \
                >/dev/null 2>&1 || true
        [ "$NETFILTER_SNAPSHOT_NAT_READY" -eq 1 ] && \
            "$IPT_RESTORE_BIN" < "$NETFILTER_SNAPSHOT_NAT" >/dev/null 2>&1 || \
            true
        [ "$NETFILTER_SNAPSHOT_MANGLE_READY" -eq 1 ] && \
            "$IPT_RESTORE_BIN" < "$NETFILTER_SNAPSHOT_MANGLE" >/dev/null 2>&1 || \
            true
        [ "$NETFILTER_SNAPSHOT_FILTER_READY" -eq 1 ] && \
            "$IPT_RESTORE_BIN" < "$NETFILTER_SNAPSHOT_FILTER" >/dev/null 2>&1 || \
            true
    fi
    rm -f "$NETFILTER_SNAPSHOT_NAT" "$NETFILTER_SNAPSHOT_MANGLE" \
        "$NETFILTER_SNAPSHOT_FILTER" 2>/dev/null || true
    netfilter_unlock
    exit "$_nfe_rc"
}
trap netfilter_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# PURGE_PROJECT is handled after the matching iptables binaries and shared
# lock are ready. Seed the same runtime constants under `set -u`; normal
# service discovery below recalculates LAN_IFACES/local_ip for apply mode.
PORT_SS="${PORT_SS:-$(config_number localportsh 1082)}"
PORT_TOR="${PORT_TOR:-$(config_number localporttor 9141)}"
PORT_VLESS="${PORT_VLESS:-$(config_number localportvless 10810)}"
PORT_TROJAN="${PORT_TROJAN:-$(config_number localporttrojan 10829)}"
PORT_HYSTERIA="${PORT_HYSTERIA:-$(config_number localporthysteria 10830)}"
PORT_WEB="${PORT_WEB:-$(config_number web_port 8080)}"
TPROXY_MARK="${TPROXY_MARK:-0x1000000}"
TPROXY_MASK="${TPROXY_MASK:-0x1000000}"
TPROXY_TABLE="${TPROXY_TABLE:-100}"
TPROXY_RULE_PRIO="${TPROXY_RULE_PRIO:-1770}"
XRAY_MARK="${XRAY_MARK:-0x2000000}"
LAN_IFACE_PATTERNS="${LAN_IFACE_PATTERNS:-br0 br1 br2 wlan0 wlan1 wlan2 wlan3 nwg0 nwg1 nwg2 wg0 wg1 tun0 tap0 ppp-l2tp0 sstp0}"
LAN_IFACES="${LAN_IFACES:-$LAN_IFACE_PATTERNS}"
local_ip="${local_ip:-${CONFIG_ROUTER_IP:-$(config_string routerip 192.168.1.1)}}"
if [ "${PURGE_PROJECT:-0}" = "1" ]; then
    purge_project_netfilter
    exit 0
fi

# Одноразовая очистка старого policy-VPN выполняется до обычной генерации
# правил. Это нужно, чтобы сначала снять references на ipset, а затем
# безопасно уничтожить ошибочный набор WAN/Bridge.
purge_vpn_state() {
    _pvs_set="${PURGE_VPN_SET:-}"
    _pvs_mark="${PURGE_VPN_MARK:-}"
    [ -n "$_pvs_set" ] || return 0

    for _pvs_proto in tcp udp; do
        while $IPT -t mangle -D PREROUTING -p "$_pvs_proto" \
            -m set --match-set "$_pvs_set" dst \
            -j MARK --set-mark "$_pvs_mark" >/dev/null 2>&1; do :; done
    done
    while $IPT -t mangle -D PREROUTING \
        -m conntrack --ctstate NEW \
        -m set --match-set "$_pvs_set" dst \
        -j CONNMARK --set-mark "$_pvs_mark" >/dev/null 2>&1; do :; done
    return 0
}

if [ -n "${PURGE_VPN_SET:-}" ]; then
    purge_vpn_state
    exit 0
fi

# ── Порты локальных прокси ───────────────────────────────────────────────
PORT_SS="${PORT_SS:-$(config_number localportsh 1082)}"
PORT_TOR="${PORT_TOR:-$(config_number localporttor 9141)}"
PORT_VLESS="${PORT_VLESS:-$(config_number localportvless 10810)}"
PORT_TROJAN="${PORT_TROJAN:-$(config_number localporttrojan 10829)}"
PORT_HYSTERIA="${PORT_HYSTERIA:-$(config_number localporthysteria 10830)}"
# Порт веб-панели (generator.py). Держится здесь, чтобы
# правила доступа переустанавливались вместе с остальными.
PORT_WEB="${PORT_WEB:-$(config_number web_port 8080)}"
# The DNS owner publishes its verified tunnel selection in the existing,
# bounded health log. Netfilter consumes that decision; it must never choose
# a tunnel merely because an enabled process happens to be running.
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-$(config_string dns_health_log /opt/var/log/unblock_dns_health.log)}"
DNS_SNAPSHOT_MAX_AGE="${DNS_SNAPSHOT_MAX_AGE:-$(config_number dns_snapshot_max_age 21600)}"  # was 90000=25h (dns4.2.21)
case "$DNS_SNAPSHOT_MAX_AGE" in
    ''|*[!0-9]*) DNS_SNAPSHOT_MAX_AGE=21600 ;;  # was 90000 (dns4.2.21)
esac

# DNS-only refresh uses the SAME DNS helpers as a normal NDM event, but
# does not rebuild LAN, TPROXY or WireGuard rules (nor their routing tables).
INIT_VLESS="/opt/etc/init.d/S24xray"
INIT_TROJ="/opt/etc/init.d/S22trojan"
INIT_HY="/opt/etc/init.d/S57hysteria"
# shellcheck disable=SC2154 # _svc_cached задаётся через eval _SVC_ALIVE_<key> (динамика, dns4.2.20)
svc_enabled() {
    _init="$1"
    [ -f "$_init" ] || return 1
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
    [ -n "$_svc_proc" ] || return 1

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

dns_snapshot_tunnel() {
    [ -f "$DNS_HEALTH_LOG" ] || return 1
    _dst_line="$(grep 'decision=final ' "$DNS_HEALTH_LOG" 2>/dev/null | tail -1 || true)"
    [ -n "$_dst_line" ] || return 1
    _dst_epoch="$(printf '%s\n' "$_dst_line" | sed -n 's/.* epoch=\([0-9][0-9]*\) .*/\1/p')"
    case "$_dst_epoch" in ''|*[!0-9]*) return 1 ;; esac
    _dst_now="$(date +%s 2>/dev/null || echo 0)"
    [ "$_dst_now" -ge "$_dst_epoch" ] || return 1
    [ $((_dst_now - _dst_epoch)) -le "$DNS_SNAPSHOT_MAX_AGE" ] || return 1
    _dst_mode="$(printf '%s\n' "$_dst_line" | sed -n 's/.* mode=\([^ ]*\).*/\1/p')"
    _dst_level="$(printf '%s\n' "$_dst_line" | sed -n 's/.* level=\([^ ]*\).*/\1/p')"
    _dst_required="$(printf '%s\n' "$_dst_line" | sed -n 's/.* required=\([^ ]*\).*/\1/p')"
    _dst_verified="$(printf '%s\n' "$_dst_line" | sed -n 's/.* verified=\([^ ]*\).*/\1/p')"
    _dst_tunnel="$(printf '%s\n' "$_dst_line" | sed -n 's/.* tunnel=\([^ ]*\).*/\1/p')"
    [ "$_dst_mode" = "TUNNEL_DNS" ] \
        && [ "$_dst_level" = "TUNNEL_DNS" ] \
        && [ "$_dst_required" = "1" ] \
        && [ "$_dst_verified" = "1" ] || return 1
    case "$_dst_tunnel" in
        xray) svc_enabled "$INIT_VLESS" || return 1; printf '%s\n' "$PORT_VLESS" ;;
        trojan) svc_enabled "$INIT_TROJ" || return 1; printf '%s\n' "$PORT_TROJAN" ;;
        hysteria) svc_enabled "$INIT_HY" || return 1; printf '%s\n' "$PORT_HYSTERIA" ;;
        *) return 1 ;;
    esac
}

# v4: only sockets explicitly marked by the DNS controller use tunnel DNS.
# The mandatory filter guard prevents a missing NAT rule from leaking a
# tunnel probe/query as direct TCP53. Normal DoT/DoH listeners are not routed
# through a tunnel merely because a proxy daemon is running.
apply_dns_v4_filter() {
    for _v4_mark in 0x2000101 0x2000102 0x2000103; do
        if ! $IPT -C OUTPUT -p tcp --dport 53 -m mark --mark "$_v4_mark" -j REJECT >/dev/null 2>&1; then
            $IPT -I OUTPUT 1 -p tcp --dport 53 -m mark --mark "$_v4_mark" -j REJECT || return 1
        fi
    done
}

apply_dns_v4_nat() {
    $IPT -t nat -N KZ_DNS_V4 >/dev/null 2>&1 || true
    # Build guards in filter BEFORE installing any marked redirect.
    apply_dns_v4_filter || return 1
    # No flushing of a live chain: replacing a target leaves no direct gap.
    for _v4_spec in "0x2000101:$PORT_HYSTERIA" "0x2000102:$PORT_VLESS" "0x2000103:$PORT_TROJAN"; do
        _v4_mark="${_v4_spec%%:*}"; _v4_port="${_v4_spec#*:}"
        if ! $IPT -t nat -C KZ_DNS_V4 -p tcp --dport 53 -m mark --mark "$_v4_mark" -j REDIRECT --to-ports "$_v4_port" >/dev/null 2>&1; then
            $IPT -t nat -I KZ_DNS_V4 1 -p tcp --dport 53 -m mark --mark "$_v4_mark" -j REDIRECT --to-ports "$_v4_port" || return 1
        fi
    done
    # Emergency sockets explicitly bypass project-wide router TCP redirect.
    for _v4_proto in tcp udp; do
        if ! $IPT -t nat -C OUTPUT -p "$_v4_proto" --dport 53 -m mark --mark 0x2000104 -j RETURN >/dev/null 2>&1; then
            $IPT -t nat -I OUTPUT 1 -p "$_v4_proto" --dport 53 -m mark --mark 0x2000104 -j RETURN || return 1
        fi
    done
    # Put the policy chain before generic mark/loopback/router RETURN rules.
    while $IPT -t nat -D OUTPUT -j KZ_DNS_V4 >/dev/null 2>&1; do :; done
    $IPT -t nat -I OUTPUT 1 -j KZ_DNS_V4 || return 1
}

apply_dns_filter() {
    # When tunnel DNS is verified, raw external DNS (including user-owned
    # server=/zone/<public-ip> rules) is fail-closed. System DoH/DoT uses
    # TCP/443 or TCP/853 and is redirected separately through the tunnel.
    for _raw_proto in tcp udp; do
        while $IPT -D OUTPUT -d 127.0.0.0/8 -p "$_raw_proto" --dport 53 \
            -j RETURN >/dev/null 2>&1; do :; done
        while $IPT -D OUTPUT -p "$_raw_proto" --dport 53 \
            -j DROP >/dev/null 2>&1; do :; done
    done
    _raw_block="${DNS_TUNNEL_BLOCK_RAW_DNS:-}"
    if [ -z "$_raw_block" ]; then
        _raw_block=0
        if [ "${DNS_TUNNEL_DISABLE:-0}" != 1 ] && dns_snapshot_tunnel >/dev/null; then
            _raw_block=1
        fi
    fi
    [ "${DNS_POLICY_V4:-0}" != 1 ] || _raw_block=0
    if [ "$_raw_block" = "1" ]; then
        for _raw_proto in tcp udp; do
            $IPT -I OUTPUT -d 127.0.0.0/8 -p "$_raw_proto" --dport 53 \
                -j RETURN >/dev/null 2>&1 || exit 1
            $IPT -A OUTPUT -p "$_raw_proto" --dport 53 \
                -j DROP >/dev/null 2>&1 || exit 1
        done
    fi

    if [ "${DNS_POLICY_V4:-0}" = 1 ]; then apply_dns_v4_filter || return 1; fi

}

apply_dns_nat() {
    # Required even on a cold start before the full hook has run.
    for _dn_rule in lo mark; do
        case "$_dn_rule" in
            lo) set -- -o lo ;;
            mark) set -- -m mark --mark "$XRAY_MARK" ;;
        esac
        if ! $IPT -t nat -C OUTPUT "$@" -j RETURN >/dev/null 2>&1; then
            $IPT -t nat -I OUTPUT "$@" -j RETURN >/dev/null 2>&1 || return 1
        fi
    done
[ "${DNS_POLICY_V4:-0}" != 1 ] || DNS_TUNNEL_DISABLE=1
DNS_TUNNEL_VERIFIED="${DNS_TUNNEL_VERIFIED:-0}"
DNS_TUNNEL_PORT=""
if [ "${DNS_TUNNEL_DISABLE:-0}" != "1" ]; then
    _dns_snapshot_port="$(dns_snapshot_tunnel || true)"
    case "${DNS_TUNNEL_PROTOCOL:-}" in
        xray)
            if [ "$DNS_TUNNEL_VERIFIED" = "1" ] \
                && svc_enabled "$INIT_VLESS"; then
                DNS_TUNNEL_PORT="$PORT_VLESS"
            fi
            ;;
        trojan)
            if [ "$DNS_TUNNEL_VERIFIED" = "1" ] \
                && svc_enabled "$INIT_TROJ"; then
                DNS_TUNNEL_PORT="$PORT_TROJAN"
            fi
            ;;
        hysteria)
            if [ "$DNS_TUNNEL_VERIFIED" = "1" ] \
                && svc_enabled "$INIT_HY"; then
                DNS_TUNNEL_PORT="$PORT_HYSTERIA"
            fi
            ;;
        '') DNS_TUNNEL_PORT="$_dns_snapshot_port" ;;
        *) log_msg "invalid DNS_TUNNEL_PROTOCOL; DNS redirect disabled" ;;
    esac
fi

# Снять старые варианты, включая прежнее правило без --dport.
for _dns_tunnel_port in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
    for _dns_remote_port in 443 853; do
        while $IPT -t nat -D OUTPUT -p tcp --dport "$_dns_remote_port" \
            -m set --match-set unblockdns dst \
            -j REDIRECT --to-port "$_dns_tunnel_port" >/dev/null 2>&1; do :; done
    done
    while $IPT -t nat -D OUTPUT -p tcp \
        -m set --match-set unblockdns dst \
        -j REDIRECT --to-port "$_dns_tunnel_port" >/dev/null 2>&1; do :; done
done

if [ -n "$DNS_TUNNEL_PORT" ]; then
    for _dns_remote_port in 443 853; do
        if ! $IPT -t nat -C OUTPUT -p tcp --dport "$_dns_remote_port" \
            -m set --match-set unblockdns dst \
            -j REDIRECT --to-port "$DNS_TUNNEL_PORT" >/dev/null 2>&1; then
            $IPT -t nat -A OUTPUT -p tcp --dport "$_dns_remote_port" \
                -m set --match-set unblockdns dst \
                -j REDIRECT --to-port "$DNS_TUNNEL_PORT" >/dev/null 2>&1 || exit 1
        fi
    done
fi
    if [ "${DNS_POLICY_V4:-0}" = 1 ]; then apply_dns_v4_nat || return 1; fi
    return 0
}

if [ "${DNS_ONLY:-0}" = 1 ]; then
    case "${table:-}" in
        nat) apply_dns_nat ;;
        filter) apply_dns_filter ;;
        *) log_msg "DNS_ONLY requires nat or filter"; exit 1 ;;
    esac
    exit 0
fi

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
    _li_links="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
        | sed 's/@.*//' | tr '\n' ' ')"
    # Prefer the deploy-time configuration when it exists. The parser is
    # intentionally limited to a simple Python list of interface names.
    for _li_if in $(sed -n \
        "s/^[[:space:]]*lan_ifaces[[:space:]]*=[[:space:]]*\\[\\(.*\\)\\]/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null \
        | tr -d "'\"" | tr ',' ' '); do
        if printf '%s\n' "$_li_links" | tr ' ' '\n' | grep -Fxq "$_li_if"; then
            _li_out="${_li_out}${_li_out:+ }${_li_if}"
        fi
    done
    for _li_if in $LAN_IFACE_PATTERNS; do
        if printf '%s\n' "$_li_links" | tr ' ' '\n' | grep -Fxq "$_li_if"; then
            case " $_li_out " in
                *" $_li_if "*) ;;
                *) _li_out="${_li_out}${_li_out:+ }${_li_if}" ;;
            esac
        fi
    done

    # Keenetic NDM names its WireGuard interface Wireguard0, while the
    # kernel exposes the same device as nwg0 (confirmed by Test.txt).
    # Discover all currently existing nwg*/wg* devices so a second server
    # interface (nwg1) is covered without hard-coding a stale name.
    #
    # Баг 3 фикс: добавлены серверные туннельные интерфейсы роутера
    # (OpenVPN ovpn*, SSTP sstp*, PPTP pptp*, L2TP l2tp*) — их клиенты
    # раньше полностью выпадали из перехвата. ГОЛЫЙ префикс `ppp` НЕ
    # добавлен сознательно: на Keenetic ppp0 — это обычно WAN-аплинк
    # самого роутера (PPPoE/PPTP/L2TP-клиент), и его перехват давал бы
    # обработку WAN-трафика как клиентского. Исходящие клиентские
    # туннели по-прежнему вычитываются реестром .vpn_client_devs ниже.
    for _li_if in $(ip -o link show 2>/dev/null \
        | awk -F': ' '{print $2}' | sed 's/@.*//' \
        | grep -E '^(br|nwg|wg|wlan|wl|ra|guest|ovpn|sstp|pptp|l2tp)[A-Za-z0-9_.-]*$' || true); do
        case " $_li_out " in
            *" $_li_if "*) ;;
            *) _li_out="${_li_out}${_li_out:+ }${_li_if}" ;;
        esac
    done

    # dns4.2.19: исключить исходящие клиентские туннели (реестр ведёт
    # 100-unblock-vpn.sh, формат "<dev> <rci-id>"): удалённая сторона
    # такого туннеля — не LAN-клиенты, иначе она получала бы перехват
    # DNS/TCP в наши прокси и ACCEPT веб-порта панели в секции 8.
    # Фильтр строго read-only: мутация реестра — только в путях up/down
    # хука 100-unblock-vpn.sh, не из accessor-а.
    if [ -f /opt/etc/unblock/.vpn_client_devs ]; then
        _li_vpn_devs=" $(awk '{print $1}' \
            /opt/etc/unblock/.vpn_client_devs 2>/dev/null | tr '\n' ' ') "
        if [ "$_li_vpn_devs" != "  " ]; then
            _li_filtered=""
            for _li_cand in $_li_out; do
                case "$_li_vpn_devs" in
                    *" $_li_cand "*) continue ;;
                esac
                _li_filtered="${_li_filtered}${_li_filtered:+ }${_li_cand}"
            done
            _li_out="$_li_filtered"
        fi
    fi

    # No br0 fallback: applying a rule to a guessed interface is worse than
    # temporarily having no client redirect during early boot.
    printf '%s\n' "$_li_out"
}

LAN_IFACES="$(lan_ifaces)"

# Use the configured routerip when it is actually assigned, otherwise
# discover a private address on the detected LAN interfaces. This supports
# non-br0 Keenetic layouts without trusting an arbitrary WAN address.
CONFIG_ROUTER_IP="${ROUTER_IP:-}"
if [ -z "$CONFIG_ROUTER_IP" ] && [ -f /opt/etc/bot/bot_config.py ]; then
    CONFIG_ROUTER_IP="$(sed -n \
        "s/^[[:space:]]*routerip[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    if [ -z "$CONFIG_ROUTER_IP" ]; then
        CONFIG_ROUTER_IP="$(sed -n \
            's/^[[:space:]]*routerip[[:space:]]*=[[:space:]]*"\([^"\]*\)".*/\1/p' \
            /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    fi
fi
local_ip=""
if printf '%s\n' "$CONFIG_ROUTER_IP" | awk -F. \
    'NF==4 && $1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255 {ok=1} END{exit !ok}' \
    && ip -4 addr show 2>/dev/null | grep -q "[[:space:]]$CONFIG_ROUTER_IP/"; then
    local_ip="$CONFIG_ROUTER_IP"
fi
if [ -z "$local_ip" ]; then
    for _lip_if in $LAN_IFACES; do
        _lip_candidate="$(ip -4 addr show "$_lip_if" 2>/dev/null \
            | awk '/inet /{print $2}' | cut -d/ -f1 \
            | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' \
            | head -n1)"
        if [ -n "$_lip_candidate" ]; then
            local_ip="$_lip_candidate"
            break
        fi
    done
fi

# ═════════════════════════════════════════════════════════════════════════
# 8. Доступ к веб-панели: только из локальных сетей
# ═════════════════════════════════════════════════════════════════════════
# Правила ставятся здесь, а не только при старте панели: Keenetic
# пересоздаёт цепочки при смене состояния интерфейсов и вызывает этот хук,
# после чего разрешающие правила панели пропадали и она становилась
# недоступной из LAN до перезапуска S99generator.
# Разрешение выдаётся по loopback и фактическим внутренним интерфейсам.
# Это закрывает WAN spoofing даже при RFC1918 source address.
if [ "${table:-}" = "filter" ]; then
    apply_dns_filter

    # Remove legacy source-only accepts. A private source address arriving
    # from WAN is not a trustworthy LAN identity.
    while $IPT -D INPUT -p tcp --dport "$PORT_WEB" -j DROP >/dev/null 2>&1; do :; done
    for web_net in $LOCAL_NETS; do
        while $IPT -D INPUT -p tcp --dport "$PORT_WEB" -s "$web_net" \
            -j ACCEPT >/dev/null 2>&1; do :; done
    done
    if ! $IPT -C INPUT -i lo -p tcp --dport "$PORT_WEB" -j ACCEPT >/dev/null 2>&1; then
        $IPT -I INPUT -i lo -p tcp --dport "$PORT_WEB" -j ACCEPT >/dev/null 2>&1 || exit 1
    fi
    for web_if in $LAN_IFACES; do
        if ! $IPT -C INPUT -i "$web_if" -p tcp --dport "$PORT_WEB" -j ACCEPT >/dev/null 2>&1; then
            $IPT -I INPUT -i "$web_if" -p tcp --dport "$PORT_WEB" -j ACCEPT >/dev/null 2>&1 || exit 1
        fi
    done
    $IPT -A INPUT -p tcp --dport "$PORT_WEB" -j DROP >/dev/null 2>&1 || exit 1

    # ─────────────────────────────────────────────────────────────────
    # Прокси-порты: закрыть от WAN (defense-in-depth).
    # ─────────────────────────────────────────────────────────────────
    # ss-redir, tor, xray, trojan и hysteria слушают 0.0.0.0, потому что
    # принимают перехваченный трафик со всех внутренних интерфейсов.
    # Своих правил INPUT у них не было — защищал только межсетевой экран
    # прошивки. При случайном пробросе порта или его отключении роутер
    # превратился бы в открытый прокси-релей.
    #
    # Разрешение выдаётся только через loopback и фактически существующие
    # внутренние интерфейсы; source CIDR alone is deliberately not trusted.
    # DROP всегда добавляется последним, поэтому отсутствие LAN-интерфейса
    # в ранней загрузке оставляет порт закрытым.
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

            # Remove legacy source-only accepts so a spoofed RFC1918
            # source from WAN cannot reach a local proxy listener.
            for proxy_net in $LOCAL_NETS; do
                while $IPT -D INPUT -p "$proxy_proto" \
                    --dport "$proxy_port" -s "$proxy_net" \
                    -j ACCEPT >/dev/null 2>&1; do :; done
            done

            $IPT -A INPUT -p "$proxy_proto" \
                --dport "$proxy_port" -j DROP \
                >/dev/null 2>&1 \
                || log_msg "INPUT DROP failed: $proxy_proto/$proxy_port"
        done
    done
fi

if [ "${table:-}" = "filter" ]; then
    # В таблице filter больше делать нечего.
    exit 0
fi

if [ "${table:-}" = "nat" ] && [ -z "$local_ip" ]; then
    log_msg "LAN router IP not found; refusing DNS DNAT"
    exit 1
fi

remove_dns_tunnel_set_refs() {
    # unblockdns is shared by the DNS owner and this hook. If an older
    # installation created it with another ipset type/geometry, ipset -exist
    # rejects the new create. Remove only the OUTPUT DNS redirects first so
    # the incompatible set can be rebuilt safely.
    for _rds_port in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        for _rds_remote in 443 853; do
            while $IPT -t nat -D OUTPUT -p tcp --dport "$_rds_remote" \
                -m set --match-set unblockdns dst \
                -j REDIRECT --to-port "$_rds_port" >/dev/null 2>&1; do :; done
        done
        while $IPT -t nat -D OUTPUT -p tcp \
            -m set --match-set unblockdns dst \
            -j REDIRECT --to-port "$_rds_port" >/dev/null 2>&1; do :; done
    done
}

rebuild_dns_tunnel_set() {
    remove_dns_tunnel_set_refs
    ipset flush unblockdns >/dev/null 2>&1 || true
    ipset flush unblockdns_new >/dev/null 2>&1 || true
    ipset destroy unblockdns_new >/dev/null 2>&1 || true
    ipset destroy unblockdns >/dev/null 2>&1 || true
    ipset create unblockdns hash:net family inet hashsize 1024 \
        maxelem 65536 -exist 2>/dev/null
}

ensure_set() {
    _es_set="$1"
    if ipset create "$_es_set" hash:net family inet hashsize 1024 \
        maxelem 65536 -exist 2>/dev/null; then
        return 0
    fi
    if [ "$_es_set" = "unblockdns" ]; then
        log_msg "ipset create failed: unblockdns; rebuilding incompatible DNS set"
        if rebuild_dns_tunnel_set; then
            log_msg "ipset unblockdns rebuilt as hash:net/family=inet"
            return 0
        fi
    fi
    log_msg "ipset create failed: $_es_set"
    return 1
}

# ── Идемпотентные помощники (проверка через -C, без grep по iptables-save)
# Протокол считается выключенным, если в его init-скрипте стоит
# ENABLED=no (ползунок в веб-панели). Для такого протокола правила
# перехвата не создаются, а ранее созданные снимаются — иначе трафик
# уходил бы на порт остановленного сервиса и соединение просто рвалось.


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
        if ! $IPT -t nat -A PREROUTING -i "$_if" -p "$_proto" \
            -m set --match-set "$_set" dst \
            -j REDIRECT --to-port "$_port" >/dev/null 2>&1; then
            log_msg "REDIRECT add failed: $_set/$_port/$_if/$_proto"
            return 1
        fi
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
                return 1
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

# dns4.2.19: жёсткий DNAT на единый $local_ip ломал DNS клиентов
# серверного WireGuard (запрос к адресу туннельного интерфейса, напр.
# 172.16.82.1, переписывался на адрес другого сегмента). Канонический
# REDIRECT подставляет primary-адрес ingress-интерфейса; старые per-iface
# DNAT-правила сначала миграционно снимаются. При недоступном xt_REDIRECT
# — fallback на DNAT на адрес самого интерфейса, строго с собственным
# -C-гейтом (иначе каждое NDM-событие плодило бы дубликаты).
for iface in $LAN_IFACES; do
    for protocol in udp tcp; do
        # Миграция: устаревший per-iface DNAT на общий $local_ip
        while $IPT -t nat -D PREROUTING -i "$iface" -p "$protocol" --dport 53 \
            -j DNAT --to-destination "$local_ip" >/dev/null 2>&1
        do
            :
        done

        if ! $IPT -t nat -C PREROUTING -i "$iface" -p "$protocol" --dport 53 \
            -j REDIRECT --to-ports 53 >/dev/null 2>&1; then
            if ! $IPT -t nat -I PREROUTING -i "$iface" -p "$protocol" --dport 53 \
                -j REDIRECT --to-ports 53 >/dev/null 2>&1; then
                _di_if_ip="$(ip -4 addr show "$iface" 2>/dev/null \
                    | awk '/inet /{print $2; exit}' | cut -d/ -f1)"
                [ -n "$_di_if_ip" ] || _di_if_ip="$local_ip"
                if ! $IPT -t nat -C PREROUTING -i "$iface" -p "$protocol" --dport 53 \
                    -j DNAT --to-destination "$_di_if_ip" >/dev/null 2>&1; then
                    $IPT -t nat -I PREROUTING -i "$iface" -p "$protocol" --dport 53 \
                        -j DNAT --to-destination "$_di_if_ip" >/dev/null 2>&1 || {
                        log_msg "DNS intercept add failed: $iface/$protocol"
                        exit 1
                    }
                fi
            fi
        fi
    done
done

# ═════════════════════════════════════════════════════════════════════════
# 2. Подготовка ipset
# ═════════════════════════════════════════════════════════════════════════
for s in unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter unblockdns; do
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
TPROXY_REQUIRED=0
if svc_enabled "$INIT_VLESS" || svc_enabled "$INIT_HY"; then
    TPROXY_REQUIRED=1
fi

# Баг 1 фикс: предпроверка возможностей ядра ДО каких-либо изменений.
# Старая версия здесь делала `exit 1`, и снапшот-ловушка откатывала
# УЖЕ применённые в секции 4 TCP-правила: отсутствие модуля ядра
# ломало не только UDP-туннель, но и весь обход. Теперь при отсутствии
# поддержки деградируем в режим «только TCP» без выхода из скрипта:
# тот же итог, что обещает диагностика mangle_add_tproxy («TCP не
# затронут»), но без убийства применённых правил.
if [ "$TPROXY_REQUIRED" -eq 1 ]; then
    if ! ensure_tproxy_kmod; then
        log_msg "TPROXY: цель недоступна в ядре — деградация в режим только TCP (UDP в туннель не пойдёт)"
        TPROXY_REQUIRED=0
    elif ! ipt_has_match "$IPT_BIN" socket; then
        log_msg "TPROXY: xt_socket недоступен — деградация в режим только TCP"
        TPROXY_REQUIRED=0
    elif ! ipt_has_match "$IPT_BIN" set; then
        log_msg "TPROXY: xt_set недоступен — деградация в режим только TCP"
        TPROXY_REQUIRED=0
    fi
fi

if [ "$TPROXY_REQUIRED" -eq 1 ]; then
    tproxy_rule_exact() {
        awk -v p="$TPROXY_RULE_PRIO" -v m="$TPROXY_MARK/$TPROXY_MASK" -v t="$TPROXY_TABLE" \
            '$1 == p ":" && $4 == "fwmark" && ($5 == m || ($5 == "16777216/16777216" && m == "0x1000000/0x1000000")) && $6 == "lookup" && $7 == t {ok=1} END {exit !ok}'
    }
    tproxy_route_exact() {
        awk -v t="$TPROXY_TABLE" \
            '$1 == "local" && $2 == "default" && $3 == "dev" && $4 == "lo" {ok=1} END {exit !ok}'
    }
    if ! ip rule show 2>/dev/null | tproxy_rule_exact; then
        ip rule add fwmark "${TPROXY_MARK}/${TPROXY_MASK}" \
            lookup "$TPROXY_TABLE" priority "$TPROXY_RULE_PRIO" 2>/dev/null || {
            log_msg "TPROXY ip rule add failed"
            exit 1
        }
        TPROXY_RULE_ADDED=1
    fi
    if ! ip route show table "$TPROXY_TABLE" 2>/dev/null | tproxy_route_exact; then
        TPROXY_ROUTE_ADDED=1
    fi
    ip route replace local default dev lo table "$TPROXY_TABLE" 2>/dev/null || {
        log_msg "TPROXY local route add failed"
        exit 1
    }
    if ! ip rule show 2>/dev/null | tproxy_rule_exact \
        || ! ip route show table "$TPROXY_TABLE" 2>/dev/null | tproxy_route_exact; then
        log_msg "TPROXY policy routing verification failed"
        exit 1
    fi
fi

# Пакеты уже установленных TPROXY-сессий должны попадать на локальный сокет
# до правил TPROXY (иначе они уйдут в форвардинг).
if [ "$TPROXY_REQUIRED" -eq 1 ] \
    && ! $IPT -t mangle -C PREROUTING -p udp -m socket \
        -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1
then
    $IPT -t mangle -I PREROUTING -p udp -m socket \
        -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1 || {
        log_msg "TPROXY socket mark add failed"
        exit 1
    }
fi

# Баг 1 фикс (продолжение): при `set -eu` return 1 из mangle_add_tproxy
# убивал скрипт посреди цикла и откатывал применённые правила. Функция
# сама пишет причину отказа в журнал (включая одноразовую диагностику
# «ядро НЕ поддерживает цель TPROXY») — фиксируем деградацию и идём
# дальше: правила для остальных интерфейсов/протоколов продолжают
# применяться, TCP-обход не затрагивается.
for iface in $LAN_IFACES; do
    if svc_enabled "$INIT_VLESS"; then
        mangle_add_tproxy unblockvless    "$PORT_VLESS"    "$iface" || {
            log_msg "TPROXY: правило для $iface отклонено — деградация (интерфейс/протокол пропущен)"
        }
    else
        mangle_del_tproxy unblockvless    "$PORT_VLESS"    "$iface"
    fi
    if svc_enabled "$INIT_HY"; then
        mangle_add_tproxy unblockhysteria "$PORT_HYSTERIA" "$iface" || {
            log_msg "TPROXY: правило для $iface отклонено — деградация (интерфейс/протокол пропущен)"
        }
    else
        mangle_del_tproxy unblockhysteria "$PORT_HYSTERIA" "$iface"
    fi
done

# ═════════════════════════════════════════════════════════════════════════
# 6. Трафик самого роутера (bot.txt -> unblockrouter)
# ═════════════════════════════════════════════════════════════════════════
if ! $IPT -t nat -C OUTPUT -o lo -j RETURN >/dev/null 2>&1; then
    $IPT -t nat -I OUTPUT -o lo -j RETURN >/dev/null 2>&1 || exit 1
fi

for net in $LOCAL_NETS; do
    if ! $IPT -t nat -C OUTPUT -d "$net" -j RETURN >/dev/null 2>&1; then
        $IPT -t nat -A OUTPUT -d "$net" -j RETURN >/dev/null 2>&1 || exit 1
    fi
done

# Защита от петли: пакеты, которые xray сам отправляет наружу, помечены
# XRAY_MARK (sockopt.mark в outbound). Без этого исключения правила ниже
# завернули бы исходящий трафик xray обратно в его же inbound.
if ! $IPT -t nat -C OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; then
    $IPT -t nat -I OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1 || exit 1
fi
if ! $IPT -t mangle -C OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1; then
    $IPT -t mangle -I OUTPUT -m mark --mark "$XRAY_MARK" -j RETURN >/dev/null 2>&1 || exit 1
fi

# DNS через активный туннель. В наборе unblockdns находятся адреса
# внешних системных DoH/DoT endpoint-ов, а не IP произвольных сайтов.
# Поэтому клиентский DNS остаётся в dnsmasq/system proxy, а только его
# исходящие TCP/443 и TCP/853 соединения идут через выбранный tunnel.
#
# ВАЖНО: выбор transport принадлежит unblock_dnsmasq.sh. При обычном
# вызове NDM этот hook только потребляет свежий canonical snapshot из
# существующего bounded health log; поиск «первого живого процесса» здесь
# запрещён, иначе fallback Xray -> Trojan -> Hysteria расходился бы с DNS
# health и мог вернуть stale unblockdns к другому tunnel.


apply_dns_nat

# TCP router path: selection is a single data word, NEVER sourced as shell.
router_protocol() {
    _rp_file=/opt/etc/unblock/.router_protocol
    _rp=xray
    if [ -f "$_rp_file" ]; then
        IFS= read -r _rp < "$_rp_file" || [ -n "$_rp" ] || return 1
    fi
    case "$_rp" in xray|trojan|hysteria) printf '%s\n' "$_rp" ;; *) return 1 ;; esac
}

apply_router_tcp() {
    _rt_proto="$(router_protocol)" || { log_msg "invalid router protocol"; return 1; }
    case "$_rt_proto" in
        xray) _rt_init="$INIT_VLESS"; _rt_port="$PORT_VLESS" ;;
        trojan) _rt_init="$INIT_TROJ"; _rt_port="$PORT_TROJAN" ;;
        hysteria) _rt_init="$INIT_HY"; _rt_port="$PORT_HYSTERIA" ;;
    esac
    # Small dedicated chain: do not flush OUTPUT or any Keenetic/WireGuard chain.
    if ! $IPT -t nat -S KZ_ROUTER >/dev/null 2>&1; then
        $IPT -t nat -N KZ_ROUTER >/dev/null 2>&1 || return 1
    fi
    $IPT -t nat -F KZ_ROUTER >/dev/null 2>&1 || return 1
    # Remove legacy redirects and the old jump; reinstall exactly once.
    while $IPT -t nat -D OUTPUT -p tcp -m set --match-set unblockrouter dst \
        -j KZ_ROUTER >/dev/null 2>&1; do :; done
    for _rt_old in "$PORT_VLESS" "$PORT_TROJAN" "$PORT_HYSTERIA"; do
        while $IPT -t nat -D OUTPUT -p tcp -m set --match-set unblockrouter dst \
            -j REDIRECT --to-port "$_rt_old" >/dev/null 2>&1; do :; done
    done
    svc_enabled "$_rt_init" || return 0

    # Trojan has no Xray sockopt mark. Bypass its upstream to prevent a loop
    # if a broad bot.txt CIDR contains the VPS. Domain endpoints require the
    # existing managed pins; no new DNS requests in a short NDM hook.
    if [ "$_rt_proto" = trojan ]; then
        _rt_host="$(sed -n 's/.*"remote_addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /opt/etc/trojan/config.json | head -n1)"
        _rt_ips="$(printf '%s\n' "$_rt_host" | awk -F. '
            NF==4 {ok=1; for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) ok=0; if(ok) print}')"
        if [ -z "$_rt_ips" ]; then
            _rt_ips="$(awk -v h="$_rt_host" '
                /^# --- KeenZOO pinned / {inside=1; next}
                /^# --- end KeenZOO pinned/ {inside=0}
                inside && $1 !~ /^#/ {for(i=2;i<=NF;i++) if($i==h) print $1}
            ' /opt/etc/hosts 2>/dev/null || true)"
        fi
        [ -n "$_rt_ips" ] || { log_msg "Trojan router path: missing IPv4 endpoint pin"; return 1; }
        for _rt_ip in $_rt_ips; do
            $IPT -t nat -A KZ_ROUTER -d "$_rt_ip" -j RETURN >/dev/null 2>&1 || return 1
        done
    fi
    $IPT -t nat -A KZ_ROUTER -p tcp -j REDIRECT --to-port "$_rt_port" >/dev/null 2>&1 || return 1
    $IPT -t nat -A OUTPUT -p tcp -m set --match-set unblockrouter dst \
        -j KZ_ROUTER >/dev/null 2>&1 || return 1
}
# dns4.2.20: router-путь ОПЦИОНАЛЕН и некритичен. Его отказ (повреждённый
# .router_protocol, временно отсутствующий trojan-pin в /opt/etc/hosts) не
# должен завершать весь nat-прогон: иначе trap откатывал снапшотом уже
# установленные правила на КАЖДОМ событии NDM. Функция идемпотентна и при
# выключенном сервисе возвращает 0 после снятия legacy-правил; обязательные
# секции по-прежнему завершают прогон с ошибкой.
apply_router_tcp || log_msg "router path skipped (non-critical)"

# Local-origin UDP is deliberately not intercepted. Linux local packets
# traverse OUTPUT -> POSTROUTING, not PREROUTING; marking OUTPUT and hoping
# for a second PREROUTING pass is not a valid transparent-proxy design.
# bot.txt is therefore a TCP-only router path, which is sufficient for the
# Telegram/HTTP bot. Remove rules left by older releases.
while $IPT -t nat -D OUTPUT -p udp \
    -m set --match-set unblockrouter dst \
    -j REDIRECT --to-port "$PORT_SS" >/dev/null 2>&1; do :; done
while $IPT -t nat -D OUTPUT -p udp \
    -m set --match-set unblockrouter dst \
    -j REDIRECT --to-port "$PORT_VLESS" >/dev/null 2>&1; do :; done
while $IPT -t mangle -D OUTPUT -p udp \
    -m set --match-set unblockrouter dst \
    -j MARK --set-mark "${TPROXY_MARK}/${TPROXY_MASK}" >/dev/null 2>&1; do :; done

# ═════════════════════════════════════════════════════════════════════════
# 7. VPN-интерфейсы прошивки: ipset -> fwmark -> policy routing
# ═════════════════════════════════════════════════════════════════════════
# При отключении интерфейса нельзя оставлять старые MARK/CONNMARK-правила:
# они отправляют новый трафик в уже неработающую policy table.
vpn_del_mark_rules() {
    _vd_set="$1"
    _vd_mark="$2"

    for _vd_proto in tcp udp; do
        while $IPT -t mangle -D PREROUTING -p "$_vd_proto" \
            -m set --match-set "$_vd_set" dst \
            -j MARK --set-mark "$_vd_mark" >/dev/null 2>&1
        do
            :
        done
    done

    while $IPT -t mangle -D PREROUTING \
        -m conntrack --ctstate NEW \
        -m set --match-set "$_vd_set" dst \
        -j CONNMARK --set-mark "$_vd_mark" >/dev/null 2>&1
    do
        :
    done
}

for vpn_file_name in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_name" ] || continue

    vpn_unblock_name="$(basename "$vpn_file_name" .txt)"
    unblockvpn="unblock${vpn_unblock_name}"
    vpn_type="$(printf '%s\n' "$unblockvpn" | sed 's/-/ /g' | awk '{print $NF}')"
    [ -n "$vpn_type" ] || continue

    vpn_type_lower="$(printf '%s' "$vpn_type" | tr '[:upper:]' '[:lower:]')"
    vpn_table_id="$(grep -w "$vpn_type_lower" /opt/etc/iproute2/rt_tables 2>/dev/null \
        | awk '{print $1}' | head -n1 || true)"
    [ -n "$vpn_table_id" ] || continue
    vpn_mark_id="0xd${vpn_table_id}"

    # dns4.2.20: различаем «RCI не ответил» (состояние неизвестно —
    # ничего не сносим) и явное не-up. Раньше пустой/ошибочный ответ
    # эквивалентился «не up» и на каждом событии NDM вёл к сносу
    # mark-правил, flush таблицы и flush ipset при живом туннеле.
    # Метрика унифицирована с 100-unblock-vpn.sh: /connected (yes|up) —
    # до правки здесь был /link, и хуки могли разойтись во мнении.
    _vlu_raw="$(curl -s --max-time 5 \
        "localhost:79/rci/show/interface/${vpn_type}/connected" 2>/dev/null || true)"
    vpn_link_up="$(printf '%s' "$_vlu_raw" | tr -d '" \r\t')"

    case "$vpn_link_up" in
        '')
            # Нет ответа: состояние неизвестно. Сохраняем всё как есть.
            continue
            ;;
        no|down|false)
            : ;;  # явное не-up: демонтаж ниже
        *)
            case "$_vlu_raw" in
                *"not found"*|*"Not Found"*)
                    : ;;  # интерфейса нет в NDM: демонтаж ниже
                *)
                    # Ошибка RCI/error-JSON без «not found»: неизвестно.
                    continue
                    ;;
            esac
            ;;
    esac
    if [ "$vpn_link_up" != "yes" ] && [ "$vpn_link_up" != "up" ]; then
        vpn_del_mark_rules "$unblockvpn" "$vpn_mark_id"
        ip -4 rule del from all table "$vpn_table_id" priority 1778 \
            >/dev/null 2>&1 || true
        ip -4 rule del fwmark "$vpn_mark_id" lookup "$vpn_table_id" \
            priority 1778 >/dev/null 2>&1 || true
        ip -4 route flush table "$vpn_table_id" >/dev/null 2>&1 || true
        ipset flush "$unblockvpn" >/dev/null 2>&1 || true
        continue
    fi

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
                    -j MARK --set-mark "$vpn_mark_id" >/dev/null 2>&1 || exit 1
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
                -j CONNMARK --set-mark "$vpn_mark_id" >/dev/null 2>&1 || exit 1
        fi
        if ! $IPT -t mangle -C PREROUTING -j CONNMARK --restore-mark >/dev/null 2>&1; then
            $IPT -t mangle -A PREROUTING -j CONNMARK --restore-mark >/dev/null 2>&1 || exit 1
        fi
    fi

    # Успешная обработка VPN-интерфейса не логируется: хук срабатывает на
    # каждое изменение состояния, и такие записи быстро раздували файл.
    # В лог попадают только ошибки.
done

exit 0

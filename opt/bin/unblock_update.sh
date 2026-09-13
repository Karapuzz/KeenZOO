#!/bin/sh
# /opt/bin/unblock_update.sh
# Единственная точка применения списков обхода:
#   1) генерация конфига dnsmasq (с БОЕВЫМИ именами ipset);
#   2) наполнение теневых наборов *_new;
#   3) атомарный ipset swap;
#   4) рестарт dnsmasq.
# Оболочка: BusyBox ash.

set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

SCRIPT_LOCK="${SCRIPT_LOCK:-/tmp/unblock_update.lockdir}"
STATUS_FILE="${STATUS_FILE:-/tmp/unblock_update_status.json}"
TMP_STATUS="${STATUS_FILE}.tmp"
LOCK_ACQUIRED=0

write_status() {
    _st="$1"
    _msg="$2"
    _ts="$(date +%s)"
    printf '{"status":"%s","ts":%s,"message":"%s"}\n' \
        "$_st" "$_ts" "$_msg" > "$TMP_STATUS"
    mv -f "$TMP_STATUS" "$STATUS_FILE"
}

cleanup() {
    _rc=$?
    rm -f "$TMP_STATUS"
    # Чужой lock снимать нельзя.
    if [ "$LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$SCRIPT_LOCK"
    fi
    return "$_rc"
}
trap cleanup EXIT INT TERM HUP

TRIES=0
while ! mkdir "$SCRIPT_LOCK" 2>/dev/null; do
    if [ -f "$SCRIPT_LOCK/pid" ]; then
        OLD_PID="$(cat "$SCRIPT_LOCK/pid" 2>/dev/null || true)"
        if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
            rm -rf "$SCRIPT_LOCK"
            continue
        fi
    fi

    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 150 ]; then
        write_status "error" "locked"
        exit 1
    fi
    sleep 2
done

LOCK_ACQUIRED=1
echo "$$" > "$SCRIPT_LOCK/pid"
write_status "running" "start"

STATIC_SETS="unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter"
VPN_SETS=""

# ONLY_SETS — частичное обновление: обрабатывается лишь указанный набор.
# Панель при правке одного списка передаёт сюда его имя, и цикл вместо
# всех 319 доменов резолвит только затронутые. Полный прогон (крон,
# загрузка) вызывается без переменной и работает как прежде.
ONLY_SETS="${ONLY_SETS:-}"
export ONLY_SETS

# REBUILD=1 — полная пересборка наборов вместо слияния (крон по средам).
# REBUILD_MIN_RATIO — порог качества: пересборка применяется, только если
# свежий набор содержит не меньше указанного процента от прежнего
# размера. 95 % выбрано осознанно: в инциденте с потерей обхода прогон
# дал 79 % (144 из 183 доменов), и такой результат порог не пройдёт.
REBUILD="${REBUILD:-0}"
REBUILD_MIN_RATIO="${REBUILD_MIN_RATIO:-95}"

upd_selected() {
    [ -n "$ONLY_SETS" ] || return 0
    for _us_want in $ONLY_SETS; do
        [ "$_us_want" = "$1" ] && return 0
    done
    return 1
}

for s in $STATIC_SETS; do
    upd_selected "$s" || continue
    ipset create "$s" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset create "${s}_new" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset flush "${s}_new" 2>/dev/null || true
done

for vpn_file_names in /opt/etc/unblock/vpn-*.txt; do
    [ -f "$vpn_file_names" ] || continue
    vpn_file_name="$(basename "$vpn_file_names" .txt)"
    unblockvpn="unblock${vpn_file_name}"
    VPN_SETS="${VPN_SETS}${VPN_SETS:+ }${unblockvpn}"
    ipset create "$unblockvpn" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset create "${unblockvpn}_new" hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || true
    ipset flush "${unblockvpn}_new" 2>/dev/null || true
done

# ── 0. Диагностика пересечений между списками ────────────────────────────
# Один и тот же адрес может попасть сразу в несколько наборов ipset, и
# тогда трафик уйдёт не в тот протокол, который выбрал пользователь.
# Причина в правилах nat PREROUTING: они создаются в фиксированном
# порядке (sh, tor, vless, troj, hysteria), а iptables применяет ПЕРВОЕ
# совпавшее — приоритет получает список, стоящий выше.
#
# Два случая пересечения:
#   1) домен буквально присутствует в двух списках;
#   2) домен одного списка является ПОДДОМЕНОМ домена из другого —
#      dnsmasq применяет ipset=/DOMAIN/SET ко всем поддоменам, поэтому
#      адрес попадает в оба набора. Реальный пример: cloudflare.net в
#      vless.txt перекрывает openai.com.cdn.cloudflare.net в trojan.txt.
#
# Списки не правятся автоматически: решение о приоритете принимает
# пользователь. Скрипт лишь пишет предупреждение в системный журнал.
check_list_overlap() {
    _clo_dir="/opt/etc/unblock"
    # Порядок = порядок правил в nat PREROUTING (кто выше, тот выигрывает).
    _clo_order="shadowsocks tor vless trojan hysteria"
    _clo_tmp="$(mktemp /tmp/overlap.XXXXXX)" || return 0

    _clo_rank=0
    for _clo_p in $_clo_order; do
        _clo_rank=$((_clo_rank + 1))
        _clo_f="${_clo_dir}/${_clo_p}.txt"
        [ -f "$_clo_f" ] || continue
        # Берётся первое поле: в списках встречается "IP #комментарий".
        # CIDR и голые адреса пропускаем — пересечения ищем по доменам.
        awk -v p="$_clo_p" -v r="$_clo_rank" '
            { sub(/\r$/, "") }
            /^[[:space:]]*(#|$)/ { next }
            {
                d = $1
                if (d ~ /^[0-9.]+$/ || d ~ /\//) next
                print tolower(d) "\t" p "\t" r
            }
        ' "$_clo_f" >> "$_clo_tmp" 2>/dev/null || true
    done

    # Один проход: индексируем домены, затем для каждого проверяем сам
    # домен и все его родительские суффиксы. Попарное сравнение (319^2)
    # на роутере слишком дорого, суффиксов же у домена единицы.
    awk -F'\t' '
        {
            dom[$1] = $2
            rank[$1] = $3
            order[++n] = $1
        }
        END {
            for (i = 1; i <= n; i++) {
                d = order[i]
                # Родительские суффиксы: a.b.c -> b.c -> c
                s = d
                while (1) {
                    p = index(s, ".")
                    if (p == 0) break
                    s = substr(s, p + 1)
                    if (s in dom && dom[s] != dom[d]) {
                        # Побеждает список с меньшим rank (он выше в цепочке).
                        if (rank[s] < rank[d]) {
                            printf("%s (%s) перекрыт правилом %s (%s)\n",
                                   d, dom[d], s, dom[s])
                        } else {
                            printf("%s (%s) перекрывает %s (%s)\n",
                                   d, dom[d], s, dom[s])
                        }
                    }
                }
            }
        }
    ' "$_clo_tmp" 2>/dev/null | sort -u | while IFS= read -r _clo_msg; do
        [ -n "$_clo_msg" ] || continue
        logger -t "unblock_update" "конфликт списков: $_clo_msg"
    done

    # Точные дубликаты одного домена в разных списках.
    cut -f1 "$_clo_tmp" 2>/dev/null | sort | uniq -d \
        | while IFS= read -r _clo_d; do
            [ -n "$_clo_d" ] || continue
            _clo_in="$(awk -F'\t' -v d="$_clo_d" \
                '$1 == d { printf "%s ", $2 }' "$_clo_tmp")"
            logger -t "unblock_update" \
                "конфликт списков: $_clo_d указан в нескольких списках: $_clo_in"
        done

    rm -f "$_clo_tmp"
    return 0
}

check_list_overlap || true

# ── 1. Конфиг dnsmasq ────────────────────────────────────────────────────
# Генерируется БЕЗ суффикса: dnsmasq пишет в постоянно существующие наборы.
# Прежняя версия запускала генератор с IPSET_SUFFIX="_new", и после swap
# наборы *_new уничтожались — dnsmasq пытался писать в несуществующие ipset
# и все новые домены переставали попадать в обход до следующего перезапуска.
if ! IPSET_SUFFIX="" /opt/bin/unblock_dnsmasq.sh; then
    write_status "error" "dnsmasq gen"
    exit 1
fi

# ── 2. Наполнение теневых наборов ────────────────────────────────────────
if ! IPSET_SUFFIX="_new" /opt/bin/unblock_ipset.sh; then
    write_status "error" "ipset fill"
    # Наборы *_new недостоверны — swap не выполняем, боевые остаются прежними.
    for s in $STATIC_SETS $VPN_SETS; do
        upd_selected "$s" || continue
        ipset flush "${s}_new" 2>/dev/null || true
        ipset destroy "${s}_new" 2>/dev/null || true
    done
    exit 1
fi

# ── 3. Слияние: новые адреса добавляются к уже накопленным ───────────────
# Раньше здесь был "ipset swap": боевой набор ЦЕЛИКОМ заменялся свежим.
# Это и ломало обход после ночного cron. dnsmasq в течение суток
# дописывает в боевой набор адреса по директивам ipset=/домен/набор —
# по мере обращений клиентов. При swap всё накопленное отбрасывалось, а
# в новом наборе оказывались только домены, которые удалось разрезолвить
# прямо сейчас. В журнале это видно прямо: "unblockvless_new: domains=183
# resolved=144" — 39 доменов оставались без адресов, и обход для них
# отваливался до следующего обращения клиента.
#
# Теперь набор дополняется, а не подменяется:
#   * swap ставит свежий набор на место боевого;
#   * затем прежнее содержимое (оно после swap лежит в *_new)
#     доливается обратно через ipset restore -exist.
# Итог — объединение старых и новых адресов без потери данных.
# Дубли исключены самой природой ipset: повторный add того же адреса
# игнорируется, а ключ -exist подавляет ошибку.
for s in $STATIC_SETS $VPN_SETS; do
    upd_selected "$s" || continue
    ipset swap "$s" "${s}_new" 2>/dev/null || true

    # REBUILD=1 — еженедельная полная пересборка (крон, среда 03:00).
    # Слияние ничего не теряет, но и не забывает: адреса, которые сервер
    # давно сменил, копились бы вечно. Раз в неделю набор оставляется
    # ровно таким, каким его построил резолвинг, — накопленный мусор
    # уходит.
    #
    # Потери, которая случалась после ночного крона, здесь быть не
    # может: пересборка выполняется ТОЛЬКО если свежий набор полноценный.
    # Критерий — доля разрешённых доменов не ниже REBUILD_MIN_RATIO.
    # В том инциденте было 144/183 = 79 %: порога 95 % такой прогон не
    # проходит, и набор был бы не пересобран, а дополнен.
    if [ "${REBUILD:-0}" = "1" ]; then
        _rb_have="$(ipset list "$s" 2>/dev/null \
            | awk '/^Members:/ {c=1; next} c && NF {n++} END {print n+0}')"
        _rb_prev="$(ipset list "${s}_new" 2>/dev/null \
            | awk '/^Members:/ {c=1; next} c && NF {n++} END {print n+0}')"
        # Пересобираем, только если свежий набор не беднее прежнего
        # более чем на (100 - REBUILD_MIN_RATIO) процентов.
        _rb_ok=0
        if [ "$_rb_prev" -eq 0 ]; then
            _rb_ok=1
        elif [ "$_rb_have" -gt 0 ]; then
            if [ $(( _rb_have * 100 / _rb_prev )) -ge "$REBUILD_MIN_RATIO" ]; then
                _rb_ok=1
            fi
        fi
        if [ "$_rb_ok" = "1" ]; then
            logger -t "unblock_update" \
                "rebuild $s: $_rb_prev -> $_rb_have (накопленное сброшено)"
            continue
        fi
        logger -t "unblock_update" \
            "rebuild $s отменён: свежих $_rb_have из $_rb_prev — дополняю"
    fi

    # Переносим накопленное (теперь в *_new) в боевой набор.
    _merge_tmp="$(mktemp /tmp/ipset.merge.XXXXXX)" || continue
    if ipset list "${s}_new" 2>/dev/null \
        | awk -v set="$s" '
            /^Members:/ { inside = 1; next }
            inside && NF { print "add " set " " $1 " -exist" }
        ' > "$_merge_tmp" 2>/dev/null
    then
        if [ -s "$_merge_tmp" ]; then
            ipset restore -exist < "$_merge_tmp" 2>/dev/null || true
        fi
    fi
    rm -f "$_merge_tmp"
done

# ── 4. Рестарт dnsmasq и переустановка правил ────────────────────────────
if [ -x /opt/etc/init.d/S56dnsmasq ]; then
    /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1 || true
fi

if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
    type=iptable table=nat /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
fi

for s in $STATIC_SETS $VPN_SETS; do
    upd_selected "$s" || continue
    ipset flush "${s}_new" 2>/dev/null || true
    ipset destroy "${s}_new" 2>/dev/null || true
done

write_status "done" "ok"
exit 0

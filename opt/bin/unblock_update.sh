#!/bin/sh
# remove keeps data but disables cron/NDM reactivation until next install.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
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
ROLLBACK_DIR=""
COMMITTED_SETS=""
STATIC_SETS=""
VPN_SETS=""
COMMIT_ROLLBACK_FAILED=0
DNSMASQ_RESTARTED=0
NETFILTER_APPLIED=0
SNAPSHOT_READY=0
TRANSACTION_DONE=0
KEEP_ROLLBACK=0
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-$(sed -n -e "s/^[[:space:]]*dns_health_log[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" -e 's/^[[:space:]]*dns_health_log[[:space:]]*=[[:space:]]*"\([^"\]*\)".*/\1/p' /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)}"
DNS_HEALTH_LOG="${DNS_HEALTH_LOG:-/opt/var/log/unblock_dns_health.log}"

json_escape_string() {
    # Экранирование для вставки в JSON: \ -> \\, " -> \", переводы строк —
    # в пробел. Без этого кавычка в сообщении ломала бы весь статус-файл,
    # и панель показывала бы «обновление не запускалось» при рабочей
    # транзакции. Один вызов sed — дёшево даже на слабом CPU роутера.
    printf '%s' "$1" \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/ /g' \
        | tr -d '\r\n'
}

write_status() {
    _st="$(json_escape_string "$1")"
    _msg="$(json_escape_string "$2")"
    _ts="$(date +%s)"
    printf '{"status":"%s","ts":%s,"message":"%s"}\n' \
        "$_st" "$_ts" "$_msg" > "$TMP_STATUS"
    mv -f "$TMP_STATUS" "$STATUS_FILE"
}

cleanup() {
    _rc=$?
    # set -e and TERM must not leave a partially applied transaction.
    if [ "$SNAPSHOT_READY" -eq 1 ] && [ "$TRANSACTION_DONE" -eq 0 ] && [ "$_rc" -ne 0 ]; then
        rollback_update "interrupted or unexpected failure" || true
    fi
    rm -f "$TMP_STATUS"
    if [ -n "$ROLLBACK_DIR" ] && [ "$KEEP_ROLLBACK" -eq 0 ]; then
        rm -rf "$ROLLBACK_DIR"
    fi
    # Чужой lock снимать нельзя.
    if [ "$LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$SCRIPT_LOCK"
    fi
    return "$_rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP


snapshot_file() {
    _sf_path="$1"
    _sf_name="$2"
    [ -n "$ROLLBACK_DIR" ] || return 1
    if [ -e "$_sf_path" ]; then
        cp -p "$_sf_path" "$ROLLBACK_DIR/$_sf_name" 2>/dev/null || return 1
        printf '1\n' > "$ROLLBACK_DIR/$_sf_name.exists"
    else
        printf '0\n' > "$ROLLBACK_DIR/$_sf_name.exists"
    fi
    return 0
}

restore_file() {
    _rf_path="$1"
    _rf_name="$2"
    _rf_exists="$(cat "$ROLLBACK_DIR/$_rf_name.exists" 2>/dev/null || true)"
    # A missing marker means the snapshot transaction was incomplete. Never
    # interpret that as "file did not exist": deleting a live config here
    # would turn a partial snapshot failure into data loss.
    [ "$_rf_exists" = "0" ] || [ "$_rf_exists" = "1" ] || return 1
    if [ "$_rf_exists" = "1" ]; then
        _rf_tmp="${_rf_path}.rollback.$$"
        cp -p "$ROLLBACK_DIR/$_rf_name" "$_rf_tmp" 2>/dev/null || return 1
        mv -f "$_rf_tmp" "$_rf_path" 2>/dev/null || {
            rm -f "$_rf_tmp"
            return 1
        }
    else
        rm -f "$_rf_path" 2>/dev/null || return 1
    fi
    return 0
}

rollback_runtime_files() {
    _rrf_ok=1
    restore_file /opt/etc/dnsmasq.conf dnsmasq.conf || _rrf_ok=0
    restore_file /opt/etc/unblock.dnsmasq unblock.dnsmasq || _rrf_ok=0
    restore_file /opt/etc/unblock.dnsmasq.cidr unblock.dnsmasq.cidr || _rrf_ok=0
    restore_file /opt/etc/hosts hosts || _rrf_ok=0
    restore_file "$DNS_HEALTH_LOG" dns_health.log || _rrf_ok=0
    # DNS generation also changes this live set before the ordinary swaps.
    ipset create unblockdns hash:net family inet hashsize 1024 maxelem 65536 -exist 2>/dev/null || _rrf_ok=0
    ipset flush unblockdns 2>/dev/null || _rrf_ok=0
    if [ -s "$ROLLBACK_DIR/unblockdns.save" ]; then
        ipset restore -exist < "$ROLLBACK_DIR/unblockdns.save" 2>/dev/null || _rrf_ok=0
    fi
    [ "$_rrf_ok" -eq 1 ]
}
discard_staging() {
    for _ds in $STATIC_SETS $VPN_SETS; do
        upd_selected "$_ds" || continue
        ipset flush "${_ds}_new" 2>/dev/null || true
        ipset destroy "${_ds}_new" 2>/dev/null || true
    done
}

reapply_runtime_after_rollback() {
    _rar_ok=1
    if [ "$DNSMASQ_RESTARTED" -eq 1 ] && [ -x /opt/etc/init.d/S56dnsmasq ]; then
        /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1 || _rar_ok=0
    fi
    if [ "$NETFILTER_APPLIED" -eq 1 ] \
        && [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        for _rar_table in nat filter; do
            if ! type=iptable table="$_rar_table" \
                /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1; then
                _rar_ok=0
            fi
        done
    fi
    [ "$_rar_ok" -eq 1 ]
}

rollback_update() {
    _fu_msg="$1"
    TRANSACTION_DONE=1
    _fu_ok=1
    [ "$COMMIT_ROLLBACK_FAILED" -eq 0 ] || _fu_ok=0
    if [ -n "$COMMITTED_SETS" ]; then
        rollback_committed_sets || _fu_ok=0
    fi
    rollback_runtime_files || _fu_ok=0
    reapply_runtime_after_rollback || _fu_ok=0
    if [ "$_fu_ok" -eq 1 ]; then
        discard_staging
        write_status "error" "$_fu_msg"
    else
        KEEP_ROLLBACK=1
        write_status "rollback_failed" \
            "$_fu_msg; откат частичный или не подтверждён: снапшот сохранён в ${ROLLBACK_DIR}; нужна ручная проверка или повторный деплой"
    fi
    return 0
}

fail_update() {
    rollback_update "$1"
    exit 1
}

lock_owner_live() {
    if [ ! -f "$SCRIPT_LOCK/pid" ]; then
        _lol_mtime="$(stat -c %Y "$SCRIPT_LOCK" 2>/dev/null || echo 0)"
        _lol_now="$(date +%s 2>/dev/null || echo 0)"
        case "$_lol_mtime:$_lol_now" in
            *[!0-9:]*|0:*) return 1 ;;
        esac
        [ $((_lol_now - _lol_mtime)) -lt 10 ] && return 0
        return 1
    fi
    _lol_pid="$(cat "$SCRIPT_LOCK/pid" 2>/dev/null || true)"
    _lol_saved="$(cat "$SCRIPT_LOCK/start" 2>/dev/null || true)"
    case "$_lol_pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$_lol_pid" 2>/dev/null || return 1
    if [ -n "$_lol_saved" ] && [ -r "/proc/$_lol_pid/stat" ]; then
        _lol_now="$(awk '{print $22}' "/proc/$_lol_pid/stat" 2>/dev/null || true)"
        [ -n "$_lol_now" ] && [ "$_lol_now" = "$_lol_saved" ] || return 1
    fi
    return 0
}

TRIES=0
while ! mkdir "$SCRIPT_LOCK" 2>/dev/null; do
    if ! lock_owner_live; then
        rm -rf "$SCRIPT_LOCK"
        continue
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
awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$SCRIPT_LOCK/start" || true
# Child scripts use the same lock and DNS decision. They must not acquire
# a nested lock or reload dnsmasq halfway through this transaction.
export KEENZOO_LOCK_DIR="$SCRIPT_LOCK"
export KEENZOO_UPDATE_LOCK_HELD=1
export KEENZOO_USE_DNS_SNAPSHOT=1
export KEENZOO_SKIP_DNSMASQ_RELOAD=1
write_status "running" "start"

# Snapshot all files touched by the generator before the transaction begins.
# They are temporary rollback data only; no new persistent state file is made.
ROLLBACK_DIR="$(mktemp -d /tmp/unblock_update.rollback.XXXXXX)" || {
    write_status "error" "rollback snapshot dir"
    exit 1
}
chmod 700 "$ROLLBACK_DIR" 2>/dev/null || true
snapshot_file /opt/etc/dnsmasq.conf dnsmasq.conf || { write_status "error" "snapshot dnsmasq.conf"; exit 1; }
snapshot_file /opt/etc/unblock.dnsmasq unblock.dnsmasq || { write_status "error" "snapshot unblock.dnsmasq"; exit 1; }
snapshot_file /opt/etc/unblock.dnsmasq.cidr unblock.dnsmasq.cidr || { write_status "error" "snapshot unblock.dnsmasq.cidr"; exit 1; }
snapshot_file /opt/etc/hosts hosts || { write_status "error" "snapshot hosts"; exit 1; }
snapshot_file "$DNS_HEALTH_LOG" dns_health.log || { write_status "error" "snapshot DNS health"; exit 1; }
if ipset list -n unblockdns >/dev/null 2>&1; then
    ipset save unblockdns > "$ROLLBACK_DIR/unblockdns.save" || { write_status "error" "snapshot unblockdns"; exit 1; }
fi
SNAPSHOT_READY=1
# The DNS generator can apply netfilter before ipset commits.
NETFILTER_APPLIED=1
# The DNS child now (and previously) reloads the daemon itself. A failure in
# generation/static fill must restore runtime DNS too, not only disk files.
DNSMASQ_RESTARTED=1

# До генерации dnsmasq удаляем оставшееся от старых версий состояние
# запрещённых WAN/Bridge VPN-интерфейсов. Проверка policy table выполняется
# внутри обработчика; валидные client VPN не затрагиваются.
if [ -x /opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh ]; then
    PRUNE_ONLY=1 /opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh \
        >/dev/null 2>&1 || true
fi

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
DNS_STAGE_LOG="$ROLLBACK_DIR/dns-candidate.log"
if ! DNS_HEALTH_LOG="$DNS_STAGE_LOG" KEENZOO_DNS_STAGE=1 \
    KEENZOO_STAGE_CIDR=1 IPSET_SUFFIX="" /opt/bin/unblock_dnsmasq.sh; then
    fail_update "dnsmasq gen"
fi

# Validate the generated file before any ipset swap. A bad managed block
# must never become the next runtime configuration.
if command -v dnsmasq >/dev/null 2>&1 \
    && ! dnsmasq --test -C /opt/etc/dnsmasq.conf >/dev/null 2>&1; then
    fail_update "dnsmasq test"
fi

# ── 2. Наполнение теневых наборов ────────────────────────────────────────
# Сначала обрабатываются только обязательные статические списки. VPN-файлы
# не входят в эту транзакцию: ошибка optional VPN не должна отменять commit
# bot.txt/vless.txt.
if ! DNS_HEALTH_LOG="$DNS_STAGE_LOG" KEENZOO_USE_DNS_SNAPSHOT=1 SKIP_VPN=1 IPSET_SUFFIX="_new" \
    /opt/bin/unblock_ipset.sh; then
    fail_update "static ipset fill"
fi

# ── 3. Слияние: новые адреса добавляются к уже накопленным ───────────────
ipset_member_count() {
    _imc_set="$1"
    _imc_dump="$(mktemp /tmp/ipset.count.XXXXXX 2>/dev/null || true)"
    [ -n "$_imc_dump" ] || return 1
    if ! ipset list "$_imc_set" > "$_imc_dump" 2>/dev/null; then
        rm -f "$_imc_dump"
        return 1
    fi
    if ! _imc_count="$(awk '/^Members:/ {inside=1; next} inside && NF {n++} END{print n+0}' \
        "$_imc_dump")"; then
        rm -f "$_imc_dump"
        return 1
    fi
    rm -f "$_imc_dump"
    printf '%s\n' "$_imc_count"
}

rollback_set_swap() {
    _rss_set="$1"
    if ipset swap "$_rss_set" "${_rss_set}_new" 2>/dev/null; then
        logger -t "unblock_update" "rollback swap done: $_rss_set"
        return 0
    fi
    COMMIT_ROLLBACK_FAILED=1
    logger -t "unblock_update" "rollback swap FAILED: $_rss_set" || true
    return 1
}

rollback_committed_sets() {
    _rcs_ok=1
    for _rcs_set in $COMMITTED_SETS; do
        rollback_set_swap "$_rcs_set" || _rcs_ok=0
    done
    [ "$_rcs_ok" -eq 1 ]
}

commit_set() {
    _cs_set="$1"
    upd_selected "$_cs_set" || return 0
    COMMIT_ROLLBACK_FAILED=0

    if ! ipset swap "$_cs_set" "${_cs_set}_new" 2>/dev/null; then
        logger -t "unblock_update" "commit failed: $_cs_set (swap)"
        return 1
    fi

    # The old live set is now preserved untouched in *_new. Every failure
    # after this point must swap it back before returning an error.
    # REPLACE_SETS=1 выставляет обёртка generator._build_wrapper только для
    # пользовательской правки списка (панель/бот, вместе с ONLY_SETS):
    # набор ЗАМЕНЯЕТСЯ свежим содержимым, а не дополняется старым — иначе
    # удалённая из списка запись жила бы в ipset до недельной пересборки.
    # Плановые крон/WAN-прогоны сюда не попадают и сохраняют merge-защиту.
    # Защита от «плохого» прогона и так срабатывает раньше: MIN_RESOLVE_RATIO
    # в unblock_ipset.sh отменяет транзакцию до коммита.
    if [ "${REPLACE_SETS:-0}" = "1" ]; then
        if ! _rp_members="$(ipset_member_count "$_cs_set")"; then
            logger -t "unblock_update" "replace failed: $_cs_set (count)"
            rollback_set_swap "$_cs_set" || true
            return 1
        fi
        logger -t "unblock_update" \
            "replace $_cs_set: members=$_rp_members (старые адреса сброшены)"
        return 0
    fi
    if [ "${REBUILD:-0}" = "1" ]; then
        if ! _rb_have="$(ipset_member_count "$_cs_set")"; then
            rollback_set_swap "$_cs_set" || true
            return 1
        fi
        if ! _rb_prev="$(ipset_member_count "${_cs_set}_new")"; then
            rollback_set_swap "$_cs_set" || true
            return 1
        fi
        _rb_ok=0
        if [ "$_rb_prev" -eq 0 ]; then
            _rb_ok=1
        elif [ "$_rb_have" -gt 0 ] \
            && [ $(( _rb_have * 100 / _rb_prev )) -ge "$REBUILD_MIN_RATIO" ]; then
            _rb_ok=1
        fi
        if [ "$_rb_ok" = "1" ]; then
            logger -t "unblock_update" \
                "rebuild $_cs_set: $_rb_prev -> $_rb_have (накопленное сброшено)"
            return 0
        fi
        logger -t "unblock_update" \
            "rebuild $_cs_set отменён: свежих $_rb_have из $_rb_prev — дополняю"
    fi

    _merge_tmp="$(mktemp /tmp/ipset.merge.XXXXXX 2>/dev/null || true)"
    if [ -z "$_merge_tmp" ]; then
        logger -t "unblock_update" "commit failed: $_cs_set (merge temp)"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    _merge_src="${_merge_tmp}.src"

    if ! ipset list "${_cs_set}_new" > "$_merge_src" 2>/dev/null; then
        logger -t "unblock_update" "commit failed: $_cs_set (old set list)"
        rm -f "$_merge_tmp" "$_merge_src"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    if ! awk -v set="$_cs_set" '
            /^Members:/ { inside = 1; next }
            inside && NF { print "add " set " " $1 " -exist" }
        ' "$_merge_src" > "$_merge_tmp" 2>/dev/null; then
        logger -t "unblock_update" "commit failed: $_cs_set (merge build)"
        rm -f "$_merge_tmp" "$_merge_src"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    if [ -s "$_merge_tmp" ] \
        && ! ipset restore -exist < "$_merge_tmp" 2>/dev/null; then
        logger -t "unblock_update" "merge failed for $_cs_set"
        rm -f "$_merge_tmp" "$_merge_src"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    rm -f "$_merge_tmp" "$_merge_src"

    # Legacy loopback entries are removed only from the new live set. The
    # preserved old set stays byte-for-byte rollback material.
    _cs_dump="$(mktemp /tmp/ipset.loopbacks.XXXXXX 2>/dev/null || true)"
    if [ -z "$_cs_dump" ] || ! ipset list "$_cs_set" > "$_cs_dump" 2>/dev/null; then
        rm -f "${_cs_dump:-}"
        logger -t "unblock_update" "commit validation failed: $_cs_set loopback scan"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    if ! _cs_loopbacks="$(awk '/^Members:/ {inside=1; next} inside && $1 ~ /^127\./ {print $1}' \
        "$_cs_dump")"; then
        rm -f "$_cs_dump"
        logger -t "unblock_update" "commit validation failed: $_cs_set loopback scan"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    rm -f "$_cs_dump"
    for _cs_ip in $_cs_loopbacks; do
        if ! ipset del "$_cs_set" "$_cs_ip" 2>/dev/null; then
            logger -t "unblock_update" "commit failed: $_cs_set (loopback prune)"
            rollback_set_swap "$_cs_set" || true
            return 1
        fi
        logger -t "unblock_update" \
            "prune legacy loopback: $_cs_set $_cs_ip"
    done

    if ! _cs_members="$(ipset_member_count "$_cs_set")"; then
        logger -t "unblock_update" "commit validation failed: $_cs_set cannot be listed"
        rollback_set_swap "$_cs_set" || true
        return 1
    fi
    logger -t "unblock_update" "commit done: $_cs_set members=$_cs_members"
    return 0
}

# Обязательные наборы коммитятся независимо от optional VPN-файлов.
for s in $STATIC_SETS; do
    if ! commit_set "$s"; then
        fail_update "static commit $s"
    fi
    upd_selected "$s" || continue
    COMMITTED_SETS="${COMMITTED_SETS}${COMMITTED_SETS:+ }$s"
done

# Каждый VPN-набор имеет отдельный commit. При ошибке его *_new уничтожается,
# а предыдущий боевой набор сохраняется. В журнале используется формулировка
# optional VPN list failed, а не process_list failed для общей транзакции.
OPTIONAL_VPN_FAILED=""
for s in $VPN_SETS; do
    upd_selected "$s" || continue
    if DNS_HEALTH_LOG="$DNS_STAGE_LOG" ONLY_SETS="$s" OPTIONAL_VPN=1 IPSET_SUFFIX="_new" \
        /opt/bin/unblock_ipset.sh; then
        if commit_set "$s"; then
            COMMITTED_SETS="${COMMITTED_SETS}${COMMITTED_SETS:+ }$s"
        elif [ "$COMMIT_ROLLBACK_FAILED" -eq 1 ]; then
            fail_update "optional VPN commit $s rollback"
        else
            OPTIONAL_VPN_FAILED="${OPTIONAL_VPN_FAILED}${OPTIONAL_VPN_FAILED:+ }$s"
            ipset flush "${s}_new" 2>/dev/null || true
            ipset destroy "${s}_new" 2>/dev/null || true
        fi
    else
        OPTIONAL_VPN_FAILED="${OPTIONAL_VPN_FAILED}${OPTIONAL_VPN_FAILED:+ }$s"
        ipset flush "${s}_new" 2>/dev/null || true
        ipset destroy "${s}_new" 2>/dev/null || true
    fi
    [ -n "$OPTIONAL_VPN_FAILED" ] && \
        logger -t "unblock_update" "optional VPN skipped: $s; static commit already applied"
done

# ── 4. Рестарт dnsmasq и переустановка правил ────────────────────────────
if [ ! -x /opt/etc/init.d/S56dnsmasq ]; then
    fail_update "dnsmasq init missing"
fi
DNSMASQ_RESTARTED=1
if ! /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1; then
    logger -t "unblock_update" "dnsmasq restart failed" || true
    fail_update "dnsmasq restart"
fi
if command -v pidof >/dev/null 2>&1 \
    && ! pidof dnsmasq >/dev/null 2>&1; then
    logger -t "unblock_update" "dnsmasq is not running after restart" || true
    fail_update "dnsmasq not running"
fi

if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
    if ! DNS_HEALTH_LOG="$DNS_STAGE_LOG" type=iptable table=nat /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1; then
        fail_update "netfilter nat"
    fi
    NETFILTER_APPLIED=1
fi

# Не объявляем update успешным, если обязательный ipset отсутствует после
# swap. Это проверяет именно применённое состояние, а не только rc dig.
for s in $STATIC_SETS; do
    upd_selected "$s" || continue
    if ! ipset list -n "$s" >/dev/null 2>&1; then
        fail_update "required ipset missing: $s"
    fi
    if ! _s_members="$(ipset_member_count "$s")"; then
        fail_update "required ipset unreadable: $s"
    fi
    logger -t "unblock_update" "validated required ipset: $s members=$_s_members"
done

# Only a real IPv4 answer through the committed config can publish success.
_upd_domain="$(sed -n -e "s/^[[:space:]]*dns_health_domain[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" \
    -e 's/^[[:space:]]*dns_health_domain[[:space:]]*=[[:space:]]*"\([^"\]*\)".*/\1/p' \
    /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
_upd_domain="${_upd_domain:-example.com}"
if ! dig -4 +short +time=3 +tries=2 "$_upd_domain" A @127.0.0.1 -p 53 2>/dev/null \
    | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    fail_update "dnsmasq client query"
fi
_upd_final="$(grep 'decision=final ' "$DNS_STAGE_LOG" 2>/dev/null | tail -1 || true)"
case "$_upd_final" in
    *' mode=TUNNEL_DNS '*|*' mode=LOCAL_DNSSEC '*|*' mode=DNS_OK_NO_DNSSEC '*) ;;
    *) fail_update "DNS candidate missing or invalid" ;;
esac
_upd_final="$(printf '%s\n' "$_upd_final" | sed 's/ client=staged/ client=ok/')"
mkdir -p "$(dirname "$DNS_HEALTH_LOG")"
# Bounded copy + atomic promotion: readers see either old or committed data.
tail -c 65536 "$DNS_HEALTH_LOG" 2>/dev/null | tail -n 198 > "$ROLLBACK_DIR/dns-publish" || :
printf '\n%s\n' "$_upd_final" >> "$ROLLBACK_DIR/dns-publish"
cp "$ROLLBACK_DIR/dns-publish" "${DNS_HEALTH_LOG}.commit.$$" \
    && mv -f "${DNS_HEALTH_LOG}.commit.$$" "$DNS_HEALTH_LOG" \
    || fail_update "DNS snapshot publish"

TRANSACTION_DONE=1
discard_staging

if [ -n "$OPTIONAL_VPN_FAILED" ]; then
    write_status "done" "ok; optional VPN skipped: $OPTIONAL_VPN_FAILED"
else
    write_status "done" "ok"
fi
exit 0

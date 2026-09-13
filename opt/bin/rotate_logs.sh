#!/bin/sh
# /opt/bin/rotate_logs.sh — ограничение размера журналов проекта.
# Оболочка: BusyBox ash.
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

MAX="${MAX:-524288}"
KEEP="${KEEP:-100}"

rotate() {
    _log="$1"
    [ -f "$_log" ] || return 0

    _sz="$(wc -c < "$_log" 2>/dev/null || echo 0)"
    case "$_sz" in
        ''|*[!0-9]*) return 0 ;;
    esac

    if [ "$_sz" -gt "$MAX" ]; then
        _tmp="${_log}.tmp.$$"
        if tail -n "$KEEP" "$_log" > "$_tmp" 2>/dev/null; then
            mv -f "$_tmp" "$_log"
        else
            rm -f "$_tmp"
        fi
    fi
}

rotate /opt/etc/bot/error.log
rotate /opt/etc/bot/generator.log
rotate /opt/root/KeenSnap/backup.log
# Лог netfilter-хука: пишется при каждом изменении состояния интерфейсов.
rotate /opt/var/log/100-redirect.log
# Лог обновления списков (в /tmp, т.е. в ОЗУ роутера — особенно важно).
rotate /tmp/unblock_update.log

# Логи самого xray могут расти быстрее прочих, если в конфиг попал
# уровень отладки: держим их строже.
MAX=262144 KEEP=50 rotate /opt/etc/xray/error.log
MAX=262144 KEEP=50 rotate /opt/etc/xray/access.log

rm -f /tmp/xray_debug*.log 2>/dev/null || true
rm -f /tmp/xray_client*.log 2>/dev/null || true
rm -f /tmp/xray_test*.log 2>/dev/null || true

exit 0

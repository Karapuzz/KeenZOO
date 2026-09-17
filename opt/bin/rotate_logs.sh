#!/bin/sh
# /opt/bin/rotate_logs.sh — ограничение размера журналов проекта.
# Оболочка: BusyBox ash.
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

MAX="${MAX:-524288}"
KEEP="${KEEP:-100}"

# Rotation rewrites files in place. Serialize it with update/refresh jobs so
# cron cannot race with health-log append or config generation.
LOG_LOCK_DIR="${KEENZOO_LOCK_DIR:-/tmp/unblock_update.lockdir}"
LOG_LOCK_ACQUIRED=0
if [ "${KEENZOO_UPDATE_LOCK_HELD:-0}" != "1" ]; then
    if [ -d "$LOG_LOCK_DIR" ]; then
        _rl_pid="$(cat "$LOG_LOCK_DIR/pid" 2>/dev/null || true)"
        _rl_saved="$(cat "$LOG_LOCK_DIR/start" 2>/dev/null || true)"
        _rl_live=0
        case "$_rl_pid" in
            ''|*[!0-9]*) ;;
            *)
                if kill -0 "$_rl_pid" 2>/dev/null; then
                    _rl_now_start="$(awk '{print $22}' "/proc/$_rl_pid/stat" 2>/dev/null || true)"
                    [ -z "$_rl_saved" ] || [ "$_rl_now_start" = "$_rl_saved" ] && _rl_live=1
                fi
                ;;
        esac
        [ "$_rl_live" -eq 1 ] && exit 0
        _rl_t="$(stat -c %Y "$LOG_LOCK_DIR" 2>/dev/null || echo 0)"
        _rl_now="$(date +%s 2>/dev/null || echo 0)"
        case "$_rl_t" in
            ''|*[!0-9]*|0) exit 0 ;;
        esac
        [ $((_rl_now - _rl_t)) -gt 300 ] || exit 0
        rm -rf "$LOG_LOCK_DIR"
    fi
    mkdir "$LOG_LOCK_DIR" 2>/dev/null || exit 0
    LOG_LOCK_ACQUIRED=1
    printf '%s\n' "$$" > "$LOG_LOCK_DIR/pid"
    awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$LOG_LOCK_DIR/start" || true
fi
cleanup_lock() {
    if [ "$LOG_LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$LOG_LOCK_DIR"
    fi
}
trap cleanup_lock EXIT INT TERM HUP

rotate() {
    _log="$1"
    [ -f "$_log" ] || return 0

    _sz="$(wc -c < "$_log" 2>/dev/null || echo 0)"
    _lines="$(wc -l < "$_log" 2>/dev/null || echo 0)"
    case "$_sz" in
        ''|*[!0-9]*) return 0 ;;
    esac
    case "$_lines" in
        ''|*[!0-9]*) return 0 ;;
    esac
    case "$MAX" in
        ''|*[!0-9]*) return 0 ;;
    esac
    case "$KEEP" in
        ''|*[!0-9]*) return 0 ;;
    esac

    if [ "$_sz" -gt "$MAX" ] || [ "$_lines" -gt "$KEEP" ]; then
        _tmp="${_log}.tmp.$$"
        _bytes="${_tmp}.bytes"
        if tail -n "$KEEP" "$_log" > "$_tmp" 2>/dev/null; then
            # Apply both bounds. tail -n alone is insufficient when a
            # single/last KEEP records exceed MAX bytes.
            _tmp_sz="$(wc -c < "$_tmp" 2>/dev/null || echo 0)"
            case "$_tmp_sz" in
                ''|*[!0-9]*) ;;
                *)
                    if [ "$_tmp_sz" -gt "$MAX" ]; then
                        tail -c "$MAX" "$_tmp" > "$_bytes" 2>/dev/null && mv -f "$_bytes" "$_tmp"
                    fi
                    # Переписываем тот же inode, а не делаем mv. generator/xray
                    # могут держать лог открытым; mv оставил бы старый inode
                    # бесконтрольно расти после ротации.
                    cat "$_tmp" > "$_log" 2>/dev/null || true
                    ;;
            esac
        fi
        rm -f "$_tmp" "$_bytes"
    fi
}

rotate /opt/etc/bot/error.log
rotate /opt/etc/bot/generator.log
rotate /opt/root/KeenSnap/backup.log
# Лог netfilter-хука: пишется при каждом изменении состояния интерфейсов.
rotate /opt/var/log/100-redirect.log
# Hysteria stderr нужен для разбора падений после WAN/reboot; init-скрипт
# также ограничивает его на старте, а cron страхует ротацию между запусками.
MAX=65536 KEEP=200 rotate /opt/var/log/hysteria.log
MAX=65536 KEEP=200 rotate /opt/var/log/trojan.log
# Лог обновления списков (в /tmp, т.е. в ОЗУ роутера — особенно важно).
rotate /tmp/unblock_update.log
# Compact DNS health rankings: at most 131072 bytes and 200 records.
MAX=131072 KEEP=200 rotate /opt/var/log/unblock_dns_health.log
# Вывод обновления бинарников/протоколов также пишется в /tmp и
# перезаписывается при каждом запуске, но ограничиваем его и между
# запусками: зависший или очень подробный update не должен занять ОЗУ.
MAX=262144 KEEP=100 rotate /tmp/proto_update.log

# Логи самого xray могут расти быстрее прочих, если в конфиг попал
# уровень отладки: держим их строже.
MAX=262144 KEEP=50 rotate /opt/etc/xray/error.log
MAX=262144 KEEP=50 rotate /opt/etc/xray/access.log

rm -f /tmp/xray_debug*.log 2>/dev/null || true
rm -f /tmp/xray_client*.log 2>/dev/null || true
rm -f /tmp/xray_test*.log 2>/dev/null || true

exit 0

#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# BEGIN KeenZOO embedded live console
# No external launcher or pipefail is required. The child performs the real
# deploy; the parent mirrors stdout/stderr and preserves the child's exit code.
if [ "${KEENZOO_LIVE_CHILD:-0}" = 1 ]; then
    # Never leak the recursion flag into services started by the installer.
    unset KEENZOO_LIVE_CHILD
else
    _kz_console=0
    case "${1:-}" in
        -install|-repair) _kz_console=1; _kz_archive="${2:-${KEENZOO_ARCHIVE:-}}"; _kz_label="${1#-}" ;;
        *.tar.gz|*.tgz) _kz_console=1; _kz_archive="$1"; _kz_label=install ;;
    esac
    if [ "$_kz_console" = 1 ]; then
        for _kz_tool in tee mktemp date tar; do
            command -v "$_kz_tool" >/dev/null 2>&1 || {
                printf 'ERROR: required command missing: %s\n' "$_kz_tool" >&2
                exit 127
            }
        done
        umask 077
        KZ_CONSOLE_WORK="$(mktemp -d /tmp/keenzoo-console.XXXXXX)" || exit 1
        trap 'rm -rf "$KZ_CONSOLE_WORK"' 0
        KZ_CONSOLE_LOG="/tmp/keenzoo-${_kz_label}-$(date +%Y%m%d-%H%M%S)-$$.log"
        # Refuse an existing path/symlink instead of truncating someone else's file.
        if ! (set -C; : > "$KZ_CONSOLE_LOG"); then
            printf 'ERROR: cannot safely create log: %s\n' "$KZ_CONSOLE_LOG" >&2
            exit 1
        fi
        KZ_CONSOLE_SELF="$0"
        case "$KZ_CONSOLE_SELF" in
            */*) ;;
            *) KZ_CONSOLE_SELF="$(command -v "$KZ_CONSOLE_SELF")" || exit 127 ;;
        esac
        printf 'Live console enabled. Log: %s\n' "$KZ_CONSOLE_LOG"
        if (
            trap - 0
            printf '\n=== KeenZOO hybrid terminal installation ===\n'
            date
            printf 'Mode: %s\nArchive: %s\n' "$_kz_label" "$_kz_archive"
            if [ ! -s "$_kz_archive" ] || [ ! -r "$_kz_archive" ]; then
                printf 'ERROR: archive missing, empty or unreadable: %s\n' "$_kz_archive" >&2
                _kz_child_rc=1
            elif ! tar tzf "$_kz_archive" > "$KZ_CONSOLE_WORK/members"; then
                printf '%s\n' 'ERROR: archive cannot be read. Installer was not started.' >&2
                _kz_child_rc=1
            else
                if command -v sha256sum >/dev/null 2>&1; then
                    sha256sum "$_kz_archive" || true
                fi
                if KEENZOO_LIVE_CHILD=1 /bin/sh "$KZ_CONSOLE_SELF" "$@"; then
                    _kz_child_rc=0
                else
                    _kz_child_rc=$?
                fi
            fi
            if ! printf '%s\n' "$_kz_child_rc" > "$KZ_CONSOLE_WORK/status"; then
                printf '%s\n' 'ERROR: installer exit status could not be recorded.' >&2
                exit 125
            fi
            printf '\nDeploy exit code: %s\nLog: %s\n' "$_kz_child_rc" "$KZ_CONSOLE_LOG"
            exit "$_kz_child_rc"
        ) 2>&1 | tee -a "$KZ_CONSOLE_LOG"; then
            _kz_tee_rc=0
        else
            _kz_tee_rc=$?
        fi
        if [ ! -s "$KZ_CONSOLE_WORK/status" ]; then
            printf 'ERROR: no reliable installer exit status; success is NOT confirmed. Log: %s\n' "$KZ_CONSOLE_LOG" >&2
            exit 125
        fi
        IFS= read -r _kz_final_rc < "$KZ_CONSOLE_WORK/status" || exit 125
        case "$_kz_final_rc" in ''|*[!0-9]*) exit 125 ;; esac
        [ "$_kz_final_rc" -le 255 ] || exit 125
        if [ "$_kz_tee_rc" -ne 0 ]; then
            printf 'ERROR: tee failed (rc=%s); log/console output may be incomplete.\n' "$_kz_tee_rc" >&2
            [ "$_kz_final_rc" -ne 0 ] || exit 74
        fi
        exit "$_kz_final_rc"
    fi
fi
# END KeenZOO embedded live console

# Деплой импортирует bot_config для проверки конфигурации, а это создаёт
# __pycache__ в /opt/etc/bot от имени root — потом он подменял правленый
# модуль. Кэш байткода на USB-накопителе не нужен: модули читаются один
# раз за старт сервиса.
export PYTHONDONTWRITEBYTECODE=1

echo "════════════════════════════════════"
echo "  Разворачивание проекта"
echo "════════════════════════════════════"

ARCHIVE=""
MODE=""
BACKUP_DIR=""
REMOVE_YES=0
XRAY_FILE=""
HY_FILE=""
XRAY_SOURCE="opkg"
XRAY_REPO="XTLS/Xray-core"
HY_REPO="HyNetworks/hysteria"

BINARY_VERIFY_MODE="${BINARY_VERIFY_MODE:-sha256}"
BINARY_GPG_KEYRING="${BINARY_GPG_KEYRING:-}"
XRAY_GPG_SIG_URL="${XRAY_GPG_SIG_URL:-}"
HY_GPG_SIG_URL="${HY_GPG_SIG_URL:-}"

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Конфиг протокола ещё не заполнен ключом?
# Признак — оставшийся плейсхолдер шаблона вида {{server}}/{{address}}
# либо отсутствие/пустота файла. Прежняя проверка искала строку
# SERVER_ADDRESS, которой нет ни в одном шаблоне, поэтому подсказка
# "введите ключ" не показывалась никогда, и вместо неё выводилось
# пугающее "установлен, но не запустился".
needs_key() {
    _cfg="$1"
    [ -s "$_cfg" ] || return 0
    grep -q '{{' "$_cfg" 2>/dev/null && return 0
    grep -qE '"(address|server)"[[:space:]]*:[[:space:]]*""' \
        "$_cfg" 2>/dev/null && return 0
    # A preserved Trojan server config is not the client/nat config generated
    # by this project. It commonly contains ssl.key pointing to a file that
    # does not exist, so trojan -t reports use_private_key_file even though the
    # config will be replaced after the user submits a Trojan client key.
    if [ "$_cfg" = "/opt/etc/trojan/config.json" ] \
        && grep -qE '"run_type"[[:space:]]*:[[:space:]]*"server"' \
            "$_cfg" 2>/dev/null; then
        return 0
    fi
    return 1
}

warn() {
    printf '%s\n' "$*" >&2
}

config_number() {
    _cn_key="$1"
    _cn_default="$2"
    _cn_value="$(sed -n \
        -e "s/^[[:space:]]*${_cn_key}[[:space:]]*=[[:space:]]*'\\([0-9][0-9]*\\)'.*$/\\1/p" \
        -e 's/^[[:space:]]*'"${_cn_key}"'[[:space:]]*=[[:space:]]*"\\([0-9][0-9]*\\)".*/\\1/p' \
        -e "s/^[[:space:]]*${_cn_key}[[:space:]]*=[[:space:]]*\\([0-9][0-9]*\\).*$/\\1/p" \
        /opt/etc/bot/bot_config.py 2>/dev/null | head -n1)"
    case "$_cn_value" in ''|*[!0-9]*) _cn_value="$_cn_default" ;; esac
    printf '%s\n' "$_cn_value"
}

WEB_PORT="$(config_number web_port 8080)"
PORT_SS="$(config_number localportsh 1082)"
PORT_TOR="$(config_number localporttor 9141)"
PORT_VLESS="$(config_number localportvless 10810)"
PORT_TROJAN="$(config_number localporttrojan 10829)"
PORT_HYSTERIA="$(config_number localporthysteria 10830)"

die() {
    warn "$*"
    exit 1
}

# Explicit command modes used by the Telegram handler. The legacy form
# deploy_bypass.sh /path/to/archive.tar.gz remains supported as install.
MODE="${1:-}"
case "$MODE" in
    -install|-repair)
        ARCHIVE="${2:-${KEENZOO_ARCHIVE:-}}"
        ;;
    -backup)
        BACKUP_DIR="${2:-}"
        ;;
    -remove)
        shift
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --backup-dir)
                    [ "$#" -ge 2 ] || die "❌ --backup-dir требует каталог"
                    BACKUP_DIR="$2"
                    shift 2
                    ;;
                --yes)
                    REMOVE_YES=1
                    shift
                    ;;
                *)
                    die "❌ Неизвестный параметр -remove: $1"
                    ;;
            esac
        done
        ;;
    -h|--help)
        cat >&2 <<'EOF'
Использование:
  deploy_bypass.sh -install ARCHIVE
  deploy_bypass.sh -repair ARCHIVE  # установленный проект, без скачиваний
  deploy_bypass.sh -backup DESTINATION_DIR
  deploy_bypass.sh -remove --backup-dir DESTINATION_DIR [--yes]
  deploy_bypass.sh ARCHIVE
EOF
        exit 0
        ;;
    *)
        MODE="-install"
        ARCHIVE="${1:-}"
        ;;
esac

# This lock covers install, backup and removal. It is deliberately different
# from unblock_update.lockdir because install invokes unblock_update itself.
DEPLOY_LOCK_DIR="${KEENZOO_DEPLOY_LOCK_DIR:-/tmp/keenzoo_deploy.lockdir}"
DEPLOY_INSTALL_MARKER="${KEENZOO_DEPLOY_INSTALL_MARKER:-/tmp/keenzoo_installing}"
DEPLOY_LOCK_ACQUIRED=0
DEPLOY_LOCK_STALE=120
EXTRACT_STAGE=""
PRESERVE_STAGE=""
REPAIR_LOCK_ACQUIRED=0
REPAIR_LOCK_DIR=""

lock_owner_live() {
    _lol_dir="$1"
    _lol_pid="$(cat "$_lol_dir/pid" 2>/dev/null || true)"
    _lol_saved="$(cat "$_lol_dir/start" 2>/dev/null || true)"
    case "$_lol_pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$_lol_pid" 2>/dev/null || return 1
    case "$_lol_saved" in ''|*[!0-9]*) return 1 ;; esac
    _lol_now="$(awk '{print $22}' "/proc/$_lol_pid/stat" 2>/dev/null || true)"
    [ -n "$_lol_now" ] && [ "$_lol_now" = "$_lol_saved" ]
}

lock_age() {
    _la_dir="$1"
    _la_mtime="$(stat -c %Y "$_la_dir" 2>/dev/null || echo 0)"
    _la_now="$(date +%s 2>/dev/null || echo 0)"
    case "$_la_mtime:$_la_now" in *[!0-9:]*|0:*) return 1 ;; esac
    [ $((_la_now - _la_mtime)) -ge 0 ] || return 1
    printf '%s\n' $((_la_now - _la_mtime))
}

cleanup_deploy_lock() {
    _cdl_rc=$?
    if [ "$REPAIR_LOCK_ACQUIRED" -eq 1 ]; then rm -rf "$REPAIR_LOCK_DIR"; fi
    [ -n "$EXTRACT_STAGE" ] && rm -rf "$EXTRACT_STAGE"
    [ -n "$PRESERVE_STAGE" ] && rm -rf "$PRESERVE_STAGE"
    if [ "$DEPLOY_LOCK_ACQUIRED" -eq 1 ]; then
        rm -rf "$DEPLOY_LOCK_DIR"
        rm -f "$DEPLOY_INSTALL_MARKER"
    fi
    return "$_cdl_rc"
}
if ! mkdir "$DEPLOY_LOCK_DIR" 2>/dev/null; then
    if lock_owner_live "$DEPLOY_LOCK_DIR"; then
        die "❌ Другая операция deploy уже выполняется"
    fi
    _cdl_age="$(lock_age "$DEPLOY_LOCK_DIR" || true)"
    case "$_cdl_age" in
        ''|*[!0-9]*) die "❌ Невозможно безопасно проверить старый deploy lock" ;;
        *) [ "$_cdl_age" -ge "$DEPLOY_LOCK_STALE" ] || \
            die "❌ Deploy lock ещё свежий, владелец не подтверждён" ;;
    esac
    rm -rf "$DEPLOY_LOCK_DIR"
    mkdir "$DEPLOY_LOCK_DIR" || die "❌ Не удалось получить deploy lock"
fi
DEPLOY_LOCK_ACQUIRED=1
# NDM ifstatechanged hook must not auto-start tunnel protocols while an
# installation is replacing configs. The marker is removed by the EXIT trap.
: > "$DEPLOY_INSTALL_MARKER" 2>/dev/null || true
printf '%s\n' "$$" > "$DEPLOY_LOCK_DIR/pid"
awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$DEPLOY_LOCK_DIR/start" || true
date +%s > "$DEPLOY_LOCK_DIR/ts" 2>/dev/null || true
trap cleanup_deploy_lock EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

remove_managed_file_sections() {
    _rm_file="$1"
    _rm_tmp="${_rm_file}.remove.$$"
    [ -f "$_rm_file" ] || return 0
    awk '
        $0 == "# BEGIN KeenZOO dynamic client interfaces" ||
        $0 == "# BEGIN KeenZOO dynamic listen addresses" ||
        $0 == "# BEGIN KeenZOO dynamic local domain" ||
        $0 == "# BEGIN KeenZOO managed DNS upstreams" ||
        $0 == "# --- KeenZOO pinned (не редактировать вручную) ---" ||
        $0 == "# --- KeenZOO NDM bootstrap (управляется проектом) ---" { skip=1; next }
        $0 == "# END KeenZOO dynamic client interfaces" ||
        $0 == "# END KeenZOO dynamic listen addresses" ||
        $0 == "# END KeenZOO dynamic local domain" ||
        $0 == "# END KeenZOO managed DNS upstreams" ||
        $0 == "# --- end KeenZOO pinned ---" ||
        $0 == "# --- end KeenZOO NDM bootstrap ---" { skip=0; next }
        /^conf-file=\/opt\/etc\/unblock\.dnsmasq([[:space:]]|$)/ { next }
        !skip { print }
    ' "$_rm_file" > "$_rm_tmp" 2>/dev/null || {
        rm -f "$_rm_tmp"
        return 1
    }
    chmod 0644 "$_rm_tmp" 2>/dev/null || {
        rm -f "$_rm_tmp"
        return 1
    }
    mv -f "$_rm_tmp" "$_rm_file" 2>/dev/null || {
        rm -f "$_rm_tmp"
        return 1
    }
}

purge_project_policy_tables() {
    _rpt_ok=1
    for _rpt_file in /opt/etc/unblock/vpn-*.txt; do
        [ -f "$_rpt_file" ] || continue
        _rpt_base="$(basename "$_rpt_file" .txt)"
        _rpt_if="${_rpt_base##*-}"
        _rpt_name="$(printf '%s' "$_rpt_if" | tr '[:upper:]' '[:lower:]')"
        _rpt_id="$(grep -w "$_rpt_name" /opt/etc/iproute2/rt_tables 2>/dev/null \
            | awk '{print $1}' | head -1 || true)"
        [ -n "$_rpt_id" ] || continue
        _rpt_ipt="$(command -v iptables 2>/dev/null || true)"
        _rpt_set="unblock${_rpt_base}"
        if [ -n "$_rpt_ipt" ]; then
            for _rpt_proto in tcp udp; do
                while "$_rpt_ipt" -w -t mangle -D PREROUTING \
                    -p "$_rpt_proto" -m set --match-set "$_rpt_set" dst \
                    -j MARK --set-mark "0xd$_rpt_id" \
                    >/dev/null 2>&1; do :; done
            done
            while "$_rpt_ipt" -w -t mangle -D PREROUTING \
                -m conntrack --ctstate NEW \
                -m set --match-set "$_rpt_set" dst \
                -j CONNMARK --set-mark "0xd$_rpt_id" \
                >/dev/null 2>&1; do :; done
        fi
        ip -4 rule del from all table "$_rpt_id" priority 1778 >/dev/null 2>&1 || true
        ip -4 rule del fwmark "0xd$_rpt_id" lookup "$_rpt_id" \
            priority 1778 >/dev/null 2>&1 || true
        ip -4 route flush table "$_rpt_id" >/dev/null 2>&1 || true
        ipset flush "$_rpt_set" >/dev/null 2>&1 || true
        ipset destroy "${_rpt_set}_new" >/dev/null 2>&1 || true
        ipset destroy "$_rpt_set" >/dev/null 2>&1 || true
        _rpt_tmp="/opt/etc/iproute2/rt_tables.remove.$$"
        awk -v n="$_rpt_name" '$2 != n' /opt/etc/iproute2/rt_tables > "$_rpt_tmp" \
            2>/dev/null && mv -f "$_rpt_tmp" /opt/etc/iproute2/rt_tables \
            || { rm -f "$_rpt_tmp"; _rpt_ok=0; }
    done
    [ -f /opt/etc/iproute2/rt_tables ] || {
        [ "$_rpt_ok" -eq 1 ] && return 0
        return 1
    }
    [ "$_rpt_ok" -eq 1 ] && return 0
    return 1
}

verify_project_removed() {
    _vpr_ok=1
    for _vpr_s in unblocksh unblocktor unblockvless unblocktroj unblockhysteria unblockrouter unblockdns; do
        if command -v ipset >/dev/null 2>&1 \
            && ipset list -n "$_vpr_s" >/dev/null 2>&1; then
            warn "⚠️ Остался ipset $_vpr_s"
            _vpr_ok=0
        fi
    done
    if command -v iptables-save >/dev/null 2>&1; then
        if iptables-save 2>/dev/null | grep -Eq \
            'unblock(sh|tor|vless|troj|hysteria|router|dns)|TPROXY|priority 1770'; then
            warn "⚠️ В iptables остались project rules"
            _vpr_ok=0
        fi
    fi
    if command -v ip >/dev/null 2>&1; then
        ip -4 rule show 2>/dev/null | grep -Eq '1770|lookup 100' && {
            warn "⚠️ Осталось TPROXY policy routing rule"
            _vpr_ok=0
        }
        ip -4 route show table 100 2>/dev/null | grep -q . && {
            warn "⚠️ Остался TPROXY route"
            _vpr_ok=0
        }
    fi
    # Проверяем ТОЛЬКО точные управляемые маркеры (те же, что удаляет
    # remove_managed_file_sections): якорь ^ и подстрока конфиг-директивы
    # с границей поля. Поставляемый проектом комментарий
    # «# Закреплённые адреса прокси-серверов (секция KeenZOO pinned).»
    # в dnsmasq.conf не является managed-секцией и не должен давать
    # ложный post-remove verification failed после корректной очистки.
    if grep -Eq '^# BEGIN KeenZOO|^# END KeenZOO|^# --- KeenZOO (pinned|NDM bootstrap)|^# --- end KeenZOO (pinned|NDM bootstrap)|^conf-file=/opt/etc/unblock\.dnsmasq([[:space:]]|$)' \
        /opt/etc/hosts /opt/etc/dnsmasq.conf 2>/dev/null; then
        warn "⚠️ В конфигурации остались managed sections"
        _vpr_ok=0
    fi
    for _vpr_proc in xray trojan hysteria tor ss-redir; do
        for _vpr_d in /proc/[0-9]*; do
            _vpr_argv0="$(cat "$_vpr_d/cmdline" 2>/dev/null \
                | tr '\0' '\n' | head -1)"
            if [ "${_vpr_argv0##*/}" = "$_vpr_proc" ]; then
                warn "⚠️ После remove остался процесс $_vpr_proc"
                _vpr_ok=0
            fi
        done
    done
    [ "$_vpr_ok" -eq 1 ] && return 0
    return 1
}

remove_project() {
    [ -n "$BACKUP_DIR" ] || die "❌ Для -remove требуется --backup-dir"
    case "$BACKUP_DIR" in
        /*) ;;
        *) die "❌ --backup-dir должен быть абсолютным путём" ;;
    esac
    case "$BACKUP_DIR" in
        /|/etc|/opt/etc|/proc|/sys|/dev)
            die "❌ Небезопасный каталог backup: $BACKUP_DIR"
            ;;
    esac
    mkdir -p "$BACKUP_DIR" || die "❌ Не удалось создать каталог backup: $BACKUP_DIR"

    if ! BACKUP_DIR="$BACKUP_DIR" /opt/bin/backup_project.sh; then
        die "❌ Backup перед удалением не создан; удаление отменено"
    fi

    if [ "$REMOVE_YES" -ne 1 ] && [ -t 0 ]; then
        printf 'Удалить автозапуск KeenZOO и остановить сервисы? [y/N]: '
        read -r _rm_answer || _rm_answer=""
        case "$_rm_answer" in
            y|Y|yes|YES|да|Да) ;;
            *) echo "Удаление отменено"; return 0 ;;
        esac
    elif [ "$REMOVE_YES" -ne 1 ]; then
        die "❌ Неинтерактивный -remove требует --yes"
    fi

    mkdir -p /opt/etc/unblock || return 1
    : > /opt/etc/unblock/.disabled || return 1

    for _rm_svc in \
        S99telegram_bot S99generator S99unblock \
        S24xray S22trojan S57hysteria S65shadowsocks S35tor
    do
        if [ -x "/opt/etc/init.d/$_rm_svc" ]; then
            "/opt/etc/init.d/$_rm_svc" stop >/dev/null 2>&1 || true
        fi
    done

    # Purge while the hook still exists. The hook is invoked in explicit
    # removal mode and does not inspect ENABLED/process state.
    _rm_purge_ok=1
    if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
        for _rm_table in nat filter; do
            if ! PURGE_PROJECT=1 KEENZOO_UPDATE_LOCK_HELD=0 \
                type=iptable table="$_rm_table" \
                /opt/etc/ndm/netfilter.d/100-redirect.sh \
                >/dev/null 2>&1; then
                warn "⚠️ Не удалось очистить netfilter table=$_rm_table"
                _rm_purge_ok=0
            fi
        done
        if ! PURGE_PROJECT=1 type=ip6tables table=filter \
            /opt/etc/ndm/netfilter.d/100-redirect.sh \
            >/dev/null 2>&1; then
            warn "⚠️ Не удалось очистить IPv6 filter rules"
            _rm_purge_ok=0
        fi
    fi

    purge_project_policy_tables || _rm_purge_ok=0
    remove_managed_file_sections /opt/etc/dnsmasq.conf || _rm_purge_ok=0
    remove_managed_file_sections /opt/etc/hosts || _rm_purge_ok=0
    rm -f /opt/etc/unblock.dnsmasq /opt/etc/unblock.dnsmasq.cidr

    # Disable every project service, not only the bot/panel hooks. This keeps
    # protocol init scripts from resurrecting the project after reboot while
    # preserving configs and user lists for the backup.
    for _rm_init in \
        /opt/etc/init.d/S99telegram_bot /opt/etc/init.d/S99generator \
        /opt/etc/init.d/S99unblock /opt/etc/init.d/S24xray \
        /opt/etc/init.d/S22trojan /opt/etc/init.d/S57hysteria \
        /opt/etc/init.d/S65shadowsocks /opt/etc/init.d/S35tor; do
        [ -f "$_rm_init" ] || continue
        if grep -qE '^[[:space:]]*ENABLED=' "$_rm_init"; then
            sed -i 's/^[[:space:]]*ENABLED=.*/ENABLED=no/' "$_rm_init"
        else
            sed -i '2i ENABLED=no' "$_rm_init"
        fi
    done

    if ! verify_project_removed; then
        _rm_purge_ok=0
    fi
    [ "$_rm_purge_ok" -eq 1 ] || \
        die "❌ Удаление остановлено: post-remove verification failed"

    echo "✅ Проект отключён без удаления пользовательских данных"
    echo "   Конфигурации и списки сохранены"
    echo "   Backup: $BACKUP_DIR"
}

# Offline repair of an ALREADY INSTALLED project. No package downloads,
# binary/config replacement, DNSOverride changes or protocol restarts.
repair_dns_ready() {
    command -v dig >/dev/null 2>&1 || return 1
    dig -4 +short +time=3 +tries=2 example.com A @127.0.0.1 -p 53 2>/dev/null \
        | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}

repair_restore_code() {
    _rrc_ok=0
    for _rrc_rel in $REPAIR_FILES; do
        if [ -f "$REPAIR_BACKUP/$_rrc_rel" ]; then
            cp -p "$REPAIR_BACKUP/$_rrc_rel" "/opt/$_rrc_rel" || _rrc_ok=1
        else
            rm -f "/opt/$_rrc_rel" || _rrc_ok=1
        fi
    done
    return "$_rrc_ok"
}

# Migrate only owned DNS policy/cron settings; never execute credentials.
v4_migrate_settings() {
    python3 - <<'PY_V4_MIGRATE'
import ast, os, pathlib, re, shutil, time
config = pathlib.Path('/opt/etc/bot/bot_config.py')
cron = pathlib.Path('/opt/etc/crontab')
source = config.read_text(encoding='utf-8')
tree = ast.parse(source)
assignments = {}
for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                assignments.setdefault(target.id, []).append(node)
mode = assignments.get('dns_policy_mode', [])
try:
    hybrid = bool(mode and ast.literal_eval(mode[-1].value) == 'hybrid')
except (ValueError, TypeError):
    hybrid = False
values = {'tunnel_protocol_priority': "['hysteria', 'xray', 'trojan']",
          'dns_policy_version': '4', 'dns_policy_mode': "'hybrid'",
          'dns_policy_pool_hours': '[11, 23]', 'dns_policy_recovery_interval': '300'}
# Upgrade from the old 15/300-second policy MUST change existing values, not
# merely append defaults. Subsequent hybrid repairs keep a valid 30..60 min choice.
interval = 3600
if hybrid and assignments.get('dns_policy_interval'):
    interval = ast.literal_eval(assignments['dns_policy_interval'][-1].value)
    if type(interval) is not int or not 1800 <= interval <= 3600:
        raise SystemExit('Hybrid control interval must be 1800..3600; configuration was not changed')
values['dns_policy_interval'] = str(interval)
owned = set(values) | {'dns_policy_pool_interval'}
for node in tree.body:
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in owned:
        raise SystemExit('DNS migration refuses annotated settings; use simple assignments')
lines = source.splitlines(keepends=True)
changes = []
for name in owned:
    nodes = assignments.get(name, [])
    for node in nodes:
        if len(node.targets) != 1:
            raise SystemExit('DNS policy migration refuses chained assignments')
        before = lines[node.lineno-1][:node.col_offset].strip()
        after = lines[node.end_lineno-1][node.end_col_offset:].strip()
        if before or (after and not after.startswith('#')):
            raise SystemExit('DNS migration refuses shared-line statements; settings were not changed')
        # Remove legacy pool interval and earlier duplicate assignments.
        text = name + ' = ' + values[name] + '\n' if name in values and node is nodes[-1] else ''
        changes.append((node.lineno-1, node.end_lineno, text))
for first, end, text in sorted(changes, reverse=True):
    lines[first:end] = [text]
new = ''.join(lines)
for name, value in values.items():
    if name not in assignments:
        new += '\n' + name + ' = ' + value + '\n'
ast.parse(new)
# Preserve unrelated cron jobs, including user run-parts schedules. Remove
# only known KeenZOO DNS/list entries with minute/five-minute cadence.
command = re.compile(r'/opt/(?:etc/init\.d/S99unblock\b|etc/bot/utils\.py\s+--dns-[\w-]+\b|bin/(?:unblock_dnsmasq|unblock_update|unblock_ipset)\.sh\b)')
frequent = {'*', '*/1', '*/5', '0-59/1', '0-59/5'}
opt_base = config.parents[2]  # /opt on the router; fixture root on the stand

def runparts_target(body):
    m = re.search(r'(?:^|[\s/])run-parts[ \t]+(\S+)', body)
    if not m:
        return None
    target = m.group(1).strip("\"'").split(';')[0].split('>')[0].split('<')[0]
    stripped = target.lstrip('/')
    if stripped.startswith('opt/'):
        return opt_base.joinpath(stripped[4:])
    return None

def disable_empty_runparts(line, body):
    # */1 and */5 run-parts entries with an empty/missing directory cost a
    # process spawn every cycle and produce zero work: comment them, keep
    # the original line for easy re-enable. Non-empty dirs are user-owned.
    tpath = runparts_target(body)
    if tpath is None or tpath.name not in ('cron.1min', 'cron.5mins'):
        return line
    try:
        empty = not tpath.is_dir() or not any(tpath.iterdir())
    except OSError:
        empty = False
    if empty:
        if line.lstrip().startswith('#'):
            return line
        return line.replace(line.lstrip(), '# disabled by KeenZOO migration (empty run-parts dir): ' + line.lstrip(), 1)
    print('WARNING: non-empty', tpath.name, '- run-parts entry kept:', line.strip())
    return line

def clean_cron(text):
    result = []
    for line in text.splitlines(keepends=True):
        fields = line.split()
        if not fields or line.lstrip().startswith('#'):
            result.append(line); continue
        body = line.split('#', 1)[0]
        line = disable_empty_runparts(line, body)
        body = line.split('#', 1)[0]
        owned_command = command.search(body)
        if owned_command and any(op in body for op in (';', '&&', '||', '|')):
            print('WARNING: compound cron entry preserved; inspect manually:', line.strip())
            result.append(line); continue
        if owned_command and len(fields) >= 6 and fields[0] in frequent and fields[1] == '*':
            print('Removed frequent KeenZOO cron entry:', line.strip())
            continue
        result.append(line)
    return ''.join(result)
updates = {config: new}
cron_paths = [cron]
spool = pathlib.Path('/opt/var/spool/cron/crontabs')
if spool.is_dir():
    cron_paths += [p for p in spool.iterdir() if p.is_file() and not p.is_symlink()]
for path in cron_paths:
    if path.is_symlink():
        raise SystemExit('Refusing symlinked cron file: ' + str(path))
    text = path.read_text() if path.exists() else ''
    updates[path] = clean_cron(text)
# Ensure canonical KeenZOO scheduled jobs exist (any cron file counts).
# Presence is signature-based; a job on a user-chosen schedule is respected.
KEENZOO_JOBS = [
    (lambda body: 'unblock_update.sh' in body and 'REBUILD=1' not in body,
     '00 06 * * * root /opt/bin/rotate_logs.sh >/dev/null 2>&1; /opt/bin/unblock_update.sh >>/tmp/unblock_update.log 2>&1; /opt/bin/rotate_logs.sh >/dev/null 2>&1'),
    (lambda body: 'unblock_update.sh' in body and 'REBUILD=1' in body,
     '00 03 * * 3 root /opt/bin/rotate_logs.sh >/dev/null 2>&1; REBUILD=1 /opt/bin/unblock_update.sh >>/tmp/unblock_update.log 2>&1; /opt/bin/rotate_logs.sh >/dev/null 2>&1'),
    (lambda body: 'check_updates.sh' in body,
     '0 3 * * * root /opt/bin/check_updates.sh >/dev/null 2>&1'),
    (lambda body: 'rotate_logs.sh' in body and 'unblock_update.sh' not in body and 'check_updates.sh' not in body,
     '30 */6 * * * root /opt/bin/rotate_logs.sh >/dev/null 2>&1'),
]
active_lines = [line for text in updates.values() for line in text.splitlines()
                if line.strip() and not line.strip().startswith('#')]
missing_jobs = [job for present, job in KEENZOO_JOBS
                if not any(present(line) for line in active_lines)]
if missing_jobs:
    base = updates.get(cron, '')
    base = base.rstrip(chr(10)) + (chr(10) if base else '')
    base += '# KeenZOO scheduled jobs (migration):' + chr(10) + chr(10).join(missing_jobs) + chr(10)
    updates[cron] = base
    print('Ensured KeenZOO cron jobs:', len(missing_jobs))

remove = []
for directory in ('/opt/etc/cron.1min', '/opt/etc/cron.5mins'):
    root = pathlib.Path(directory)
    if not root.is_dir():
        continue
    for path in root.iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text()
        except (UnicodeError, OSError):
            continue
        executable = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        if len(executable) == 1 and re.match(r'^(?:exec\s+)?/opt/', executable[0]) and command.search(executable[0]):
            remove.append(path)
        elif command.search(text):
            print('WARNING: custom cron wrapper preserved; inspect manually:', path)
changed = {path: text for path, text in updates.items()
           if not path.exists() or path.read_text() != text}
if changed or remove:
    backup = pathlib.Path('/opt/root/keenzoo-hybrid-settings-' + time.strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid()))
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Build all replacements first. Credentials and cron backups remain private.
    staged = []
    try:
        for path in list(changed) + remove:
            if path.exists():
                dst = backup / path.relative_to(config.parents[2])
                dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copy2(path, dst); os.chmod(dst, 0o600)
        for path, text in changed.items():
            temporary = path.with_name(path.name + '.hybrid.' + str(os.getpid()))
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(text)
            staged.append((temporary, path))
        for temporary, path in staged:
            os.replace(temporary, path)
        for path in remove:
            path.unlink()
            print('Removed simple frequent KeenZOO wrapper:', path)
        # Cronie/crond checks the spool directory mtime for root crontab updates.
        if spool.is_dir():
            os.utime(spool, None)
    finally:
        for temporary, path in staged:
            if temporary.exists():
                temporary.unlink()
    print('DNS hybrid settings backup:', backup)
print('DNS hybrid: idle control=' + str(interval) + 's; pool=11:00/23:00 router local; Primary recovery=300s')
print('DNS policy: Hysteria -> Xray -> Trojan; emergency bootstrap TCP/UDP53 enabled')
PY_V4_MIGRATE
}

repair_installed_project() {
    [ -s "$ARCHIVE" ] || die "❌ Укажите локальный исправленный архив для -repair"
    [ -f /opt/etc/unblock/.disabled ] && die "❌ Проект отключён; -repair не включает его автоматически"
    [ -f /opt/etc/bot/bot_config.py ] && [ ! -L /opt/etc/bot/bot_config.py ] \
        || die "❌ Для repair требуется сохранённый bot_config.py установленного проекта"
    REPAIR_FILES='bin/update_protocols.sh bin/backup_project.sh bin/unblock_dnsmasq.sh bin/unblock_update.sh bin/check_updates.sh bin/deploy_bypass.sh etc/ndm/netfilter.d/100-redirect.sh etc/bot/generator.py etc/bot/utils.py etc/init.d/S99unblock etc/ndm/ifstatechanged.d/100-unblock-vpn.sh bin/unblock_ipset.sh bin/rotate_logs.sh etc/bot/version.md'
    # BusyBox tar normalizes absolute names even in -t output. Include its
    # warnings in the strict allow-list check, otherwise /opt/x looks like opt/x.
    _ri_members="$(tar tzf "$ARCHIVE" 2>&1)" || die "❌ Повреждён архив"
    if printf '%s\n' "$_ri_members" | grep -qvE '^(\./)?opt(/[A-Za-z0-9_.-]+)*/?$' \
        || printf '%s\n' "$_ri_members" | grep -qE '(^|/)\.\.(/|$)'; then
        die "❌ Небезопасные пути в архиве"
    fi
    _ri_types="$(tar tvzf "$ARCHIVE" 2>/dev/null)" || die "❌ Не прочитан архив"
    if printf '%s\n' "$_ri_types" | awk 'NF && substr($1,1,1) !~ /^[-d]$/ {bad=1} END {exit !bad}'; then
        die "❌ Ссылки и специальные файлы в repair-архиве запрещены"
    fi
    EXTRACT_STAGE="$(mktemp -d /tmp/keenzoo.repair.XXXXXX)" || die "❌ Нет места для staging"
    tar xzf "$ARCHIVE" -C "$EXTRACT_STAGE" || die "❌ Распаковка не выполнена"
    for _ri_rel in $REPAIR_FILES; do
        [ -f "$EXTRACT_STAGE/opt/$_ri_rel" ] && [ ! -L "$EXTRACT_STAGE/opt/$_ri_rel" ] \
            || die "❌ В архиве нет $_ri_rel"
        [ ! -L "/opt/$_ri_rel" ] && { [ ! -e "/opt/$_ri_rel" ] || [ -f "/opt/$_ri_rel" ]; } \
            || die "❌ Небезопасный целевой файл: /opt/$_ri_rel"
        case "$_ri_rel" in
            *.sh|etc/init.d/*) sh -n "$EXTRACT_STAGE/opt/$_ri_rel" || die "❌ Ошибка shell: $_ri_rel" ;;
            *.py) python3 -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8").read())' \
                "$EXTRACT_STAGE/opt/$_ri_rel" || die "❌ Ошибка Python: $_ri_rel" ;;
        esac
    done
    # A binary update may restart tunnels while DNS is being repaired.
    _ri_proto_lock=/tmp/keenzoo_protocol_update.lockdir
    if [ -d "$_ri_proto_lock" ]; then
        lock_owner_live "$_ri_proto_lock" && die "❌ Выполняется обновление протоколов; дождитесь окончания"
        _ri_age="$(lock_age "$_ri_proto_lock" || true)"
        case "$_ri_age" in ''|*[!0-9]*) die "❌ Не проверен protocol update lock" ;; esac
        [ "$_ri_age" -ge 120 ] || die "❌ Protocol update lock свежий; повторите позднее"
    fi
    # Refuse a busy/live or newly-created mutex; never kill an update worker.
    REPAIR_LOCK_DIR="${KEENZOO_LOCK_DIR:-/tmp/unblock_update.lockdir}"
    if ! mkdir "$REPAIR_LOCK_DIR" 2>/dev/null; then
        lock_owner_live "$REPAIR_LOCK_DIR" && die "❌ Выполняется обновление; дождитесь его окончания"
        _ri_age="$(lock_age "$REPAIR_LOCK_DIR" || true)"
        case "$_ri_age" in ''|*[!0-9]*) die "❌ Не проверен владелец update lock" ;; esac
        [ "$_ri_age" -ge 120 ] || die "❌ Update lock свежий; повторите позднее"
        rm -rf "$REPAIR_LOCK_DIR"
        mkdir "$REPAIR_LOCK_DIR" || die "❌ Не получена блокировка"
    fi
    REPAIR_LOCK_ACQUIRED=1
    printf '%s\n' "$$" > "$REPAIR_LOCK_DIR/pid"
    awk '{print $22}' "/proc/$$/stat" > "$REPAIR_LOCK_DIR/start"
    REPAIR_BACKUP="/opt/root/keenzoo-repair-$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -p "$REPAIR_BACKUP" || die "❌ Нет места для резервной копии"
    chmod 0700 "$REPAIR_BACKUP" || die "❌ Не защищён каталог резервной копии"
    for _ri_rel in $REPAIR_FILES etc/bot/bot_config.py etc/crontab etc/dnsmasq.conf etc/hosts etc/unblock.dnsmasq etc/unblock.dnsmasq.cidr; do
        [ -f "/opt/$_ri_rel" ] || continue
        mkdir -p "$REPAIR_BACKUP/$(dirname "$_ri_rel")"
        cp -p "/opt/$_ri_rel" "$REPAIR_BACKUP/$_ri_rel" || die "❌ Не создан backup $_ri_rel"
    done
    echo "Backup кода и DNS-файлов (не полный образ роутера): $REPAIR_BACKUP"
    if grep -q 'class DNSPolicyV4' /opt/etc/bot/utils.py 2>/dev/null; then
        python3 /opt/etc/bot/utils.py --dns-stop || die "DNS v4 worker could not stop safely"
    fi
    for _ri_rel in $REPAIR_FILES; do
        mkdir -p "/opt/$(dirname "$_ri_rel")" || die "❌ Не создан каталог $_ri_rel"
        _ri_tmp="/opt/${_ri_rel}.repair.$$"
        _ri_mode=0755
        case "$_ri_rel" in *.py|*.md) _ri_mode=0644 ;; esac
        if ! { cp "$EXTRACT_STAGE/opt/$_ri_rel" "$_ri_tmp" \
            && chmod "$_ri_mode" "$_ri_tmp" && mv -f "$_ri_tmp" "/opt/$_ri_rel"; }; then
            rm -f "$_ri_tmp"
            repair_restore_code || warn "❌ Не весь код восстановлен: $REPAIR_BACKUP"
            die "❌ Запись кода не завершена"
        fi
    done
    v4_migrate_settings || die "DNS v4 settings migration failed"
    echo "✅ Код v4 обновлён; ключи, списки и бинарники сохранены; DNS-настройки мигрированы"
    _ri_ok=1
    # Phase 1 creates a usable DNS baseline, so a later ipset transaction can
    # roll back to THIS baseline rather than to the broken installed snapshot.
    if ! KEENZOO_LOCK_DIR="$REPAIR_LOCK_DIR" KEENZOO_UPDATE_LOCK_HELD=1 \
        DNS_HEALTH_ONLY=1 /opt/bin/unblock_dnsmasq.sh; then
        _ri_ok=0
        warn "❌ DNS health/туннель не восстановлен; см. unblock_dns_health.log"
    fi
    rm -rf "$REPAIR_LOCK_DIR"
    REPAIR_LOCK_ACQUIRED=0
    if [ "$_ri_ok" = 1 ]; then
        if ! /opt/bin/unblock_update.sh; then
            _ri_ok=0
            warn "❌ Не завершено обновление списков; DNS baseline сохраняется через rollback"
        fi
    fi
    # Reload the new Python routes. No proxy daemon is stopped/restarted here.
    if [ -x /opt/etc/init.d/S99generator ]; then
        /opt/etc/init.d/S99generator restart || _ri_ok=0
    fi
    if ! repair_dns_ready; then
        _ri_ok=0
        warn "❌ Нет IPv4 DNS-ответа через 127.0.0.1:53; не перезагружайте роутер"
    fi
    if [ "$_ri_ok" != 1 ]; then
        warn "⚠️ Repair неполный. Исправленный код оставлен для диагностики; настройки не сброшены"
        return 1
    fi
    echo "✅ Repair: DNS отвечает, списки пересобраны, панель перезапущена"
    echo "   Проверьте сайты из LAN и WireGuard до перезагрузки"
}

case "$MODE" in
    -repair)
        # Execute directly (not in an if/! context): ash must keep errexit
        # enabled inside the function for failed backup/filesystem operations.
        repair_installed_project
        exit $?
        ;;
    -backup)
        [ -n "$BACKUP_DIR" ] || die "❌ Для -backup требуется DESTINATION_DIR"
        case "$BACKUP_DIR" in
            /*) ;;
            *) die "❌ DESTINATION_DIR должен быть абсолютным путём" ;;
        esac
        case "$BACKUP_DIR" in
            /|/etc|/opt/etc|/proc|/sys|/dev)
                die "❌ Небезопасный каталог backup: $BACKUP_DIR"
                ;;
        esac
        mkdir -p "$BACKUP_DIR" || die "❌ Не удалось создать каталог backup: $BACKUP_DIR"
        if BACKUP_DIR="$BACKUP_DIR" /opt/bin/backup_project.sh; then
            exit 0
        else
            exit $?
        fi
        ;;
    -remove)
        remove_project
        exit 0
        ;;
esac

if [ -z "$ARCHIVE" ]; then
    echo "Использование:"
    echo "  $0 -install /tmp/bypass_project.tar.gz"
    exit 1
fi

if [ ! -f "$ARCHIVE" ]; then
    die "❌ Не найден: $ARCHIVE"
fi

# Путь приводится к абсолютному сразу: ниже выполняется "cd /" перед
# распаковкой, после чего относительный путь вида "backup.tar.gz" уже
# не разрешается и распаковка срывается.
case "$ARCHIVE" in
    /*) ;;
    *) ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")" ;;
esac

ARCH="$(uname -m)"
KERNEL="$(uname -r | cut -d. -f1-2)"

echo "Архитектура: $ARCH"
echo "Ядро: $(uname -r)"

# ── IPv6: deployment notice ────────────────────────────────────────────────
# The current project has IPv4 ipsets/TPROXY only. A partially disabled
# IPv6 stack can allow AAAA traffic outside the IPv4 policy, so the operator
# must receive an explicit warning and the commands needed to disable IPv6.
# This is deliberately a NOTICE, not a deployment gate: the full project
# deployment must continue so the operator can finish the configuration and
# apply the remaining IPv4 policy.
show_ipv6_notice() {
    _v6_disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)"
    _v6_fail_closed=1
    # all=1 alone is not enough for a strict production gate: default and
    # already-created interfaces must not be able to bring IPv6 back.
    for _v6_file in /proc/sys/net/ipv6/conf/all/disable_ipv6 \
        /proc/sys/net/ipv6/conf/default/disable_ipv6 \
        /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        [ -r "$_v6_file" ] || continue
        _v6_value="$(cat "$_v6_file" 2>/dev/null || echo 0)"
        [ "$_v6_value" = "1" ] || _v6_fail_closed=0
    done

    if [ "$_v6_fail_closed" = "1" ]; then
        echo "ℹ️ IPv6 отключён на уровне kernel sysctl (all/default/interfaces=1)"
        return 0
    fi

    warn "⚠️ IPv6 не находится в fail-closed состоянии (all=$_v6_disabled)"
    warn "   ВНИМАНИЕ: IPv6-трафик не покрывается IPv4-политикой KeenZOO."
    warn "   Развёртывание продолжается полностью; после него отключите IPv6"
    warn "   командами ниже либо настройте отдельную полноценную IPv6-политику."
    warn ""
    warn "   Проверка текущей конфигурации KeeneticOS:"
    warn "     ndmc -c 'show interface'"
    warn "     ndmc -c 'show running-config'"
    warn ""
    warn "   Отключение IPv6 в конфигурации KeeneticOS:"
    warn "   ВАЖНО: команды с <...> ниже — шаблоны; НЕ запускайте их буквально."
    warn "   Сначала замените <WAN_OR_LAN_NAME>/<PPP_OR_VPN_NAME> именами"
    warn "   из вывода \"ndmc -c 'show interface'\"."
    warn "     ndmc -c 'no ipv6 subnet Default'"
    warn "     ndmc -c 'no ipv6 subnet Guest'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> no ipv6 address auto'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> no ipv6 prefix auto'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> no ipv6 name-servers auto'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> no ipv6 force-default'"
    warn "     ndmc -c 'interface <PPP_OR_VPN_NAME> no ipv6cp'"
    warn "     ndmc -c 'system configuration save'"
    warn ""
    warn "   Немедленное отключение IPv6 в kernel до перезагрузки:"
    warn "     sysctl -w net.ipv6.conf.all.disable_ipv6=1"
    warn "     sysctl -w net.ipv6.conf.default.disable_ipv6=1"
    warn '     for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do printf 1 > "$f"; done'
    warn "     killall radvd 2>/dev/null || true"
    warn ""
    warn "   Включение IPv6 обратно:"
    warn "     sysctl -w net.ipv6.conf.default.disable_ipv6=0"
    warn "     sysctl -w net.ipv6.conf.all.disable_ipv6=0"
    warn '     for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do printf 0 > "$f"; done'
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> ipv6 address auto'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> ipv6 prefix auto'"
    warn "     ndmc -c 'interface <WAN_OR_LAN_NAME> ipv6 name-servers auto'"
    warn "     ndmc -c 'interface <PPP_OR_VPN_NAME> ipv6cp'"
    warn "     ndmc -c 'system configuration save'"
    warn ""
    warn "   Проверка после изменения:"
    warn "     cat /proc/sys/net/ipv6/conf/all/disable_ipv6"
    warn "     ip -6 addr"
    warn "     ip -6 route"
    warn "     ps | grep '[r]advd'"
    return 0
}

# IPv6 is intentionally non-blocking: print the notice/commands above, then
# continue with the complete deployment. Any later IPv6 netfilter diagnostic
# remains visible in the final status, while IPv4 installation is not skipped.
show_ipv6_notice || warn "⚠️ Не удалось проверить IPv6; развёртывание продолжается"

# ── Порядок байт ─────────────────────────────────────────────────────────
# На Keenetic `uname -m` возвращает "mips" и для big-endian, и для
# little-endian сборок. Ошибка в определении даёт нерабочий бинарник
# ("Exec format error"), поэтому порядок байт определяется фактически:
# по заголовку ELF (байт 0x05: 1 = LE, 2 = BE), с запасным вариантом
# через /proc/cpuinfo.
detect_endian() {
    _de_probe=""
    for _de_c in /bin/busybox /bin/sh /bin/cat "$0"; do
        if [ -r "$_de_c" ]; then
            _de_probe="$_de_c"
            break
        fi
    done

    if [ -n "$_de_probe" ] && have_cmd od; then
        _de_b="$(dd if="$_de_probe" bs=1 skip=5 count=1 2>/dev/null | od -b | awk 'NR==1 {print $2+0}')"
        case "$_de_b" in
            1) printf 'le\n'; return 0 ;;
            2) printf 'be\n'; return 0 ;;
        esac
    fi

    if grep -qi 'little.endian' /proc/cpuinfo 2>/dev/null; then
        printf 'le\n'; return 0
    fi
    if grep -qi 'big.endian' /proc/cpuinfo 2>/dev/null; then
        printf 'be\n'; return 0
    fi

    # Do not guess the ABI when no probe succeeded.
    printf 'unknown\n'
}

# Проверка ABI с плавающей точкой: Entware для MIPS/ARM собран
# в soft-float, и hard-float бинарник Hysteria на нём падает.
ENTWARE_ARCH=""

case "$ARCH" in
    aarch64|arm64)
        ENTWARE_ARCH="aarch64-k3.10"
        HY_FILE="hysteria-linux-arm64"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm64-v8a.zip"
        ;;
    armv7l|armv7)
        ENTWARE_ARCH="armv7sf-k3.2"
        HY_FILE="hysteria-linux-arm"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v7a.zip"
        ;;
    armv6l|armv6)
        ENTWARE_ARCH="armv5sf-k3.2"
        HY_FILE="hysteria-linux-armv5"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v6.zip"
        ;;
    armv5l|armv5tel|armv5)
        ENTWARE_ARCH="armv5sf-k3.2"
        HY_FILE="hysteria-linux-armv5"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v5.zip"
        ;;
    mips|mipsel|mipsle)
        case "$(detect_endian)" in
            le)
                ENTWARE_ARCH="mipselsf-k3.4"
                HY_FILE="hysteria-linux-mipsle-sf"
                XRAY_SOURCE="github"
                XRAY_FILE="Xray-linux-mips32le.zip"
                ;;
            be)
                ENTWARE_ARCH="mipssf-k3.4"
                HY_FILE=""
                XRAY_SOURCE="opkg"
                XRAY_FILE=""
                echo "ℹ️ MIPS big-endian: Xray из Entware, Hysteria2 недоступна"
                ;;
            *)
                ENTWARE_ARCH=""; HY_FILE=""; XRAY_SOURCE="opkg"; XRAY_FILE=""
                warn "⚠️ MIPS endian неизвестен: только существующий feed Entware"
                ;;
        esac
        ;;
    x86_64|amd64)
        ENTWARE_ARCH="x64-k3.2"
        HY_FILE="hysteria-linux-amd64"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-64.zip"
        ;;
    i386|i486|i586|i686)
        ENTWARE_ARCH="x86-k2.6"
        HY_FILE="hysteria-linux-386"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-32.zip"
        ;;
    *)
        echo "⚠️ Архитектура $ARCH не распознана: бинарники только из opkg"
        ENTWARE_ARCH=""
        HY_FILE=""
        XRAY_SOURCE="opkg"
        XRAY_FILE=""
        ;;
esac

# На старых ядрах свежие сборки Go-бинарников могут не запускаться.
# Скачивание всё равно выполняется, но при неудачном запуске делается
# откат на пакет из Entware — логика отката ниже по скрипту.
case "$KERNEL" in
    2.*|3.0|3.1|3.2)
        echo "ℹ️ Ядро $KERNEL старое: при несовместимости будет откат на opkg"
        ;;
esac

echo "Entware: ${ENTWARE_ARCH:-неизвестно}"
[ -n "$XRAY_FILE" ] && echo "xray: $XRAY_FILE"
[ -n "$HY_FILE" ] && echo "hysteria: $HY_FILE"

DL_CMD=""
WGET_IS_GNU=0

# GNU wget понимает --https-only, BusyBox — нет. Проверяется по справке,
# а не по факту запуска, чтобы не делать лишний сетевой вызов.
detect_wget_flavor() {
    WGET_IS_GNU=0
    if wget --help 2>&1 | grep -q -- '--https-only'; then
        WGET_IS_GNU=1
    fi
}

if have_cmd curl; then
    DL_CMD="curl"
elif have_cmd wget; then
    DL_CMD="wget"
    detect_wget_flavor
fi

# На шаге 3 останавливается dnsmasq, а при включённом "opkg dns-override"
# он ЕДИНСТВЕННЫЙ резолвер роутера. В результате шаги 6-7 падали с
# "curl: (6) Could not resolve host: github.com", хотя интернет был.
# Здесь DNS восстанавливается на время скачивания: сначала пробуем
# поднять dnsmasq, иначе временно прописываем публичные резолверы.
RESOLV_BACKUP=""

# Проверка разрешения имени. nslookup есть в BusyBox, но может быть
# вырезан; тогда пробуем dig (пакет bind-dig) и, в крайнем случае,
# считаем DNS рабочим, если резолвится через сам загрузчик.
dns_ok() {
    # nslookup на некоторых BusyBox умеет использовать локальный resolver
    # даже при пустом /etc/resolv.conf. Для сервисов Entware этого
    # недостаточно: Python/requests читает системный resolver напрямую.
    # Сначала убеждаемся, что nameserver действительно объявлен.
    if ! grep -qE '^[[:space:]]*nameserver[[:space:]]+[^[:space:]]+' \
        /etc/resolv.conf 2>/dev/null; then
        return 1
    fi

    if have_cmd nslookup; then
        nslookup github.com >/dev/null 2>&1 && return 0
        return 1
    fi
    if have_cmd dig; then
        [ -n "$(dig +short +time=3 +tries=1 github.com 2>/dev/null)" ] \
            && return 0
        return 1
    fi
    # Ни одной утилиты — наличие nameserver достаточно для продолжения:
    # проверка будет выполнена сервисом, который использует DNS.
    return 0
}

ensure_dns() {
    # Проверяем именно разрешение имени, а не наличие файла.
    if dns_ok; then
        return 0
    fi

    # 1. Попытка поднять локальный dnsmasq (он же нужен проекту).
    if [ -x /opt/etc/init.d/S56dnsmasq ]; then
        /opt/etc/init.d/S56dnsmasq start >/dev/null 2>&1 || true
        sleep 2
        if dns_ok; then
            return 0
        fi
    fi

    # 2. Временные публичные резолверы. Оригинал сохраняется и
    #    восстанавливается в restore_dns().
    if [ -z "$RESOLV_BACKUP" ] && [ -f /etc/resolv.conf ]; then
        RESOLV_BACKUP="$(mktemp /tmp/resolv.bak.XXXXXX)"
        cat /etc/resolv.conf > "$RESOLV_BACKUP" 2>/dev/null || true
    fi

    {
        echo "nameserver 1.1.1.1"
        echo "nameserver 8.8.8.8"
        echo "nameserver 77.88.8.8"
    } > /etc/resolv.conf 2>/dev/null || true

    dns_ok
}

restore_dns() {
    if [ -n "$RESOLV_BACKUP" ] && [ -f "$RESOLV_BACKUP" ]; then
        cat "$RESOLV_BACKUP" > /etc/resolv.conf 2>/dev/null || true
        rm -f "$RESOLV_BACKUP"
        RESOLV_BACKUP=""
    fi
}

dl_file() {
    _url="$1"
    _out="$2"

    # Загружается только по https, поэтому downgrade на http невозможен
    # и без GNU-опции --https-only.
    case "$_url" in
        https://*) ;;
        *) warn "⚠️ Отклонён не-https URL: $_url"; return 1 ;;
    esac

    # Бинарник hysteria весит ~21 МБ: при общем лимите 180 с на медленном
    # канале (<130 КБ/с) скачивание обрывалось по таймауту и выглядело как
    # "контрольная сумма не пройдена". Ограничиваем не общее время, а
    # ПРОСТОЙ соединения, и делаем повторные попытки.
    # DNS мог быть остановлен вместе с dnsmasq на шаге 3.
    ensure_dns >/dev/null 2>&1 || true

    _try=1
    while [ "$_try" -le 3 ]; do
        if [ "$DL_CMD" = "curl" ]; then
            if curl -fsSL --connect-timeout 20 \
                --speed-time 60 --speed-limit 1024 \
                --retry 2 --retry-delay 3 \
                -o "$_out" "$_url"; then
                return 0
            fi
        elif [ "$DL_CMD" = "wget" ]; then
            # BusyBox wget не поддерживает GNU-опции --https-only и
            # --timeout=N: он завершается с "unrecognized option" ещё до
            # скачивания. У него есть только -T SEC, и это таймаут
            # чтения, а не всей передачи.
            if [ "${WGET_IS_GNU:-0}" = "1" ]; then
                if wget -q --https-only --read-timeout=60 --tries=2 \
                    -O "$_out" "$_url"; then
                    return 0
                fi
            else
                if wget -q -T 60 -O "$_out" "$_url"; then
                    return 0
                fi
            fi
        else
            return 1
        fi

        rm -f "$_out"
        _try=$((_try + 1))
        [ "$_try" -le 3 ] && sleep 3
    done

    return 1
}

sha256_of_file() {
    _file="$1"

    if have_cmd sha256sum; then
        sha256sum "$_file" | awk '{print $1}'
    elif have_cmd openssl; then
        openssl dgst -sha256 "$_file" | awk '{print $NF}'
    else
        return 1
    fi
}

extract_xray_sha256() {
    # Формат .dgst у Xray:
    #   MD5= ...
    #   SHA2-256= fe1ded07...
    #   SHA2-512= ...
    # BusyBox awk не поддерживает gawk-расширение IGNORECASE. Ищем
    # строго SHA2-256, чтобы не принять SHA2-512.
    _dgst_file="$1"
    awk '/^[Ss][Hh][Aa]2?-?256[[:space:]]*=/ {
             gsub(/[[:space:]]/, "", $NF)
             print $NF
             exit
         }' "$_dgst_file"
}

extract_hysteria_sha256() {
    # Формат hashes.txt у Hysteria:
    #   <sha256>  build/hysteria-linux-mipsle-sf
    # Сравниваем basename, так как upstream добавляет каталог build/.
    _hashes_file="$1"
    _asset_name="$2"
    awk -v asset="$_asset_name" '
        {
            n = $NF
            sub(/^.*\//, "", n)
            if (n == asset) {
                print $1
                exit
            }
        }' "$_hashes_file"
}

verify_sha256() {
    _file="$1"
    _expected="$2"

    if ! verify_required; then
        return 0
    fi

    _actual="$(sha256_of_file "$_file" 2>/dev/null || true)"
    if [ -z "$_actual" ]; then
        warn "⚠️ Нет sha256sum/openssl — проверить контрольную сумму невозможно"
        return 1
    fi
    if [ "$_actual" != "$_expected" ]; then
        warn "⚠️ Контрольная сумма не совпала: ожидалось $_expected, получено $_actual"
        return 1
    fi
    return 0
}

# ── Проверка целостности скачиваемых бинарников ──────────────────────────
# BINARY_VERIFY_MODE: sha256 (по умолчанию) | gpg | sha256+gpg | none
# Режим "none" допускается только явной установкой переменной окружения:
# без проверки установка бинарника из сети считается небезопасной.
verify_required() {
    [ "$BINARY_VERIFY_MODE" != "none" ]
}

gpg_required() {
    [ "$BINARY_VERIFY_MODE" = "gpg" ] || [ "$BINARY_VERIFY_MODE" = "sha256+gpg" ]
}

verify_gpg_if_requested() {
    _sig_url="$1"
    _file="$2"
    _name="$3"

    if ! gpg_required; then
        return 0
    fi

    [ -n "$_sig_url" ] || {
        warn "⚠️ GPG включён, но не задан URL подписи для $_name"
        return 1
    }

    [ -n "$BINARY_GPG_KEYRING" ] || {
        warn "⚠️ GPG включён, но не задан BINARY_GPG_KEYRING"
        return 1
    }

    if ! have_cmd gpgv && ! have_cmd gpg; then
        warn "⚠️ GPG включён, но gpg/gpgv не найден"
        return 1
    fi

    # BusyBox mktemp требует, чтобы XXXXXX были в САМОМ конце шаблона:
    # суффикс после них даёт "mktemp: Invalid argument". GNU coreutils
    # такой шаблон принимает, поэтому дефект проявлялся только на роутере.
    _sig_file="$(mktemp "/tmp/${_name}.asc.XXXXXX")"
    if ! dl_file "$_sig_url" "$_sig_file"; then
        rm -f "$_sig_file"
        warn "⚠️ Не удалось скачать GPG-подпись для $_name"
        return 1
    fi

    if have_cmd gpgv; then
        if ! gpgv --keyring "$BINARY_GPG_KEYRING" \
            "$_sig_file" "$_file" >/dev/null 2>&1; then
            rm -f "$_sig_file"
            warn "⚠️ GPG-подпись $_name не прошла проверку"
            return 1
        fi
    else
        if ! gpg --batch --no-default-keyring \
            --keyring "$BINARY_GPG_KEYRING" \
            --verify "$_sig_file" "$_file" >/dev/null 2>&1; then
            rm -f "$_sig_file"
            warn "⚠️ GPG-подпись $_name не прошла проверку"
            return 1
        fi
    fi

    rm -f "$_sig_file"
    return 0
}

# Свежий тег релиза. Использовать /releases/latest НЕЛЬЗЯ: XTLS
# помечает все новые релизы как prerelease, и GitHub отдаёт по "latest"
# застрявшую v26.3.27 (собрана go1.26.1). На MIPS её рантайм падает:
#   futexwakeup addr=... returned -89   (89 = ENOSYS на MIPS)
#   SIGSEGV: segmentation violation
# Сборки от go1.26.5 и новее этой проблемы не имеют — именно поэтому
# вручную поставленная 26.7.28 работала, а установленная скриптом — нет.
# Поэтому берём первый НЕ-draft релиз из общего списка, включая
# prerelease, и качаем по конкретному тегу.
gh_newest_tag() {
    _gnt_repo="$1"
    _gnt_tmp="$(mktemp /tmp/ghtag.XXXXXX)" || return 1
    if dl_file \
        "https://api.github.com/repos/${_gnt_repo}/releases?per_page=10" \
        "$_gnt_tmp" >/dev/null 2>&1
    then
        # Объекты релизов разделяются по "},{", draft-релизы пропускаются.
        tr '{' '\n' < "$_gnt_tmp" \
            | grep '"tag_name"' \
            | grep -v '"draft": *true' \
            | head -1 \
            | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
    rm -f "$_gnt_tmp"
}

# Базовый URL загрузки: конкретный тег, если удалось его узнать, иначе
# прежний /releases/latest как запасной вариант.
gh_dl_base() {
    _gdb_repo="$1"
    _gdb_tag="$(gh_newest_tag "$_gdb_repo" 2>/dev/null || true)"
    if [ -n "$_gdb_tag" ]; then
        printf 'https://github.com/%s/releases/download/%s' \
            "$_gdb_repo" "$_gdb_tag"
    else
        printf 'https://github.com/%s/releases/latest/download' "$_gdb_repo"
    fi
}

download_verified_xray_zip() {
    _asset="$1"
    _zip_file="$2"
    _dgst_file="$3"
    _base="$(gh_dl_base "$XRAY_REPO")"
    _url="${_base}/${_asset}"
    _dgst_url="${_url}.dgst"

    dl_file "$_url" "$_zip_file" || return 1
    dl_file "$_dgst_url" "$_dgst_file" || return 1

    _expected="$(extract_xray_sha256 "$_dgst_file")"
    [ -n "$_expected" ] || return 1

    verify_sha256 "$_zip_file" "$_expected" || return 1
    verify_gpg_if_requested "$XRAY_GPG_SIG_URL" "$_zip_file" "xray-zip" || return 1
    return 0
}

download_verified_hysteria_bin() {
    _asset="$1"
    _bin_file="$2"
    _hashes_file="$3"
    _hy_base="$(gh_dl_base "$HY_REPO")"
    _url="${_hy_base}/${_asset}"
    _hashes_url="${_hy_base}/hashes.txt"

    dl_file "$_url" "$_bin_file" || return 1
    dl_file "$_hashes_url" "$_hashes_file" || return 1

    _expected="$(extract_hysteria_sha256 "$_hashes_file" "$_asset")"
    [ -n "$_expected" ] || return 1

    verify_sha256 "$_bin_file" "$_expected" || return 1
    verify_gpg_if_requested "$HY_GPG_SIG_URL" "$_bin_file" "hysteria-bin" || return 1
    return 0
}

safe_stop_service() {
    _svc="$1"
    if [ -x "/opt/etc/init.d/$_svc" ]; then
        "/opt/etc/init.d/$_svc" stop >/dev/null 2>&1 || true
    fi
}

safe_start_service() {
    _svc="$1"
    [ -x "/opt/etc/init.d/$_svc" ] || {
        warn "⚠️ $_svc: init-скрипт не найден или неисполняемый"
        return 0
    }

    # Не скрывать причину отказа старта. Раньше stderr полностью
    # отбрасывался, поэтому на роутере было видно только "start failed"
    # без ошибки конфигурации или отсутствия прав. Для Trojan заранее
    # показываем результат штатной проверки конфига, если бинарник её
    # поддерживает.
    if [ "$_svc" = "S22trojan" ] && have_cmd trojan \
        && [ -f /opt/etc/trojan/config.json ]; then
        _sss_trojan_log="$(mktemp /tmp/keenzoo.trojan.XXXXXX 2>/dev/null || true)"
        if [ -n "$_sss_trojan_log" ]; then
            if ! trojan -t -c /opt/etc/trojan/config.json \
                >"$_sss_trojan_log" 2>&1; then
                warn "⚠️ S22trojan: trojan -t проверка не прошла"
                sed 's/^/     /' "$_sss_trojan_log" | tail -12 >&2 || true
            fi
            rm -f "$_sss_trojan_log"
        fi
    fi

    # Ошибка отдельного сервиса не должна обрывать весь deploy:
    # итоговая диагностика ниже покажет, что именно не поднялось.
    _sss_log="$(mktemp "/tmp/keenzoo.start.${_svc}.XXXXXX" 2>/dev/null || true)"
    if [ -n "$_sss_log" ]; then
        if ! "/opt/etc/init.d/$_svc" start >"$_sss_log" 2>&1; then
            warn "⚠️ $_svc: start завершился ошибкой"
            # S99generator prints a structured READINESS_REASON before its
            # diagnostic log. Do not tail it away: that was why the user saw
            # only the generic warning instead of the actual failed check.
            if [ "$_svc" = "S99generator" ]; then
                sed 's/^/     /' "$_sss_log" >&2 || true
            else
                sed 's/^/     /' "$_sss_log" | tail -12 >&2 || true
            fi
            rm -f "$_sss_log"
            return 0
        fi
        rm -f "$_sss_log"
    elif ! "/opt/etc/init.d/$_svc" start; then
        warn "⚠️ $_svc: start завершился ошибкой"
        return 0
    fi
    return 0
}

protocol_version() {
    _pv_name="$1"
    _pv_value=""
    case "$_pv_name" in
        ss-redir)
            have_cmd ss-redir && _pv_value="$(ss-redir -h 2>&1 \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
            ;;
        trojan)
            have_cmd trojan && _pv_value="$(trojan --version 2>&1 \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
            ;;
        xray)
            have_cmd xray && _pv_value="$(xray version 2>&1 \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
            ;;
        hysteria)
            have_cmd hysteria && _pv_value="$(hysteria version 2>&1 \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
            ;;
    esac
    [ -n "$_pv_value" ] || _pv_value="не определена"
    printf '%s\n' "$_pv_value"
}

report_protocols_not_started() {
    echo "   Протоколы не запускаются на этапе установки:"
    for _rpn in ss-redir trojan xray hysteria; do
        case "$_rpn" in
            ss-redir) _rpn_cfg=/opt/etc/shadowsocks.json ;;
            trojan) _rpn_cfg=/opt/etc/trojan/config.json ;;
            xray) _rpn_cfg=/opt/etc/xray/config.json ;;
            hysteria) _rpn_cfg=/opt/etc/hysteria/config.json ;;
        esac
        _rpn_version="$(protocol_version "$_rpn")"
        if needs_key "$_rpn_cfg"; then
            echo "     ⏸ $_rpn — установлен, версия $_rpn_version; ключ не задан, не запускается"
        else
            echo "     ⏸ $_rpn — установлен, версия $_rpn_version; конфигурация найдена, не запускается при установке"
        fi
    done
    echo "     ключ не задан — сервис не запускается; добавьте ключ через бота или веб-панель"
}

proc_exact() {
    _pe_name="$1"
    for _pe_d in /proc/[0-9]*; do
        _pe_argv0="$(cat "$_pe_d/cmdline" 2>/dev/null \
            | tr '\0' '\n' | head -1)"
        [ "${_pe_argv0##*/}" = "$_pe_name" ] && return 0
    done
    return 1
}

proc_script() {
    _ps_name="$1"
    _ps_script="$2"
    for _ps_d in /proc/[0-9]*; do
        _ps_cmd="$(cat "$_ps_d/cmdline" 2>/dev/null | tr '\0' ' ')"
        case " $_ps_cmd " in
            *" $_ps_script "*)
                case "$_ps_cmd" in
                    "$_ps_name"\ *|*"/$_ps_name "*) return 0 ;;
                esac
                ;;
        esac
    done
    return 1
}

socket_ready() {
    _sr_port="$1"
    _sr_proto="$2"
    case "$_sr_port" in ''|*[!0-9]*) return 1 ;; esac
    _sr_hex="$(printf '%04X' "$_sr_port" | tr '[:upper:]' '[:lower:]')"
    if [ "$_sr_proto" = "udp" ]; then
        _sr_files="/proc/net/udp /proc/net/udp6"
    else
        _sr_files="/proc/net/tcp /proc/net/tcp6"
    fi
    awk -v p="$_sr_hex" -v udp="$_sr_proto" '
        NR > 1 {
            split($2, a, ":")
            if (toupper(a[2]) == toupper(p) && (udp == "udp" || $4 == "0A")) ok=1
        }
        END { exit !ok }
    ' $_sr_files 2>/dev/null
}

service_ready() {
    _sready="$1"
    case "$_sready" in
        S24xray) proc_exact xray && socket_ready "$PORT_VLESS" tcp ;;
        S22trojan) proc_exact trojan && socket_ready "$PORT_TROJAN" tcp ;;
        S35tor) proc_exact tor && socket_ready "$PORT_TOR" tcp ;;
        S65shadowsocks)
            proc_exact ss-redir && \
                { socket_ready "$PORT_SS" tcp || socket_ready "$PORT_SS" udp; }
            ;;
        S57hysteria)
            proc_exact hysteria && \
                { socket_ready "$PORT_HYSTERIA" tcp || socket_ready "$PORT_HYSTERIA" udp; }
            ;;
        S56dnsmasq)
            proc_exact dnsmasq || return 1
            command -v dig >/dev/null 2>&1 || return 1
            dig +short +time=2 +tries=1 example.com \
                @127.0.0.1 -p 53 2>/dev/null | \
                grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
            ;;
        S99generator)
            proc_script python3 /opt/etc/bot/generator.py \
                || proc_script python /opt/etc/bot/generator.py
            ;;
        *) return 1 ;;
    esac
}

# Transport acceptance is not DNS health. Accept authentication challenges,
# but never label a 404/500/503 application failure as a healthy endpoint.
http_endpoint_ready() {
    _her_path="$1"
    socket_ready "$WEB_PORT" tcp || return 1
    if command -v curl >/dev/null 2>&1; then
        _her_code="$(curl -sS --noproxy '*' --connect-timeout 2 --max-time 5 \
            -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:${WEB_PORT}${_her_path}" 2>/dev/null)" || return 1
    elif command -v wget >/dev/null 2>&1; then
        _her_code="$(wget -S -T 5 -O /dev/null \
            "http://127.0.0.1:${WEB_PORT}${_her_path}" 2>&1 \
            | awk '/HTTP\/[0-9.]+ [0-9]+/ {code=$2} END {print code}')"
    else
        return 1
    fi
    case "$_her_code" in 200|401|403) return 0 ;; *) return 1 ;; esac
}

web_panel_ready() {
    http_endpoint_ready /
}

web_panel_dns_status_ready() {
    http_endpoint_ready /api/dns-status
}

wait_service_ready() {
    _wsr_svc="$1"
    _wsr_n=0
    while [ "$_wsr_n" -lt 15 ]; do
        service_ready "$_wsr_svc" && return 0
        sleep 1
        _wsr_n=$((_wsr_n + 1))
    done
    service_ready "$_wsr_svc"
}

# Модули ядра для UDP: xt_TPROXY даёт цель TPROXY (в отличие от REDIRECT
# сохраняет исходный адрес назначения, без чего UDP-прокси не знает, куда
# слать пакет), xt_socket — сопоставление с уже установленным сокетом.
# Модуль может быть вкомпилирован в ядро — тогда его нет в lsmod, поэтому
# доступность проверяется боем через iptables.
# -w: ждать освобождения блокировки xtables, а не падать с ошибкой,
# если ndm в этот момент правит правила.
# Пакет Entware "iptables" (1.4.21) кладёт /opt/sbin/iptables и содержит
# ТОЛЬКО libxt_CT/libxt_conntrack. Расширений TPROXY, socket и set в нём нет,
# а /opt/sbin стоит в PATH первым — поэтому правила TPROXY и "-m set" молча
# не создавались. Прошивочный iptables Keenetic эти расширения имеет
# (компонент "Модули ядра подсистемы Netfilter").
# Выбирается бинарник, реально умеющий TPROXY и set.
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

kmod_available() {
    _m="$1"

    # 1. Обычный случай: модуль загружен и виден в lsmod.
    #    Имя может содержать дефис или подчёркивание (xt_TPROXY / xt-TPROXY).
    _m_alt="$(printf '%s' "$_m" | tr '_' '-')"
    if lsmod 2>/dev/null \
        | awk -v a="$_m" -v b="$_m_alt" '$1==a || $1==b {found=1} END{exit !found}'; then
        return 0
    fi

    # 2. Модуль вкомпилирован в ядро — в lsmod его нет. Ядро публикует
    #    список доступных целей и совпадений в /proc.
    #    ВАЖНО: для xt_TPROXY наличия в /proc НЕДОСТАТОЧНО. Ядро может
    #    объявлять цель, но отвергать её в реальном правиле вместе с
    #    "-m set" — тогда шаг 2 рапортовал об успехе, а хук писал
    #    "TPROXY add failed: No chain/target/match by that name".
    #    Поэтому для TPROXY проверка в /proc НЕ засчитывается как
    #    окончательная: решает боевая проба ниже (уровень 4).
    case "$_m" in
        xt_TPROXY)
            :
            ;;
        xt_socket)
            grep -qx 'socket' /proc/net/ip_tables_matches 2>/dev/null \
                && return 0
            ;;
        xt_set)
            grep -qx 'set' /proc/net/ip_tables_matches 2>/dev/null \
                && return 0
            ;;
    esac

    # 3. Файл модуля присутствует, но ещё не загружен.
    if [ -d "/lib/modules/$(uname -r)" ]; then
        if find "/lib/modules/$(uname -r)" \
            \( -name "${_m}.ko" -o -name "${_m_alt}.ko" \) 2>/dev/null \
            | grep -q .; then
            return 0
        fi
    fi

    # 4. Последняя проверка — боем, реальным правилом.
    #    ВАЖНО: TPROXY и socket разрешены ядром только в хуке PREROUTING
    #    таблицы mangle. В пользовательской цепочке ядро не может доказать,
    #    что она вызывается только из PREROUTING, и отклоняет правило
    #    ("used from hooks ..., but only usable from PREROUTING") — из-за
    #    этого прежняя проба в отдельной цепочке давала ложное
    #    "недоступен" на роутере, где модули фактически есть.
    #    Поэтому правило вставляется прямо в PREROUTING и сразу удаляется.
    _probe_rc=1
    case "$_m" in
        xt_TPROXY)
            # Проба повторяет БОЕВОЕ правило целиком, включая "-m set":
            # именно эта связка отвергалась ядром, а проба без set
            # проходила и давала ложный "✅ модули доступны".
            _probe_set="KEENZOO_PROBE_$$"
            ipset create "$_probe_set" hash:net family inet \
                -exist >/dev/null 2>&1 || true

            if $IPT -t mangle -I PREROUTING -p udp -d 127.0.0.2 \
                --dport 1 -m set --match-set "$_probe_set" dst \
                -j TPROXY --on-ip 127.0.0.1 --on-port 12345 \
                --tproxy-mark 1/1 >/dev/null 2>&1; then
                _probe_rc=0
                $IPT -t mangle -D PREROUTING -p udp -d 127.0.0.2 \
                    --dport 1 -m set --match-set "$_probe_set" dst \
                    -j TPROXY --on-ip 127.0.0.1 --on-port 12345 \
                    --tproxy-mark 1/1 >/dev/null 2>&1 || true
            fi

            ipset destroy "$_probe_set" >/dev/null 2>&1 || true
            ;;
        xt_socket)
            if $IPT -t mangle -I PREROUTING -p udp -d 127.0.0.2 \
                -m socket -j ACCEPT >/dev/null 2>&1; then
                _probe_rc=0
                $IPT -t mangle -D PREROUTING -p udp -d 127.0.0.2 \
                    -m socket -j ACCEPT >/dev/null 2>&1 || true
            fi
            ;;
        xt_set)
            _probe_rc=0
            ;;
    esac

    return "$_probe_rc"
}

echo ""
echo "⏳ [1/11] Пакеты..."
opkg update >/dev/null 2>&1 || true

# curl предпочтительнее: BusyBox wget во встроенной сборке Keenetic собран
# без поддержки TLS и на https падает с "Segmentation fault", из-за чего
# xray и hysteria не скачивались. Работоспособность проверяется боем.
dl_works() {
    _probe="$(mktemp /tmp/dlprobe.XXXXXX)" || return 1
    if dl_file "https://bin.entware.net/${ENTWARE_ARCH}/Packages.gz" \
        "$_probe" >/dev/null 2>&1 && [ -s "$_probe" ]; then
        rm -f "$_probe"
        return 0
    fi
    rm -f "$_probe"
    return 1
}

# ca-bundle нужен и curl, и wget-ssl: без корневых сертификатов
# проверка TLS-сертификата GitHub не пройдёт.
opkg install ca-bundle ca-certificates >/dev/null 2>&1 || true

if [ -n "$DL_CMD" ] && dl_works; then
    :
else
    _prev="$DL_CMD"
    DL_CMD=""

    opkg install curl >/dev/null 2>&1 || true
    if have_cmd curl; then
        DL_CMD="curl"
        dl_works || DL_CMD=""
    fi

    if [ -z "$DL_CMD" ]; then
        opkg install wget-ssl >/dev/null 2>&1 || true
        if have_cmd wget; then
            DL_CMD="wget"
            detect_wget_flavor
            dl_works || DL_CMD=""
        fi
    fi

    # Ничего не заработало — возвращаем исходный вариант, вдруг
    # недоступен именно пробный хост, а GitHub откроется.
    [ -z "$DL_CMD" ] && DL_CMD="$_prev"
fi

if [ -n "$DL_CMD" ]; then
    echo "   Загрузчик: $DL_CMD ($(command -v "$DL_CMD" 2>/dev/null))"
else
    warn "⚠️ Нет рабочего curl/wget — бинарники с GitHub не скачать"
fi

FAILED=""
# Только пакеты, реально существующие в репозитории Entware.
# flask и pyTelegramBotAPI в opkg НЕ поставляются ни для одной
# архитектуры — они ставятся исключительно через pip (ниже).
for pkg in \
    tor tor-geoip bind-dig cron \
    dnsmasq-full ipset iptables \
    obfs4 webtunnel-client \
    shadowsocks-libev-ss-redir \
    shadowsocks-libev-config \
    xray trojan coreutils-split unzip \
    python3-pip python3-requests \
    python3-setuptools python3-openssl
do
    if ! opkg install "$pkg" >/dev/null 2>&1; then
        FAILED="${FAILED} ${pkg}"
    fi
done

# Python-зависимости панели и бота: только pip.
if ! have_cmd pip3; then
    python3 -m ensurepip >/dev/null 2>&1 || true
fi

if have_cmd pip3 || python3 -m pip --version >/dev/null 2>&1; then
    PIP="pip3"
    have_cmd pip3 || PIP="python3 -m pip"

    if ! python3 -c "import flask" >/dev/null 2>&1; then
        echo "   Установка flask через pip..."
        $PIP install --no-cache-dir flask >/dev/null 2>&1 \
            || $PIP install --no-cache-dir --break-system-packages flask \
                >/dev/null 2>&1 || true
    fi

    if ! python3 -c "import telebot" >/dev/null 2>&1; then
        echo "   Установка pyTelegramBotAPI через pip..."
        # --no-deps обязателен. Свежие pyTelegramBotAPI тянут aiohttp,
        # у которого для mips нет готового wheel: pip пытается собрать
        # его из исходников и падает на "No such file or directory: 'gcc'"
        # (компилятора в Entware нет). При этом aiohttp нужен только для
        # асинхронного режима AsyncTeleBot — проект использует обычный
        # polling, где достаточно requests. Ставим сам пакет без
        # необязательных зависимостей, requests добираем отдельно.
        $PIP install --no-cache-dir --no-deps pyTelegramBotAPI \
            >/dev/null 2>&1 \
            || $PIP install --no-cache-dir --break-system-packages \
                --no-deps pyTelegramBotAPI >/dev/null 2>&1 || true

        # requests — единственная реально необходимая зависимость.
        # Сначала пробуем пакет Entware (готовый бинарник, без сборки).
        if ! python3 -c "import requests" >/dev/null 2>&1; then
            opkg install python3-requests >/dev/null 2>&1 || true
        fi
        if ! python3 -c "import requests" >/dev/null 2>&1; then
            $PIP install --no-cache-dir requests >/dev/null 2>&1 \
                || $PIP install --no-cache-dir --break-system-packages \
                    requests >/dev/null 2>&1 || true
        fi

        # Если --no-deps не помог (старый pip), пробуем обычным способом.
        if ! python3 -c "import telebot" >/dev/null 2>&1; then
            $PIP install --no-cache-dir pyTelegramBotAPI >/dev/null 2>&1 \
                || $PIP install --no-cache-dir --break-system-packages \
                    pyTelegramBotAPI >/dev/null 2>&1 || true
        fi
    fi
else
    FAILED="${FAILED} pip3"
fi

# Итог проверяется по факту импорта, а не по коду возврата установщика.
python3 -c "import flask" >/dev/null 2>&1 \
    || FAILED="${FAILED} flask"
python3 -c "import telebot" >/dev/null 2>&1 \
    || FAILED="${FAILED} pyTelegramBotAPI(telebot)"

if [ -n "$FAILED" ]; then
    echo "⚠️ Нет:${FAILED}"
    case "$FAILED" in
        *flask*|*telebot*|*pip3*)
            warn "   Веб-панель и бот без этих модулей не запустятся."
            warn "   Установите вручную:"
            warn "     opkg install python3-pip"
            warn "     pip3 install flask pyTelegramBotAPI"
            ;;
    esac
else
    echo "✅ Пакеты"
fi

# dnsmasq должен быть собран с поддержкой ipset, иначе обход по доменам
# не работает вовсе: обычная сборка молча игнорирует директивы ipset=.
DNSMASQ_IPSET_OK=1
if dnsmasq --version 2>/dev/null | grep -q 'no-ipset'; then
    DNSMASQ_IPSET_OK=0
    opkg install --force-reinstall dnsmasq-full >/dev/null 2>&1 || true
    if dnsmasq --version 2>/dev/null | grep -q 'no-ipset'; then
        warn "⚠️ dnsmasq собран БЕЗ ipset — обход по доменам работать не будет"
        warn "   Установите вручную: opkg install dnsmasq-full"
    else
        DNSMASQ_IPSET_OK=1
    fi
fi
[ "$DNSMASQ_IPSET_OK" -eq 1 ] && echo "✅ dnsmasq с поддержкой ipset"

echo ""
echo "⏳ [2/11] Модули ядра..."

# Пакет Entware "iptables" перекрывает прошивочный бинарник в PATH, но не
# содержит расширений TPROXY/socket/set — с ним правила перехвата молча не
# создаются.
#
# Прежнее условие требовало, чтобы прошивочный бинарник лежал строго в
# /usr/sbin или /sbin. На части моделей (проверено на KN-2311, mipsel) его
# там нет, удаление пропускалось, и в системе оставался нерабочий пакет
# Entware: правила :53 создавались, а "-m set" и TPROXY — нет. Защита от
# удаления сама блокировала починку.
#
# Теперь решение принимается по ФАКТУ и БЕЗ РИСКА: замена ищется ДО
# удаления. Слепое удаление опасно — на KN-2311 (mipsel) прошивочного
# iptables нет ни в одном каталоге, и пакет Entware там единственный
# рабочий: с ним создаются хотя бы правила :53 и REDIRECT. Удалив его,
# мы оставили бы роутер вообще без iptables.
# IPT_BIN вычисляется в начале скрипта — ДО шага 1, где ставятся пакеты.
# Поэтому здесь он ОБЯЗАТЕЛЬНО пересчитывается: к этому моменту пакет
# iptables уже установлен шагом 1, а в начале его могло не быть вовсе
# (тогда pick_iptables возвращала голое имя "iptables", и все проверки
# расширений падали — ровно это наблюдалось на aarch64 KN-1811).
IPT_BIN="$(pick_iptables)"
IPT="$IPT_BIN -w"

if ! ipt_is_capable "$IPT_BIN"; then
    # Пакет может отсутствовать или быть в битом состоянии (оборванная
    # установка: бинарник есть, libiptext.so не грузится). На KN-2311
    # ручной "opkg install --force-reinstall iptables" сразу всё починил.
    # Ставим/переустанавливаем и пересчитываем выбор.
    echo "   iptables без TPROXY/set — устанавливаю пакет..."
    if opkg list-installed 2>/dev/null | grep -q '^iptables '; then
        opkg install --force-reinstall iptables >/dev/null 2>&1 || true
    else
        opkg install iptables >/dev/null 2>&1 || true
    fi
    hash -r 2>/dev/null || true
    _ipt_re="$(pick_iptables)"
    if ipt_is_capable "$_ipt_re"; then
        IPT_BIN="$_ipt_re"
        IPT="$IPT_BIN -w"
        echo "   ✅ После установки расширения доступны"
    fi
fi

if ! ipt_is_capable "$IPT_BIN"; then
    # Ищем пригодный бинарник ВНЕ /opt (прошивочный).
    _ipt_fw=""
    for _c in /usr/sbin/iptables /sbin/iptables /bin/iptables \
        /usr/bin/iptables /usr/local/sbin/iptables /tmp/sbin/iptables; do
        [ -x "$_c" ] || continue
        if ipt_is_capable "$_c"; then
            _ipt_fw="$_c"
            break
        fi
    done

    if [ -n "$_ipt_fw" ]; then
        # Замена есть — пакет Entware только мешает, перекрывая её в PATH.
        if opkg list-installed 2>/dev/null | grep -q '^iptables '; then
            echo "   Пакет Entware iptables перекрывает прошивочный — удаляю..."
            opkg remove iptables >/dev/null 2>&1 || true
            hash -r 2>/dev/null || true
        fi
        IPT_BIN="$_ipt_fw"
        IPT="$IPT_BIN -w"
        echo "   Прошивочный iptables: $IPT_BIN"
    fi
fi
echo "   iptables: $IPT_BIN"

# Явная диагностика userspace-расширений. Модули ядра (компонент
# "Модули ядра подсистемы Netfilter") дают xt_TPROXY.ko, но правила
# создаёт userspace-библиотека libxt_TPROXY.so из пакета iptables.
# В сборке Entware её нет, поэтому при отсутствии прошивочного
# бинарника перехват молча не работает — предупреждаем сразу.
if ! ipt_has_match "$IPT_BIN" set; then
    warn "⚠️ $IPT_BIN не поддерживает '-m set'"
    warn "   Правила обхода по спискам создать невозможно."
    # Совет "переустановите iptables" здесь бесполезен и вводит в
    # заблуждение: пакет Entware (в т.ч. сборка keenetic 1.4.21-6) несёт
    # только libxt_CT/NOTRACK/conntrack/state — libxt_set.so и
    # libxt_TPROXY.so в нём НЕТ, сколько ни переустанавливай. Расширения
    # даёт userspace-утилита прошивки, которая появляется вместе с
    # компонентом Netfilter. Если её нет на устройстве — обход по
    # ipset невозможен, и об этом надо сказать прямо.
    if opkg list-installed 2>/dev/null | grep -q '^iptables '; then
        warn "   Активен пакет Entware iptables."
        warn "   Отдельных libxt_set.so/libxt_TPROXY.so в нём нет, но"
        warn "   расширения могут быть вкомпилированы в libiptext.so —"
        warn "   проверьте вручную:"
        warn "     $IPT_BIN -m set --help 2>&1 | head -5"
        warn "     $IPT_BIN -j TPROXY --help 2>&1 | head -5"
    fi
    warn "   Прошивочный iptables с расширениями не найден."
    warn "   Установите компонент «Модули ядра подсистемы Netfilter»:"
    warn "     Общие настройки → Обновления и компоненты →"
    warn "     Изменить набор компонентов → применить → перезагрузка."
    warn "   Если компонент уже стоит — модель не предоставляет"
    warn "   userspace-расширений, обход по спискам работать не будет."
elif ! ipt_has_target "$IPT_BIN" TPROXY; then
    warn "⚠️ $IPT_BIN поддерживает '-m set', но не цель TPROXY"
    warn "   TCP-обход будет работать, UDP в туннель — нет."
fi
# Загрузка модулей netfilter.
# На Keenetic модули лежат ПЛОСКО в /lib/modules/<версия>/ и файла
# modules.dep нет (его создаёт depmod, которого в прошивке нет).
# Поэтому modprobe молча не находит модуль: файл xt_TPROXY.ko
# присутствует, но /proc/net/ip_tables_targets пуст, и правила
# TPROXY отвергаются с "No chain/target/match by that name".
# Рабочий путь — insmod с полным путём, соблюдая порядок зависимостей.
load_kmod() {
    _km="$1"

    # Уже загружен?
    if lsmod 2>/dev/null | awk -v m="$_km" '$1==m {f=1} END{exit !f}'
    then
        return 0
    fi

    # Штатный способ (сработает, если modules.dep всё же есть).
    modprobe "$_km" >/dev/null 2>&1 && return 0

    # Ручная загрузка: ищем .ko в дереве модулей текущего ядра.
    _kdir="/lib/modules/$(uname -r)"
    [ -d "$_kdir" ] || return 1

    _kfile="$(find "$_kdir" -name "${_km}.ko" -print 2>/dev/null \
        | head -n1)"
    [ -n "$_kfile" ] || return 1

    insmod "$_kfile" >/dev/null 2>&1 || true

    lsmod 2>/dev/null | awk -v m="$_km" '$1==m {f=1} END{exit !f}'
}

# Зависимости грузятся ПЕРВЫМИ: xt_TPROXY на ядре 4.9 требует
# nf_defrag_ipv4 и nf_tproxy_ipv4, xt_socket — nf_socket_ipv4.
for _dep in nf_defrag_ipv4 nf_tproxy_ipv4 nf_tproxy_core \
    nf_socket_ipv4 ip_set; do
    load_kmod "$_dep" >/dev/null 2>&1 || true
done

for _mod in xt_TPROXY xt_socket xt_set; do
    load_kmod "$_mod" >/dev/null 2>&1 || true
done

KMOD_OK=1
for m in xt_TPROXY xt_socket; do
    kmod_available "$m" || { KMOD_OK=0; warn "⚠️ Модуль $m недоступен"; }
done

if [ "$KMOD_OK" -eq 1 ]; then
    echo "✅ Модули ядра (UDP через туннель доступен)"
else
    warn "   Без них UDP в туннель не пойдёт, TCP продолжит работать."
    warn "   Keenetic: Общие настройки → Обновления и компоненты →"
    warn "   Изменить набор компонентов → «Модули ядра подсистемы"
    warn "   Netfilter» → применить и перезагрузить роутер."
fi

echo ""
echo "⏳ [3/11] Остановка..."
# dnsmasq НЕ останавливается здесь: при включённом "opkg dns-override" он
# единственный резолвер роутера, и без него шаги 6-7 не могут разрешить
# github.com. Он будет перезапущен на шаге 9 после обновления конфига.
for svc in \
    S99telegram_bot S99generator S24xray \
    S65shadowsocks S22trojan \
    S57hysteria S35tor
do
    safe_stop_service "$svc"
done
killall xray >/dev/null 2>&1 || true
killall -9 xray >/dev/null 2>&1 || true
sleep 2
echo "✅ Остановлены"

# ═════════════════════════════════════════════════════════════════════
# Остатки прежних проектов обхода
# ═════════════════════════════════════════════════════════════════════
# Установка часто идёт поверх другого решения (H-wave, xkeen) или поверх
# init-скриптов пакетов Entware. Их файлы не перезаписываются нашими —
# имена разные — и продолжают работать параллельно: второй экземпляр на
# том же порту, чужие правила netfilter поверх наших, дубли в init.d.
#
# Удаляются ТОЛЬКО файлы из явного списка известных конфликтов и только
# с подтверждения. Ничего не опознанного скрипт не трогает. Перед
# удалением делается резервная копия в /opt/root/replaced-<дата>.
LEFTOVER_LIST="
/opt/etc/init.d/S96hysteria
/opt/etc/init.d/S23hysteria
/opt/etc/init.d/S22shadowsocks
/opt/etc/ndm/netfilter.d/002-hwave.sh
/opt/etc/ndm/netfilter.d/002-xkeen.sh
/opt/etc/ndm/ifstatechanged.d/002-hwave.sh
"

# Наши бинарники ставятся в /opt/sbin. Копия в /opt/bin перехватывает
# запуск: в PATH init-скриптов /opt/sbin идёт первым, но чужой проект
# мог прописать собственный PATH либо вызывать бинарник по полному пути.
for _lo_b in xray hysteria; do
    if [ -f "/opt/bin/$_lo_b" ] && [ -f "/opt/sbin/$_lo_b" ]; then
        LEFTOVER_LIST="$LEFTOVER_LIST
/opt/bin/$_lo_b"
    fi
done

_lo_found=""
for _lo_f in $LEFTOVER_LIST; do
    [ -e "$_lo_f" ] || continue
    _lo_found="$_lo_found $_lo_f"
done

if [ -n "$_lo_found" ]; then
    echo ""
    echo "⚠️ Найдены файлы прежних установок:"
    for _lo_f in $_lo_found; do
        echo "     $_lo_f"
    done
    echo "   Они конфликтуют с проектом: дублирующие сервисы на тех же"
    echo "   портах и посторонние правила netfilter."

    _lo_do=0
    if [ "${ASSUME_YES:-0}" = "1" ]; then
        _lo_do=1
        echo "   ASSUME_YES=1 — удаляю без запроса."
    elif [ -t 0 ]; then
        printf '   Удалить их (резервная копия сохранится)? [y/N]: '
        read -r _lo_ans 2>/dev/null || _lo_ans=""
        case "$_lo_ans" in
            y|Y|yes|YES|да|Да) _lo_do=1 ;;
        esac
    else
        # Неинтерактивный запуск: молча удалять чужие файлы нельзя.
        echo "   Неинтерактивный режим — файлы оставлены."
        echo "   Для удаления: ASSUME_YES=1 $0 <архив>"
    fi

    if [ "$_lo_do" = "1" ]; then
        _lo_bak="/opt/root/replaced-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$_lo_bak" 2>/dev/null || true
        for _lo_f in $_lo_found; do
            case "$_lo_f" in
                /opt/etc/init.d/S*)
                    "$_lo_f" stop >/dev/null 2>&1 || true
                    ;;
            esac
            cp -a "$_lo_f" "$_lo_bak/" 2>/dev/null || true
            rm -f "$_lo_f" 2>/dev/null || true
            echo "   ♻️  удалён $_lo_f"
        done
        echo "   Копии сохранены: $_lo_bak"
    else
        echo "   Пропущено. Удалить вручную можно так:"
        for _lo_f in $_lo_found; do
            echo "     rm -f $_lo_f"
        done
    fi
    echo ""
fi

echo ""
echo "⏳ [4/11] Директории..."
mkdir -p \
    /opt/etc/unblock \
    /opt/etc/xray \
    /opt/etc/trojan \
    /opt/etc/hysteria \
    /opt/etc/tor \
    /opt/etc/bot/templates \
    /opt/etc/ndm/netfilter.d \
    /opt/etc/ndm/fs.d \
    /opt/etc/ndm/ifstatechanged.d \
    /opt/etc/iproute2 \
    /opt/bin \
    /opt/sbin \
    /opt/var/run
echo "✅ Директории"

echo ""
echo "⏳ [5/11] Распаковка..."
# Архив разворачивается в корень, поэтому его содержимое проверяется:
# допускаются только пути внутри opt/ без выхода за пределы (../).
if tar tzf "$ARCHIVE" 2>/dev/null | grep -qE '(^/|\.\./)'; then
    die "❌ Архив содержит абсолютные пути или ../ — установка прервана"
fi
# Группировка обязательна: в '\./?(opt/|$)' необязательным был только слэш,
# а сама точка требовалась, поэтому запись "opt/..." не совпадала и любой
# корректный архив отклонялся. Правильно — '(\./)?', где необязательна
# вся последовательность "./".
if tar tzf "$ARCHIVE" 2>&1 | grep -qvE '^(\./)?(opt/|opt$|$)'; then
    die "❌ Архив содержит файлы вне opt/ — установка прервана"
fi

# Архив бэкапа несёт /opt/etc/bot/PLATFORM_INFO.txt с описанием роутера,
# на котором он снят. Бинарники xray/hysteria в бэкап НЕ входят — они
# скачиваются заново под текущую платформу, поэтому перенос между
# архитектурами возможен. Но конфиги могут содержать привязки к прежнему
# железу (имена интерфейсов, адреса), а при смене порядка байт MIPS
# несовпадение особенно коварно: uname -m одинаков для BE и LE.
# Поэтому предупреждаем, но не прерываем установку.
_bk_info="$(tar xzOf "$ARCHIVE" \
    ./opt/etc/bot/PLATFORM_INFO.txt opt/etc/bot/PLATFORM_INFO.txt \
    2>/dev/null | head -20 || true)"
if [ -n "$_bk_info" ]; then
    _bk_arch="$(printf '%s' "$_bk_info" \
        | sed -n 's/^arch=//p' | head -1)"
    _bk_end="$(printf '%s' "$_bk_info" \
        | sed -n 's/^endian=//p' | head -1)"
    _cur_end="$(detect_endian)"
    case "$_cur_end" in
        le) _cur_end="little" ;;
        be) _cur_end="big" ;;
    esac

    if [ -n "$_bk_arch" ] && [ "$_bk_arch" != "$ARCH" ]; then
        warn "⚠️ Архив снят на другой архитектуре: $_bk_arch (сейчас $ARCH)"
        warn "   Бинарники будут скачаны под $ARCH — это штатно."
        warn "   Проверьте конфиги: имена интерфейсов и адреса могли"
        warn "   отличаться на прежнем роутере."
    elif [ -n "$_bk_end" ] && [ "$_bk_end" != "unknown" ] \
        && [ "$_bk_end" != "$_cur_end" ]; then
        warn "⚠️ Архив снят на MIPS $_bk_end-endian, роутер — $_cur_end-endian"
        warn "   uname -m у них совпадает, но сборки несовместимы."
    fi
fi

# Do not extract an untrusted archive directly into /. First inspect member
# types, then extract into a private staging directory. BusyBox tar prints the
# POSIX type in column one: l/h/b/c/p are links or special files. Rejecting
# them before extraction prevents a link member from redirecting later writes.
_TAR_VERBOSE="$(tar tvzf "$ARCHIVE" 2>/dev/null)" || \
    die "❌ Не удалось прочитать список архива"
if printf '%s\n' "$_TAR_VERBOSE" | awk '
    NF && substr($1, 1, 1) ~ /^[lhbcps]$/ { bad=1 }
    END { exit bad ? 0 : 1 }
'; then
    die "❌ Архив содержит symlink/hardlink/device/FIFO — установка прервана"
fi

EXTRACT_STAGE="$(mktemp -d /tmp/keenzoo.extract.XXXXXX)" || \
    die "❌ Не удалось создать staging-каталог"
if ! tar xzf "$ARCHIVE" -C "$EXTRACT_STAGE" >/dev/null 2>&1; then
    die "❌ Ошибка распаковки архива в staging"
fi
[ -d "$EXTRACT_STAGE/opt" ] || \
    die "❌ В staging отсутствует каталог opt"
if find "$EXTRACT_STAGE/opt" -type l -o -type b -o -type c -o -type p \
    | grep -q .; then
    die "❌ Staging содержит специальный файл или ссылку"
fi
# Do not carry archive owner/mode into /opt. The project applies the required
# executable/secret modes in the following deployment steps.
find "$EXTRACT_STAGE/opt" -type d -exec chmod 0755 {} \; 2>/dev/null || \
    die "❌ Не удалось нормализовать режимы каталогов"
find "$EXTRACT_STAGE/opt" -type f -exec chmod 0644 {} \; 2>/dev/null || \
    die "❌ Не удалось нормализовать режимы файлов"
# Keep mutable router state out of the archive copy. In particular, replacing
# dnsmasq.conf here would silently discard the user's ordered
# server=/resource/.../ rules; replacing bot/proxy configs could also discard
# credentials and the DNS pins' source endpoints. A fresh router has no files
# to preserve and receives the archive defaults normally.
PRESERVE_STAGE="$(mktemp -d /tmp/keenzoo.preserve.XXXXXX)" || \
    die "❌ Не удалось создать каталог сохранения настроек"
_preserve_file() {
    _pf_src="$1"
    [ -f "$_pf_src" ] || return 0
    _pf_rel="${_pf_src#/opt/}"
    mkdir -p "$PRESERVE_STAGE/$(dirname "$_pf_rel")" || return 1
    cp -p "$_pf_src" "$PRESERVE_STAGE/$_pf_rel" 2>/dev/null || \
        cp "$_pf_src" "$PRESERVE_STAGE/$_pf_rel" || return 1
}
for _pf in \
    /opt/etc/dnsmasq.conf \
    /opt/etc/crontab \
    /opt/etc/hosts \
    /opt/etc/bot/bot_config.py \
    /opt/etc/xray/config.json \
    /opt/etc/trojan/config.json \
    /opt/etc/hysteria/config.json \
    /opt/etc/shadowsocks.json \
    /opt/etc/tor/torrc \
    /opt/etc/unblock/*.txt \
    /opt/etc/unblock/.router_protocol
 do
    _preserve_file "$_pf" || die "❌ Не удалось сохранить $_pf"
done

    if grep -q 'class DNSPolicyV4' /opt/etc/bot/utils.py 2>/dev/null; then
        python3 /opt/etc/bot/utils.py --dns-stop || die "DNS v4 worker could not stop safely"
    fi
mkdir -p /opt
if ! cp -R "$EXTRACT_STAGE/opt/." /opt/ >/dev/null 2>&1; then
    die "❌ Не удалось установить staged-файлы в /opt"
fi
if ! cp -R "$PRESERVE_STAGE/." /opt/ >/dev/null 2>&1; then
    die "❌ Не удалось восстановить пользовательские настройки"
fi
rm -rf "$EXTRACT_STAGE"
EXTRACT_STAGE=""
rm -rf "$PRESERVE_STAGE"
PRESERVE_STAGE=""
rm -f /opt/etc/unblock/.disabled
echo "✅ Архив проверен и установлен через staging; пользовательские настройки сохранены"

find /opt/bin -name "*.sh" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
find /opt/etc/init.d -name "S*" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
find /opt/etc/ndm -name "*.sh" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

echo ""
# Ранее здесь MIPS принудительно уводился на opkg: считалось, что сборки
# GitHub собраны с GOMIPS=hardfloat и на soft-float Entware не пойдут.
# Это неверно. Заголовки ELF пакета Entware и релиза XTLS совпадают
# (0x50001004, cpic, o32, mips32), обе сборки содержат COP1-инструкции,
# а Go-бинарник статический и с libc Entware не линкуется — конфликта
# ABI, ради которого вводился запрет, не возникает. Проверено на
# Keenetic Hero 4G+ (MT7621A): Xray linux/mipsle работает.
# Совместимость и так проверяется фактически — запуском "$DEST_TMP
# version" ниже, с откатом на opkg при неудаче. Дублировать эту проверку
# запретом по имени архитектуры не нужно.

echo "⏳ [6/11] xray ($XRAY_SOURCE)..."
if [ "$XRAY_SOURCE" = "opkg" ]; then
    opkg install --force-reinstall xray >/dev/null 2>&1 || true
    if xray version >/dev/null 2>&1; then
        echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
    else
        echo "❌ xray из opkg не работает"
    fi
fi

if [ "$XRAY_SOURCE" = "github" ] && [ -n "$XRAY_FILE" ] && [ -n "$DL_CMD" ]; then
    # XXXXXX только в конце шаблона — иначе BusyBox mktemp падает
    # с "Invalid argument" (см. комментарий в verify_gpg_if_requested).
    TMP_ZIP="$(mktemp /tmp/xray.zip.XXXXXX)"
    TMP_DGST="$(mktemp /tmp/xray.dgst.XXXXXX)"
    TMP_DIR="$(mktemp -d /tmp/xray.dir.XXXXXX)"
    DEST_TMP="/opt/sbin/xray.new.$$"

    if download_verified_xray_zip "$XRAY_FILE" "$TMP_ZIP" "$TMP_DGST"; then
        if unzip -o "$TMP_ZIP" xray -d "$TMP_DIR" >/dev/null 2>&1 \
            && [ -f "$TMP_DIR/xray" ]; then
            cp "$TMP_DIR/xray" "$DEST_TMP"
            chmod +x "$DEST_TMP"

            # Причина неудачи ДОЛЖНА быть видна. Раньше вывод полностью
            # подавлялся и любая ошибка (нехватка памяти, отсутствие
            # /opt/sbin, обрезанный при скачивании файл) объявлялась
            # "несовместимостью hardfloat". На KN-2311 это дало ложный
            # диагноз: та же сборка mips32le там работает.
            # "|| true" обязателен: под set -e присваивание из $(...)
            # с ненулевым кодом обрывает ВЕСЬ скрипт (проверено в dash и
            # busybox ash). Код возврата берётся отдельным запуском.
            _xr_err="$("$DEST_TMP" version 2>&1 || true)"
            if "$DEST_TMP" version >/dev/null 2>&1; then
                _xr_rc=0
            else
                _xr_rc=1
            fi
            if [ "$_xr_rc" = "0" ]; then
                mv -f "$DEST_TMP" /opt/sbin/xray
                echo "✅ xray GitHub: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
            else
                echo "⚠️ Сборка GitHub не запустилась (код $_xr_rc):"
                printf '   %s\n' "$(printf '%s' "$_xr_err" | head -3)"
                case "$_xr_err" in
                    *"Illegal instruction"*|*"llegal nstruction"*)
                        echo "   Признак несовместимости набора инструкций."
                        ;;
                    *"not found"*|*"Exec format"*)
                        echo "   Неверная архитектура или битый файл."
                        ;;
                    *"annot allocate"*|*"out of memory"*)
                        echo "   Не хватило памяти — освободите ОЗУ и повторите."
                        ;;
                esac
                echo "   Откат на пакет Entware."
                rm -f "$DEST_TMP"
                opkg install --force-reinstall xray >/dev/null 2>&1 || true
                echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
            fi
        else
            echo "⚠️ Распаковка/верификация, opkg..."
            opkg install --force-reinstall xray >/dev/null 2>&1 || true
        fi
    else
        echo "⚠️ Скачивание/верификация, opkg..."
        opkg install --force-reinstall xray >/dev/null 2>&1 || true
    fi

    rm -rf "$TMP_DIR"
    rm -f "$TMP_ZIP" "$TMP_DGST" "$DEST_TMP"
else
    # Источник уже обработан выше (opkg или soft-float MIPS) —
    # молчим, чтобы не путать лишним предупреждением.
    [ "$XRAY_SOURCE" = "opkg" ] || echo "⚠️ Пропущено"
fi

echo ""
echo "⏳ [7/11] hysteria ($ARCH)..."
if [ -n "$HY_FILE" ] && [ -n "$DL_CMD" ]; then
    # XXXXXX только в конце — совместимость с BusyBox mktemp.
    TMP_BIN="$(mktemp /tmp/hysteria.bin.XXXXXX)"
    TMP_HASHES="$(mktemp /tmp/hysteria.hashes.XXXXXX)"
    DEST_TMP="/opt/sbin/hysteria.new.$$"

    if [ ! -x /opt/sbin/hysteria ]; then
        if download_verified_hysteria_bin "$HY_FILE" "$TMP_BIN" "$TMP_HASHES"; then
            cp "$TMP_BIN" "$DEST_TMP"
            chmod +x "$DEST_TMP"

            # Работоспособность проверяется до установки в /opt/sbin.
            if "$DEST_TMP" version >/dev/null 2>&1; then
                mv -f "$DEST_TMP" /opt/sbin/hysteria
                echo "✅ hysteria: $(hysteria version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
            else
                echo "⚠️ hysteria: бинарник несовместим с платформой"
                rm -f "$DEST_TMP"
            fi
        else
            # Фолбэк: проект H-wave собирает тот же официальный бинарник
            # в виде ipk (проверено: sha256 совпадает с релизом apernet).
            # Пакет несёт собственные S96hysteria, 002-hwave.sh и конфиги,
            # которые конфликтуют с KeenZOO (S57hysteria, 100-redirect.sh),
            # поэтому берём из него ТОЛЬКО бинарник, а служебные файлы
            # пакета удаляем.
            warn "⚠️ hysteria: прямая загрузка не удалась, пробую H-wave..."

            # В релизе H-wave только два пакета: arm64 и mipsle.
            # Значения uname -m перечисляются так же, как в основном
            # case выше: "arm64" и "mipsel"/"mipsle" раньше не
            # распознавались, и фолбэк молча отключался. Для MIPS
            # обязательна проверка порядка байт — пакет только LE.
            HW_VER="2.12.2"
            case "$ARCH" in
                aarch64|arm64)
                    HW_PKG="hysteria_${HW_VER}_arm64.ipk"
                    ;;
                mips|mipsel|mipsle)
                    if [ "$(detect_endian)" = "be" ]; then
                        HW_PKG=""
                    else
                        HW_PKG="hysteria_${HW_VER}_mipsle.ipk"
                    fi
                    ;;
                *)  HW_PKG="" ;;
            esac

            HW_OK=0
            if [ -n "$HW_PKG" ]; then
                TMP_IPK="$(mktemp /tmp/hwave.ipk.XXXXXX)"
                TMP_IDIR="$(mktemp -d /tmp/hwave.dir.XXXXXX)"
                HW_URL="https://github.com/for6to9si/H-wave/releases/download/v${HW_VER}/${HW_PKG}"

                if dl_file "$HW_URL" "$TMP_IPK"; then
                    if (cd "$TMP_IDIR" && tar xzf "$TMP_IPK" 2>/dev/null \
                        && tar xzf data.tar.gz 2>/dev/null) \
                        && [ -f "$TMP_IDIR/opt/sbin/hysteria" ]; then

                        # Проверка обязательна: отсутствие hashes.txt или
                        # sha256sum/openssl не должно превращаться в обход
                        # проверки. Без ожидаемой суммы бинарник из сети не
                        # устанавливается.
                        _hw_sum="$(sha256_of_file \
                            "$TMP_IDIR/opt/sbin/hysteria" || true)"
                        _hw_exp="$(extract_hysteria_sha256 \
                            "$TMP_HASHES" "$HY_FILE" 2>/dev/null)"

                        if [ -z "$_hw_exp" ]; then
                            warn "   ⚠️ H-wave: checksum для $HY_FILE не получена"
                        elif [ -z "$_hw_sum" ]; then
                            warn "   ⚠️ H-wave: sha256sum/openssl недоступен"
                        elif [ "$_hw_sum" = "$_hw_exp" ]; then
                            cp "$TMP_IDIR/opt/sbin/hysteria" "$DEST_TMP"
                            chmod +x "$DEST_TMP"
                            if "$DEST_TMP" version >/dev/null 2>&1; then
                                mv -f "$DEST_TMP" /opt/sbin/hysteria
                                HW_OK=1
                            fi
                        else
                            warn "   ⚠️ H-wave: контрольная сумма не совпала"
                        fi
                    fi
                fi
                rm -rf "$TMP_IDIR"
                rm -f "$TMP_IPK"
            fi

            if [ "$HW_OK" = "1" ]; then
                echo "✅ hysteria (H-wave): $(hysteria version 2>/dev/null \
                    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
            else
                warn "⚠️ hysteria: установить не удалось."
                warn "   В Entware пакета hysteria нет. Поставьте вручную:"
                warn "   opkg install $HW_URL"
                warn "   затем удалите конфликтующие файлы пакета:"
                warn "   rm -f /opt/etc/init.d/S96hysteria \\"
                warn "         /opt/etc/ndm/netfilter.d/002-hwave.sh"
            fi
        fi
    else
        echo "✅ hysteria: есть"
    fi

    rm -f "$TMP_BIN" "$TMP_HASHES" "$DEST_TMP"
else
    echo "⚠️ Пропущено"
fi

echo ""
# Скачивание завершено — вернуть исходный resolv.conf,
# если он временно подменялся в ensure_dns.
restore_dns

echo "⏳ [8/11] Права..."
for f in \
    /opt/bin/unblock_dnsmasq.sh \
    /opt/bin/unblock_ipset.sh \
    /opt/bin/unblock_update.sh \
    /opt/bin/check_updates.sh \
    /opt/bin/update_protocols.sh \
    /opt/bin/backup_project.sh \
    /opt/bin/deploy_bypass.sh \
    /opt/bin/rotate_logs.sh \
    /opt/etc/ndm/netfilter.d/100-redirect.sh \
    /opt/etc/ndm/fs.d/100-ipset.sh \
    /opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh
do
    [ -f "$f" ] && chmod +x "$f"
done

# ── Устранение дублирующих init-скриптов ─────────────────────────────
# Две причины появления дублей:
#   1) переезд hysteria с S23 на S57 (старт после dnsmasq/S56, иначе
#      Go-резолвер не находит домен сервера и сервис молча умирает);
#   2) пакеты Entware несут СВОИ init-скрипты под другими именами —
#      shadowsocks-libev-ss-redir кладёт S22shadowsocks, тогда как
#      проект использует S65shadowsocks с собственным конфигом
#      (/opt/etc/shadowsocks.json и ключом -u для UDP).
# Оба скрипта запускают один бинарник на одном порту: второй экземпляр
# не забиндится, и какой именно выживет — дело случая. Функция ниже
# гасит и убирает лишний файл, оставляя рабочий.
drop_duplicate_init() {
    _dup="/opt/etc/init.d/$1"      # лишний
    _keep="/opt/etc/init.d/$2"     # рабочий

    [ -f "$_dup" ] || return 0
    [ -f "$_keep" ] || return 0

    "$_dup" stop >/dev/null 2>&1 || true
    rm -f "$_dup"
    echo "  Удалён дублирующий $1 (используется $2)"
}

drop_duplicate_init S23hysteria    S57hysteria
drop_duplicate_init S22shadowsocks S65shadowsocks

for f in /opt/etc/init.d/S*; do
    [ -f "$f" ] && chmod +x "$f"
done

[ -f /opt/sbin/xray ] && chmod +x /opt/sbin/xray
[ -f /opt/sbin/hysteria ] && chmod +x /opt/sbin/hysteria

for f in shadowsocks tor vless trojan hysteria bot; do
    touch "/opt/etc/unblock/${f}.txt"
done

touch /opt/etc/bot/error.log

# dnsmasq из Entware читает /opt/etc/hosts и при отсутствии файла пишет
# в системный журнал "failed to load names from /opt/etc/hosts" при
# каждом старте. Создаём пустой файл, чтобы не засорять лог роутера.
[ -f /opt/etc/hosts ] || : > /opt/etc/hosts
chmod 0644 /opt/etc/hosts 2>/dev/null || true

v4_migrate_settings || die "DNS v4 settings migration failed"

# cron отказывается выполнять задания из crontab с правами шире 0600 и
# пишет в журнал "(*system*) BAD FILE MODE (/opt/etc/crontab)". Файл при
# этом игнорируется целиком: обновление списков, проверка версий и
# ротация журналов молча не запускаются.
if [ -f /opt/etc/crontab ]; then
    chmod 0600 /opt/etc/crontab
    chown root:root /opt/etc/crontab 2>/dev/null || true
fi

# bot_config.py содержит токен бота и пароль панели: доступ только root.
[ -f /opt/etc/bot/bot_config.py ] && chmod 0600 /opt/etc/bot/bot_config.py

# Конфигурации протоколов содержат пароли, UUID и Reality-ключи. Раньше
# они оставались с правами 0644 и читались любым процессом на роутере.
for f in /opt/etc/shadowsocks.json \
    /opt/etc/xray/config.json \
    /opt/etc/trojan/config.json \
    /opt/etc/hysteria/config.json; do
    [ -f "$f" ] && chmod 0600 "$f"
done

# Trojan 1.16 в client/nat-режиме не использует системный CA store
# автоматически на Entware: при пустом ssl.cert он завершается с
# "use_certificate_chain_file: No such file or directory". Новые шаблоны
# уже содержат путь, а этот мигратор чинит старый сохранённый config.json
# после deploy, не перезаписывая явно заданный пользователем сертификат.
ensure_trojan_ca_bundle() {
    _tcfg=/opt/etc/trojan/config.json
    _tca=/opt/etc/ssl/certs/ca-certificates.crt
    [ -f "$_tcfg" ] || return 0
    if [ ! -f "$_tca" ]; then
        # ca-certificates normally creates this Entware path. On older
        # installations it may only leave a compatible bundle elsewhere;
        # copy it into the path used by the Trojan config.
        mkdir -p "$(dirname "$_tca")" 2>/dev/null || true
        for _tca_src in \
            /opt/etc/ssl/cert.pem \
            /etc/ssl/certs/ca-certificates.crt \
            /etc/ssl/cert.pem; do
            if [ -f "$_tca_src" ] && cp "$_tca_src" "$_tca" 2>/dev/null; then
                chmod 0644 "$_tca" 2>/dev/null || true
                break
            fi
        done
    fi
    [ -f "$_tca" ] || {
        warn "⚠️ Не найден CA bundle для Trojan: $_tca"
        return 0
    }
    have_cmd python3 || {
        warn "⚠️ python3 не найден: ssl.cert Trojan не удалось проверить"
        return 0
    }
    if ! python3 - "$_tcfg" "$_tca" <<'PYEOF'
import json
import os
import sys
import tempfile

path, ca = sys.argv[1:]
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except Exception as e:
    print("Trojan JSON не прочитан: %s" % e, file=sys.stderr)
    raise SystemExit(1)

ssl = data.get('ssl')
if not isinstance(ssl, dict):
    raise SystemExit(0)
if ssl.get('verify', True):
    # Keep every user field (endpoint, password, websocket, SNI, etc.).
    # Only repair the TLS CA field when it is empty or points to a file that
    # does not exist. This fixes old configs without overwriting a valid
    # user-supplied CA file.
    old_cert = ssl.get('cert')
    if not old_cert or not os.path.isfile(old_cert):
        ssl['cert'] = ca
        directory = os.path.dirname(path) or '.'
        fd, tmp = tempfile.mkstemp(
            prefix='.trojan.config.', suffix='.tmp', dir=directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write('\n')
            os.chmod(tmp, os.stat(path).st_mode & 0o777)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        print("Trojan: добавлен CA bundle %s" % ca)
PYEOF
    then
        warn "⚠️ Не удалось обновить ssl.cert в Trojan config.json"
    fi
}
ensure_trojan_ca_bundle

# Проверяем только уже заполненный клиентский/nat-конфиг: placeholder,
# отсутствующий ключ и сохранённый server-конфиг — нормальное состояние
# переезда и не должны превращаться в ошибку установки. Это dry-run Trojan,
# а не запуск рабочего процесса.
if have_cmd trojan && [ -s /opt/etc/trojan/config.json ] \
    && ! needs_key /opt/etc/trojan/config.json; then
    _trojan_check_log="$(mktemp /tmp/keenzoo.trojan.check.XXXXXX 2>/dev/null || true)"
    if [ -n "$_trojan_check_log" ]; then
        if trojan -t -c /opt/etc/trojan/config.json \
            >"$_trojan_check_log" 2>&1; then
            echo "✅ Trojan config проверен; рабочий процесс не запускался"
        else
            warn "⚠️ Trojan config не прошёл dry-run; сервис не запускается"
            sed 's/^/     /' "$_trojan_check_log" | tail -12 >&2 || true
        fi
        rm -f "$_trojan_check_log"
    fi
fi

# torrc содержит мосты и cert= — тоже чувствительные данные.
[ -f /opt/etc/tor/torrc ] && chmod 0640 /opt/etc/tor/torrc

# Питоновские модули должны читаться интерпретатором.
for f in /opt/etc/bot/*.py; do
    case "$f" in
        */bot_config.py) ;;
        *) [ -f "$f" ] && chmod 0644 "$f" ;;
    esac
done

# Кэш от предыдущей версии ломает импорт после обновления.
rm -rf /opt/etc/bot/__pycache__ 2>/dev/null || true

# Автозапуск Entware работает только для исполняемых S*-скриптов.
CHK_EXEC=""
for f in /opt/etc/init.d/S99generator /opt/etc/init.d/S99telegram_bot \
    /opt/etc/init.d/S99unblock; do
    [ -f "$f" ] || continue
    chmod +x "$f"
    [ -x "$f" ] || CHK_EXEC="${CHK_EXEC} ${f}"
done
[ -n "$CHK_EXEC" ] && warn "⚠️ Не удалось сделать исполняемым:$CHK_EXEC"

echo "✅ Права"

echo ""
echo "⏳ [9/11] Конфигурация dnsmasq..."
touch /opt/etc/unblock.dnsmasq
chmod 0644 /opt/etc/unblock.dnsmasq

# Директива conf-file подключает сгенерированный список ipset=/домен/набор.
# Добавляется однократно: повторные запуски деплоя не должны плодить дубли.
if [ -f /opt/etc/dnsmasq.conf ]; then
    if grep -q '^conf-file=/opt/etc/unblock.dnsmasq' /opt/etc/dnsmasq.conf; then
        echo "✅ conf-file уже подключён"
    else
        printf 'conf-file=/opt/etc/unblock.dnsmasq\n' >> /opt/etc/dnsmasq.conf
        echo "✅ conf-file добавлен"
    fi

    if dnsmasq --test -C /opt/etc/dnsmasq.conf >/dev/null 2>&1; then
        echo "✅ Конфигурация dnsmasq валидна"
    else
        warn "⚠️ dnsmasq --test не прошёл:"
        dnsmasq --test -C /opt/etc/dnsmasq.conf 2>&1 | head -5 >&2 || true
    fi
else
    warn "⚠️ /opt/etc/dnsmasq.conf отсутствует"
fi

# Секреты не заполняются автоматически — только диагностика, чтобы
# пользователь не искал причину молчащего бота и не стартующей панели.
# Устаревший или чужой __pycache__ подменяет модуль и ломает импорт
# (частая причина после переустановки поверх старой версии).
rm -rf /opt/etc/bot/__pycache__ 2>/dev/null || true

# Права: файл содержит токен, поэтому 0600, но обязан читаться root.
if [ -f /opt/etc/bot/bot_config.py ]; then
    chmod 0600 /opt/etc/bot/bot_config.py 2>/dev/null || true
fi

# stderr НЕ подавляется: раньше причина ошибки скрывалась и сообщение
# "bot_config.py не читается" не давало понять, что именно сломано.
CFG_ERR="$(mktemp /tmp/cfgerr.XXXXXX)"
CFG_STATE="$(python3 - 2>"$CFG_ERR" <<'PYEOF' || echo "err"
import sys
sys.path.insert(0, '/opt/etc/bot')
try:
    import bot_config as c
except Exception as e:
    sys.stderr.write("%s: %s\n" % (type(e).__name__, e))
    print("err"); raise SystemExit(0)
_token = str(getattr(c, 'token', '') or '').strip()
_token_ok = (
    len(_token) >= 10
    and ':' in _token
    and _token.split(':', 1)[0].isdigit()
    and _token not in ('ТОКЕН_БОТА', 'TOKEN', 'YOUR_BOT_TOKEN'))
_ids = getattr(c, 'allowed_user_ids', [])
_names = getattr(c, 'usernames', [])
_ids_ok = bool(_ids) and not (
    _ids == [123456789]
    and 'ИМЯ_ЮЗЕРА' in _names)
_password = str(getattr(c, 'web_password', '') or '').strip()
_password_ok = bool(_password) and _password != 'НАДЁЖНЫЙ_ПАРОЛЬ'
print("%s %s %s" % (
    "ok" if _token_ok else "empty",
    "ok" if _ids_ok else "empty",
    "ok" if _password_ok else "empty"))
PYEOF
)"

NEED_CONFIG=0
if [ "$CFG_STATE" = "err" ]; then
    warn "⚠️ bot_config.py не читается:"
    [ -s "$CFG_ERR" ] && sed 's/^/     /' "$CFG_ERR" >&2
    warn "     Частая причина — значение без кавычек, например"
    warn "     usernames = [Ivanov] вместо usernames = ['Ivanov']."
    warn "     Проверка: cd /opt/etc/bot && python3 -c 'import bot_config'"
    NEED_CONFIG=1
else
    set -- $CFG_STATE
    [ "${1:-empty}" = "ok" ] || {
        warn "⚠️ token не задан или имеет неверный формат"
        NEED_CONFIG=1
    }
    [ "${2:-empty}" = "ok" ] || {
        warn "⚠️ allowed_user_ids пуст или оставлен шаблон"
        NEED_CONFIG=1
    }
    [ "${3:-empty}" = "ok" ] || {
        warn "⚠️ web_password пуст или оставлен шаблон"
        NEED_CONFIG=1
    }
fi
rm -f "$CFG_ERR"
[ "$NEED_CONFIG" -eq 0 ] && echo "✅ Секреты заданы"

DNS_OVERRIDE_OK=0

# Keenetic's firmware resolver normally owns port 53. The Entware dnsmasq
# cannot start until opkg dns-override is enabled, so this must happen BEFORE
# the first S56dnsmasq restart. The old order enabled it only at step 11,
# after dnsmasq had already failed with "Address already in use".
ensure_dns_override() {
    DNS_OVERRIDE_OK=0
    if ! have_cmd ndmc; then
        warn "⚠️ ndmc не найден — DNS Override не настроен."
        warn "   Порт 53 может остаться занят системным DNS Keenetic."
        return 0
    fi

    if ndmc -c "show running-config" 2>/dev/null \
        | grep -q "opkg dns-override"; then
        DNS_OVERRIDE_OK=1
        echo "✅ DNS Override уже включён"
        return 0
    fi

    echo "   Включаю DNS Override до запуска dnsmasq..."
    if ! ndmc -c "opkg dns-override" >/dev/null 2>&1; then
        warn "⚠️ Не удалось включить DNS Override через ndmc"
    fi
    sleep 2
    ndmc -c "system configuration save" >/dev/null 2>&1 || \
        warn "⚠️ Не удалось сохранить конфигурацию KeeneticOS"
    sleep 1

    if ndmc -c "show running-config" 2>/dev/null \
        | grep -q "opkg dns-override"; then
        DNS_OVERRIDE_OK=1
        echo "✅ DNS Override включён и сохранён"
    else
        warn "⚠️ Не удалось подтвердить DNS Override."
        warn "   Выполните вручную до запуска dnsmasq:"
        warn "     ndmc -c \"opkg dns-override\""
        warn "     ndmc -c \"system configuration save\""
        warn "     ndmc -c \"show running-config\" | grep dns-override"
    fi
    return 0
}

echo ""
echo "⏳ [10/11] Запуск..."
# dnsmasq работал во время скачивания (чтобы не потерять DNS), но конфиг
# на шаге 9 мог измениться — поэтому именно ПЕРЕзапуск, а не start.
# DNS Override уже включён выше, до освобождения порта 53.
ensure_dns_override
safe_stop_service "S56dnsmasq"
safe_start_service "S56dnsmasq"

# Tunnel clients are deliberately not started during installation. At this
# point configs may still contain {{...}} placeholders or preserved user
# configs may be incomplete. Starting them caused noisy failures and could
# race with the WAN recovery hook. Keys are added later through the panel;
# the user then starts/restarts the selected protocol explicitly.
PROTOCOLS_STARTED=0
report_protocols_not_started

# Наборы ipset должны существовать до применения правил netfilter,
# иначе правила с --match-set не добавятся.
if [ -x /opt/etc/ndm/fs.d/100-ipset.sh ]; then
    /opt/etc/ndm/fs.d/100-ipset.sh >/dev/null 2>&1 || true
fi
python3 /opt/etc/bot/utils.py --dns-start || die "DNS v4 controller did not start"

# Списки наполняются синхронно: правила ниже и проверка в конце должны
# видеть готовые наборы. Проверка endpoint и pinning выполняются внутри
# существующего unblock_dnsmasq.sh; отдельный bootstrap-файл не создаётся.
if [ -x /opt/bin/unblock_update.sh ]; then
    echo "   Наполнение списков (до нескольких минут)..."
    if /opt/bin/unblock_update.sh; then
        echo "✅ Списки обновлены"
    else
        warn "⚠️ unblock_update.sh вернул ошибку"
    fi
fi

# Tunnel protocols remain stopped until the user adds a key. Netfilter is
# still applied now; it will skip disabled/unready protocol listeners and is
# reapplied by the panel after a protocol is started.

# Правила перехвата применяются для обеих таблиц: nat (TCP/DNS),
# mangle (TPROXY) и filter (LAN-only listeners). Ни один rc не скрывается:
# итоговый флаг используется в финальной диагностике.
NETFILTER_OK=1
if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
    for _nf_table in nat filter; do
        _nf_log="$(mktemp /tmp/redirect.${_nf_table}.XXXXXX)"
        if ! type=iptable table="$_nf_table"             /opt/etc/ndm/netfilter.d/100-redirect.sh >"$_nf_log" 2>&1; then
            NETFILTER_OK=0
            warn "⚠️ netfilter $_nf_table не применён"
            sed 's/^/     /' "$_nf_log" | tail -8 >&2
        fi
        rm -f "$_nf_log"
    done
    if ! type=ip6tables table=filter         /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1; then
        NETFILTER_OK=0
        warn "⚠️ IPv6 filter rules не применены"
    fi

    TP_NOW="$($IPT_BIN -t mangle -S PREROUTING 2>/dev/null         | grep -c 'TPROXY' 2>/dev/null || true)"
    if service_ready S24xray || service_ready S57hysteria; then
        [ "${TP_NOW:-0}" -gt 0 ] 2>/dev/null || {
            NETFILTER_OK=0
            warn "⚠️ active UDP tunnel has no verified TPROXY rule"
        }
    fi
    [ "$NETFILTER_OK" -eq 1 ] &&         echo "✅ Правила netfilter применены (TPROXY: ${TP_NOW:-0})"
else
    NETFILTER_OK=0
    warn "⚠️ отсутствует 100-redirect.sh"
fi

if [ "$NEED_CONFIG" -eq 1 ]; then
    safe_stop_service "S99telegram_bot"
    warn "⏸ S99telegram_bot не запускается: сначала заполните bot_config.py"
else
    safe_start_service "S99telegram_bot"
fi
safe_start_service "S99generator"

echo "✅ Запущены"

echo ""
echo "⏳ [11/11] DNS Override..."
# Повторная идемпотентная проверка оставлена в финале: статус должен быть
# виден в итоговой диагностике даже если ndmc не сработал на шаге 10.
ensure_dns_override

echo ""
echo "════════════════════════════════════"
echo "  ✅ Проект развёрнут!"
echo ""
echo "  Архитектура: $ARCH"
echo "  Ядро: $(uname -r)"
echo "  xray источник: $XRAY_SOURCE"
echo ""
# Адрес панели нужен в подсказках ниже, поэтому определяется здесь.
LAN_IP="$(ip -4 addr show br0 2>/dev/null \
    | awk '/inet /{split($2,a,"/"); print a[1]; exit}')"
[ -n "$LAN_IP" ] || LAN_IP="192.168.1.1"

echo "  Сервисы:"
for svc in xray ss-redir trojan tor hysteria dnsmasq; do
    case "$svc" in
        xray) _svc_init=S24xray ;;
        ss-redir) _svc_init=S65shadowsocks ;;
        trojan) _svc_init=S22trojan ;;
        tor) _svc_init=S35tor ;;
        hysteria) _svc_init=S57hysteria ;;
        dnsmasq) _svc_init=S56dnsmasq ;;
    esac
    if service_ready "$_svc_init"; then
        echo "    ✅ $svc (process + listener/DNS ready)"
        continue
    fi

    # Служба не поднялась. Причины различаются, и молчаливое "—"
    # не позволяет понять, что делать.
    # Служба установлена, но без ключа стартовать не может — это
    # штатное состояние после установки с нуля, а не ошибка.
    # Подсказка объясняет, что делать дальше.
    need_key_msg() {
        echo "    ⏸ $1 — успешно установлен."
        echo "         ключ не задан — сервис не запускается; добавьте ключ через бота или веб-панель"
        echo "         Добавьте ключ $2, чтобы запустить:"
        echo "         бот: меню «$3»"
        echo "         панель: http://${LAN_IP}:${WEB_PORT}"
        echo "         вкладка «$4»"
    }

    # Ключ есть, но служба всё равно не поднялась — вот это ошибка.
    failed_msg() {
        echo "    ❌ $1 — установлен, ключ задан, но не запустился."
        echo "         Проверьте: $2"
        echo "         Логи: logread | grep $1"
    }

    if [ "${PROTOCOLS_STARTED:-1}" -eq 0 ]; then
        case "$svc" in
            xray)
                _p_cfg=/opt/etc/xray/config.json
                _p_key=VLESS
                _p_menu=VLESS
                _p_tab=VLESS
                ;;
            ss-redir)
                _p_cfg=/opt/etc/shadowsocks.json
                _p_key=Shadowsocks
                _p_menu=Shadowsocks
                _p_tab=Shadowsocks
                ;;
            trojan)
                _p_cfg=/opt/etc/trojan/config.json
                _p_key=Trojan
                _p_menu=Trojan
                _p_tab=Trojan
                ;;
            hysteria)
                _p_cfg=/opt/etc/hysteria/config.json
                _p_key=Hysteria2
                _p_menu=Hysteria
                _p_tab=Hysteria
                ;;
            *) _p_cfg="" ;;
        esac
        if [ -n "$_p_cfg" ]; then
            if needs_key "$_p_cfg"; then
                need_key_msg "$svc" "$_p_key" "$_p_menu" "$_p_tab"
            else
                echo "    ⏸ $svc — версия $(protocol_version "$svc");"
                echo "         ключ найден, но сервис намеренно не запускался при установке."
                echo "         Запустите после проверки: $_svc_init start"
            fi
            continue
        fi
    fi

    case "$svc" in
        xray)
            if ! have_cmd xray; then
                echo "    ❌ $svc — не установлен"
            elif needs_key /opt/etc/xray/config.json; then
                need_key_msg "$svc" VLESS "VLESS" "VLESS"
            else
                failed_msg "$svc" "xray -test -c /opt/etc/xray/config.json"
            fi
            ;;
        hysteria)
            if ! have_cmd hysteria; then
                echo "    ❌ $svc — не установлен (нет в Entware)"
            elif needs_key /opt/etc/hysteria/config.json; then
                need_key_msg "$svc" Hysteria2 "Hysteria" "Hysteria"
            else
                failed_msg "$svc" \
                    "hysteria client -c /opt/etc/hysteria/config.json"
            fi
            ;;
        ss-redir)
            if needs_key /opt/etc/shadowsocks.json; then
                need_key_msg "$svc" Shadowsocks "Shadowsocks" "Shadowsocks"
            else
                failed_msg "$svc" "cat /opt/etc/shadowsocks.json"
            fi
            ;;
        trojan)
            if needs_key /opt/etc/trojan/config.json; then
                need_key_msg "$svc" Trojan "Trojan" "Trojan"
            else
                failed_msg "$svc" \
                    "trojan -t -c /opt/etc/trojan/config.json"
            fi
            ;;
        *)
            echo "    — $svc"
            ;;
    esac
done
if [ -x /opt/etc/init.d/S99generator ] \
    && /opt/etc/init.d/S99generator status >/dev/null 2>&1 \
    && web_panel_ready \
    && web_panel_dns_status_ready; then
    echo "    ✅ web-panel (HTTP + /api/dns-status ready)"
else
    warn "    ❌ web-panel (listener/HTTP or /api/dns-status not ready)"
    warn "       Проверка: /opt/etc/init.d/S99generator status"
    warn "       curl -i http://127.0.0.1:${WEB_PORT}/api/dns-status"
fi
# ── Закреплённые адреса прокси-серверов ──────────────────────────────
# Если адрес сервера задан доменом, при блокировке DoT/DoH его нельзя
# будет разрешить и туннель не поднимется. unblock_dnsmasq.sh закрепляет
# IP в /opt/etc/hosts заранее; здесь показываем результат.
echo ""
echo "  Адреса серверов:"
_pin_shown=0
for _pin_cfg in /opt/etc/xray/config.json /opt/etc/hysteria/config.json; do
    [ -f "$_pin_cfg" ] || continue
    case "$_pin_cfg" in
        *xray*) _pin_name="xray"
            _pin_host="$(sed -n 's/.*"address"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                "$_pin_cfg" 2>/dev/null \
                | grep -vE '^(127\.|0\.0\.0\.0|::1?$|localhost$)' | head -1)" ;;
        *) _pin_name="hysteria"
            _pin_host="$(sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                "$_pin_cfg" 2>/dev/null | head -1 | sed 's/:[0-9]*$//')" ;;
    esac
    [ -n "$_pin_host" ] || continue
    case "$_pin_host" in
        ''|*[!0-9.]*)
            # Домен: смотрим, закреплён ли он уже.
            _pin_ip="$(grep -E "[[:space:]]${_pin_host}\$" /opt/etc/hosts \
                2>/dev/null | awk '{print $1}' | head -1)"
            if [ -n "$_pin_ip" ]; then
                echo "    ✅ $_pin_name: $_pin_host → $_pin_ip (закреплён)"
            else
                echo "    ⏸ $_pin_name: $_pin_host — домен ещё не закреплён"
                echo "         Закрепится при первом запуске обновления списков."
                echo "         Надёжнее указать в конфиге IP, а домен оставить в sni."
            fi
            ;;
        *)
            echo "    ✅ $_pin_name: $_pin_host (задан IP, закрепление не нужно)"
            ;;
    esac
    _pin_shown=1
done
[ "$_pin_shown" = "1" ] || echo "    — конфигурации протоколов не найдены"

echo ""
echo "  Версии:"
for _pv_name in ss-redir trojan xray hysteria; do
    printf "    %-10s " "$_pv_name:"
    protocol_version "$_pv_name"
done

echo ""
echo "  Python:"
python3 -c "
import flask, telebot
print('    flask:', flask.__version__)
print('    telebot: OK')
" 2>/dev/null || echo "    ❌ Нет модулей"

echo ""
echo "  Бот:"
# Не использовать `ps | grep`: grep совпадает с собственной командной
# строкой и давал ложное "✅ Запущен" даже после отказа по токену.
if proc_script python3 /opt/etc/bot/main.py \
    || proc_script python /opt/etc/bot/main.py; then
    echo "    ✅ Запущен"
else
    echo "    — Не запущен"
fi
if proc_script python3 /opt/etc/bot/generator.py \
    || proc_script python /opt/etc/bot/generator.py; then
    echo "    ✅ Web-панель"
else
    echo "    — Web-панель"
fi

echo ""
echo "  Наборы ipset:"
for s in unblocksh unblocktor unblockvless \
         unblocktroj unblockhysteria unblockrouter; do
    if ipset list "$s" >/dev/null 2>&1; then
        _cnt="$(ipset list "$s" 2>/dev/null | grep -c '^[0-9]' 2>/dev/null || true)"
        printf "    %-18s %s\n" "$s" "${_cnt:-0}"
    else
        printf "    %-18s отсутствует\n" "$s"
    fi
done

echo ""
echo "  Перехват трафика:"
# grep -c при нуле совпадений печатает 0 и возвращает код 1, поэтому
# результат нормализуется через ${VAR:-0}, а не "|| echo 0".
TP_CNT="$($IPT_BIN -t mangle -S PREROUTING 2>/dev/null \
    | grep -c 'TPROXY' 2>/dev/null || true)"
TP_CNT="${TP_CNT:-0}"
if [ "$TP_CNT" -gt 0 ] 2>/dev/null; then
    echo "    ✅ UDP через TPROXY: $TP_CNT правил"
else
    echo "    ⚠️ Правил TPROXY нет — UDP не пойдёт в туннель"
    if ! $IPT_BIN -j TPROXY --help >/dev/null 2>&1; then
        echo "       Причина: $IPT_BIN не умеет TPROXY."
        echo "       Удалите пакет Entware: opkg remove iptables"
    else
        echo "       Обычно это значит, что наборы vless/hysteria пусты"
        echo "       или ключи ещё не добавлены — добавьте их и выполните"
        echo "       /opt/etc/ndm/netfilter.d/100-redirect.sh"
    fi
fi

if $IPT_BIN -t nat -S PREROUTING 2>/dev/null \
    | grep -- '--dport 53' | grep -qv -- ' -i '; then
    echo "    ❌ Есть правило :53 без -i (открытый DNS-релей!)"
else
    echo "    ✅ Правила :53 привязаны к интерфейсам"
fi

if [ "$DNS_OVERRIDE_OK" -eq 1 ]; then
    echo "    ✅ DNS Override активен"
else
    echo "    ⚠️ DNS Override не подтверждён"
fi

echo ""
if [ "$NEED_CONFIG" -eq 1 ]; then
    echo "  ⚠️ ТРЕБУЕТСЯ НАСТРОЙКА перед перезагрузкой:"
    echo "     vi /opt/etc/bot/bot_config.py"
    echo "        token            — от @BotFather"
    echo "        allowed_user_ids — числовые ID (@userinfobot)"
    echo "        web_password     — пароль веб-панели"
    echo "     /opt/etc/init.d/S99telegram_bot restart"
    echo "     /opt/etc/init.d/S99generator restart"
    echo ""
fi

echo "  Веб-панель: http://${LAN_IP}:${WEB_PORT} (admin, только из LAN)"
WEB_ACC="$($IPT_BIN -S INPUT 2>/dev/null \
    | grep -c -- "--dport ${WEB_PORT} -j ACCEPT" 2>/dev/null || true)"
WEB_ACC="${WEB_ACC:-0}"
if [ "$WEB_ACC" -gt 0 ] 2>/dev/null; then
    echo "    ✅ Доступ из LAN разрешён ($WEB_ACC правил)"
else
    warn "    ⚠️ Нет разрешающих правил для порта ${WEB_PORT}"
    warn "       Выполните: type=iptable table=filter \\"
    warn "         /opt/etc/ndm/netfilter.d/100-redirect.sh"
fi

# Панель обязана СЛУШАТЬ порт: connection refused означает, что процесс
# не запущен, и правила firewall тут ни при чём.
if netstat -ltn 2>/dev/null | grep -q ":${WEB_PORT} " \
    || ss -ltn 2>/dev/null | grep -q ":${WEB_PORT} "; then
    echo "    ✅ Порт ${WEB_PORT} слушается"
else
    warn "    ⚠️ Порт ${WEB_PORT} НЕ слушается — панель не запущена"
    warn "       Причина будет видна в логе:"
    warn "         tail -40 /opt/etc/bot/generator.log"
    warn "         /opt/etc/init.d/S99generator restart"
fi

# Резолвинг для процессов самого роутера (бот, curl, check_updates).
# При включённом dns-override прошивочный резолвер отключён, и если
# /etc/resolv.conf не указывает на локальный dnsmasq, процессы получают
# "Temporary failure in name resolution" — именно из-за этого падал
# телеграм-бот с ошибкой на api.telegram.org.
#
# nameserver должен быть ПЕРВЫМ: иначе процесс может обратиться к DNS
# провайдера напрямую и запрос не попадёт в dnsmasq, который наполняет
# unblockrouter через ipset. Файл уже существует в системе, отдельный
# постоянный resolver-файл проект не создаёт.
ensure_local_resolver() {
    [ -e /etc/resolv.conf ] || : > /etc/resolv.conf 2>/dev/null || return 1
    [ -w /etc/resolv.conf ] || return 1

    _elr_tmp="$(mktemp /tmp/keenzoo_resolv.XXXXXX 2>/dev/null || true)"
    [ -n "$_elr_tmp" ] || return 1

    if {
        printf 'nameserver 127.0.0.1\n'
        sed '/^[[:space:]]*nameserver[[:space:]]*127\.0\.0\.1[[:space:]]*$/d' \
            /etc/resolv.conf 2>/dev/null
    } > "$_elr_tmp" 2>/dev/null \
        && cat "$_elr_tmp" > /etc/resolv.conf 2>/dev/null
    then
        rm -f "$_elr_tmp"
        return 0
    fi

    rm -f "$_elr_tmp"
    return 1
}

if ! ensure_local_resolver; then
    warn "    ⚠️ Не удалось установить nameserver 127.0.0.1 в /etc/resolv.conf"
fi

DEPLOY_DNS_READY=0
if service_ready S56dnsmasq && dns_ok; then
    DEPLOY_DNS_READY=1
    echo "    ✅ Резолвинг на роутере работает через локальный dnsmasq"
else
    warn "    ⚠️ Роутер не резолвит имена — бот работать не сможет"
    warn "       Проверьте: cat /etc/resolv.conf"
    warn "       и: nslookup api.telegram.org 127.0.0.1"
fi

# Прокси-порты не должны быть доступны из внешней сети.
PROXY_DROP=0
PROXY_PORTS="$(config_number localportsh 1082) $(config_number localporttor 9141) $(config_number localportvless 10810) $(config_number localporttrojan 10829) $(config_number localporthysteria 10830)"
for _pp in $PROXY_PORTS; do
    $IPT_BIN -S INPUT 2>/dev/null \
        | grep -q -- "--dport $_pp -j DROP" && \
        PROXY_DROP=$((PROXY_DROP + 1))
done
if [ "$PROXY_DROP" -ge 5 ]; then
    echo "    ✅ Прокси-порты закрыты от WAN ($PROXY_DROP/5)"
else
    warn "    ⚠️ Прокси-порты защищены частично ($PROXY_DROP/5)"
    warn "       type=iptable table=filter \\"
    warn "         /opt/etc/ndm/netfilter.d/100-redirect.sh"
fi

# IPv6-состояние сообщается в начале deploy как предупреждение, но не
# блокирует полное развёртывание. IPv4-политика и итоговая диагностика
# выполняются независимо; при активном IPv6 предупреждение остаётся видимым.

# Автозапуск после перезагрузки: Entware выполняет только исполняемые
# скрипты /opt/etc/init.d/S*. Без +x панель молча не поднимется.
if [ -x /opt/etc/init.d/S99generator ]; then
    echo "    ✅ Автозапуск после перезагрузки настроен"
else
    warn "    ⚠️ S99generator не исполняемый — после reboot не стартует"
    warn "       chmod +x /opt/etc/init.d/S99generator"
fi
echo ""
echo "  Проверка UDP — с КЛИЕНТА в LAN, не с роутера:"
echo "    curl --http3 -sI https://www.google.com --max-time 10 | head -1"
echo "  Затем на роутере счётчики должны вырасти:"
echo "    $IPT_BIN -t mangle -L PREROUTING -v -n | grep TPROXY"
echo ""
if [ "$DEPLOY_DNS_READY" = 1 ]; then
    echo "  Проверьте сайты из LAN/WireGuard; только затем выполните reboot"
else
    warn "  ❌ Установка не прошла DNS readiness. Не перезагружайте роутер"
    warn "     Используйте -repair с локальным исправленным архивом и сохраните логи"
fi
echo ""
echo "  🔴 Отзовите и перевыпустите секреты из репозитория"
echo "     (токен @BotFather /revoke, ключи VLESS/Trojan/Hysteria)."
echo ""
echo "════════════════════════════════════"
[ "$DEPLOY_DNS_READY" = 1 ] || exit 1

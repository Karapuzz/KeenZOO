#!/bin/sh
# /opt/bin/check_updates.sh — сбор текущих и доступных версий компонентов.
# Оболочка: BusyBox ash.
# remove keeps data but disables cron/NDM reactivation until next install:
# без этого отключённый проект продолжал ежедневно ходить в GitHub API и
# мог слать Telegram-уведомления по сохранившемуся токену из bot_config.py.
if [ -f /opt/etc/unblock/.disabled ] && [ "${PURGE_PROJECT:-0}" != 1 ]; then
    exit 0
fi
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# A BusyBox executable does NOT imply that its timeout applet is compiled in.
# 125 = no usable deadline runner; 124 = deadline; 126/127 = not executed.
run_bounded() {
    _rb_seconds="$1"
    shift
    if command -v python3 >/dev/null 2>&1; then
    python3 - "$_rb_seconds" "$@" <<'PY_DEADLINE'
import os
import signal
import subprocess
import sys

proc = None

def stop_group():
    if proc is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass

def interrupted(sig, frame):
    raise SystemExit(128 + sig)

for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, interrupted)
try:
    proc = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        rc = proc.wait(timeout=float(sys.argv[1]))
    except subprocess.TimeoutExpired:
        rc = 124
except OSError as exc:
    rc = 127 if isinstance(exc, FileNotFoundError) else 126
finally:
    stop_group()
sys.exit(rc if rc >= 0 else 128 - rc)
PY_DEADLINE
        return $?
    fi
    # Early bootstrap may not have Python yet. Require a working kill-after
    # option rather than trusting either a symlink or a BusyBox version.
    if command -v timeout >/dev/null 2>&1 \
        && timeout -k 1 1 /bin/sh -c ':' >/dev/null 2>&1; then
        timeout -k 1 "$_rb_seconds" "$@"
        return $?
    fi
    if command -v busybox >/dev/null 2>&1 \
        && busybox timeout -k 1 1 /bin/sh -c ':' >/dev/null 2>&1; then
        busybox timeout -k 1 "$_rb_seconds" "$@"
        return $?
    fi
    return 125
}

STATUS_FILE="/tmp/updates_status.json"
TMP_STATUS="${STATUS_FILE}.tmp.$$"
# Shared by cron, the panel and update_protocols.sh, not just the UI launcher.
CHECK_LOCK_DIR="${CHECK_LOCK_DIR:-/tmp/keenzoo_versions_worker.lockdir}"
check_lock_live() {
    _cl_pid="$(cat "$CHECK_LOCK_DIR/pid" 2>/dev/null || true)"
    _cl_start="$(cat "$CHECK_LOCK_DIR/start" 2>/dev/null || true)"
    case "$_cl_pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$_cl_pid" 2>/dev/null || return 1
    [ -n "$_cl_start" ] && [ "$_cl_start" = "$(awk '{print $22}' "/proc/$_cl_pid/stat" 2>/dev/null)" ]
}
if ! mkdir "$CHECK_LOCK_DIR" 2>/dev/null; then
    check_lock_live && exit 75
    _cl_age=$(( $(date +%s) - $(stat -c %Y "$CHECK_LOCK_DIR" 2>/dev/null || date +%s) ))
    # dns4.2.19: отрицательный возраст (скачок часов назад) = битый замок,
    # снимаем его сразу, а не ждём «созревания» в будущем.
    [ "$_cl_age" -ge 10 ] || [ "$_cl_age" -lt 0 ] || exit 75
    rm -rf "$CHECK_LOCK_DIR"
    mkdir "$CHECK_LOCK_DIR" 2>/dev/null || exit 75
fi
printf '%s\n' "$$" > "$CHECK_LOCK_DIR/pid"
awk '{print $22}' "/proc/$$/stat" > "$CHECK_LOCK_DIR/start"
trap 'rm -f "$TMP_STATUS"; rm -rf "$CHECK_LOCK_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
BOT_CHAT_ID_FILE="/opt/var/run/bot_chat_id_notify.txt"
BOT_TOKEN_FILE="/opt/etc/bot/bot_config.py"

XRAY_REPO="XTLS/Xray-core"
HY_REPO="HyNetworks/hysteria"

# Репозитории для СПРАВОЧНОЙ проверки наличия готовых сборок.
# Обновление этих протоколов выполняется только через opkg.
SS_REPO="shadowsocks/shadowsocks-libev"
TROJAN_REPO="trojan-gfw/trojan"
TOR_REPO="torproject/tor"

ARCH="$(uname -m)"

# ── Наличие ГОТОВЫХ бинарников на GitHub по архитектурам ────────────
# Проверено по релизам проектов:
#   Xray-core   — есть сборки под все архитектуры Keenetic;
#   Hysteria2   — есть, кроме big-endian MIPS;
#   Trojan      — только linux-amd64/macOS/Windows;
#   Shadowsocks — только исходники (.tar.gz);
#   Tor         — релизов с бинарниками на GitHub нет.
# Поэтому схема «GitHub, затем opkg» применима ТОЛЬКО к xray и hysteria.
# Для остальных источник обновлений — opkg (единственный рабочий).
#
# MIPS little-endian: сборки GitHub РАБОТАЮТ. Прежний запрет ссылался на
# GOMIPS=hardfloat, но это правило из мира C: несовместимость ABI важна
# при линковке с libc, а бинарник Go статический и с libc Entware не
# линкуется. Сверка заголовков ELF пакета Entware и релиза XTLS дала
# одинаковые флаги (0x50001004, cpic, o32, mips32), и обе сборки содержат
# COP1-инструкции — то есть пакет самого Entware «hardfloat» ровно в той
# же мере. Отдельного soft-float варианта XTLS не публикует в принципе.
# Проверено на Keenetic Hero 4G+ (MT7621A): Xray 26.7.28 linux/mipsle
# работает штатно. Запрет давал вечное «обновление» до более старой
# версии Entware, поэтому снят.
#
# Big-endian MIPS оставлен на opkg: фактических данных по нему нет.
# Порядок байт определяется по заголовку ELF (байт 0x05: 1 = LE, 2 = BE),
# так как uname -m на Keenetic возвращает "mips" для обоих вариантов.
cu_is_mips_le() {
    for _cu_c in /bin/busybox /bin/sh /bin/cat; do
        [ -r "$_cu_c" ] || continue
        _cu_b="$(dd if="$_cu_c" bs=1 skip=5 count=1 2>/dev/null | od -b | awk 'NR==1 {print $2+0}')"
        case "$_cu_b" in
            1) return 0 ;;
            2) return 1 ;;
        esac
    done
    grep -qi 'little.endian' /proc/cpuinfo 2>/dev/null && return 0
    grep -qi 'big.endian' /proc/cpuinfo 2>/dev/null && return 1
    # Подавляющее большинство Keenetic на MIPS — little-endian.
    return 1
}

case "$ARCH" in
    mips|mipsel|mipsle)
        if cu_is_mips_le; then
            XRAY_GH_OK=1
            HY_GH_OK=1
        else
            XRAY_GH_OK=0
            HY_GH_OK=0
        fi
        ;;
    *)
        XRAY_GH_OK=1
        HY_GH_OK=1
        ;;
esac

# ── Загрузчик ──
DL=""
if command -v curl >/dev/null 2>&1; then
    DL="curl"
elif command -v wget >/dev/null 2>&1; then
    DL="wget"
fi

dl_json() {
    _url="$1"
    if [ "$DL" = "curl" ]; then
        curl -4 -fsS --connect-timeout 5 --max-time 15 \
            "$_url" 2>/dev/null
    elif [ "$DL" = "wget" ]; then
        # BusyBox wget понимает только -T SEC, GNU-опция --timeout=
        # вызывает "unrecognized option" и пустой ответ.
        wget -q -T 15 -O - "$_url" 2>/dev/null
    else
        echo ""
    fi
}

# ── Telegram ──
get_bot_token() {
    grep "^token" "$BOT_TOKEN_FILE" 2>/dev/null \
        | sed "s/.*= *['\"]//;s/['\"].*//" || true
}

send_telegram() {
    _msg="$1"
    _token="$(get_bot_token || true)"
    _chat_id=""
    if [ -f "$BOT_CHAT_ID_FILE" ]; then
        _chat_id="$(cat "$BOT_CHAT_ID_FILE" 2>/dev/null || true)"
    fi
    if [ -z "$_chat_id" ] \
        && [ -f /opt/var/run/bot_chat_id.txt ]
    then
        _chat_id="$(cat /opt/var/run/bot_chat_id.txt 2>/dev/null || true)"
    fi
    if [ -n "$_token" ] \
        && [ -n "$_chat_id" ]; then
        # dns4.2.21 (аудит A3 C3): токен не должен попадать в argv/ps.
        # Bot API требует токен в path URL — поэтому отправка через python3
        # heredoc: аргументы командной строки содержат лишь `python3 -`,
        # секреты передаются окружением (env не виден в `ps`; /proc/<pid>/
        # environ читается только владельцем процесса, то есть root).
        # urllib — без новых зависимостей. Прежние curl/wget-ветки
        # остаются резервом на случай отсутствия python3.
        if command -v python3 >/dev/null 2>&1; then
            TG_TOKEN="$_token" TG_CHAT_ID="$_chat_id" TG_MSG="$_msg" \
                python3 - <<'PY_TG_SEND' >/dev/null 2>&1 || true
import os
import urllib.parse
import urllib.request

url = 'https://api.telegram.org/bot%s/sendMessage' % os.environ['TG_TOKEN']
body = urllib.parse.urlencode({
    'chat_id': os.environ['TG_CHAT_ID'],
    'text': os.environ['TG_MSG'],
    'parse_mode': 'HTML',
}).encode()
try:
    urllib.request.urlopen(url, data=body, timeout=10).read(64)
except OSError:
    pass
# секрет не оставляем в env дольше жизни процесса
for _k in ('TG_TOKEN', 'TG_CHAT_ID', 'TG_MSG'):
    os.environ.pop(_k, None)
PY_TG_SEND
        elif [ "$DL" = "curl" ]; then
            curl -s --max-time 10 \
                -X POST \
                "https://api.telegram.org/bot${_token}/sendMessage" \
                -d "chat_id=${_chat_id}" \
                -d "text=${_msg}" \
                -d "parse_mode=HTML" \
                >/dev/null 2>&1
        elif [ "$DL" = "wget" ]; then
            # BusyBox: -T SEC и --post-data ОТДЕЛЬНЫМ аргументом
            # (форма --post-data=... тоже GNU-only).
            wget -q -T 10 \
                --post-data "chat_id=${_chat_id}&text=${_msg}&parse_mode=HTML" \
                -O /dev/null \
                "https://api.telegram.org/bot${_token}/sendMessage" 2>&1
        fi
    fi
}

# ── Версии GitHub ──
# Разбор tag_name допускает произвольные пробелы после ключа и двоеточия.
# Hysteria публикует релизы с тегами вида app/v2.6.0, Xray — v1.8.24,
# поэтому отбрасывается и путь до слэша, и ведущая "v".
github_version() {
    _repo="$1"
    # grep -o вырезает КАЖДОЕ вхождение отдельной строкой, поэтому head -1
    # берёт tag_name самого релиза. Прежний вариант с sed 's/.*"tag_name".../'
    # из-за жадного .* выхватывал ПОСЛЕДНЕЕ вхождение в однострочном JSON —
    # то есть tag_name из assets, а не версию релиза.
    # Пробелы/табы после ключа и двоеточия допускаются.
    # НЕ /releases/latest: XTLS помечает новые релизы как prerelease,
    # и "latest" отдаёт застрявшую версию. Панель показывала бы её как
    # "доступную", хотя деплой ставит более свежую — версии расходятся.
    dl_json "https://api.github.com/repos/${_repo}/releases?per_page=10" \
        | tr '{' '\n' \
        | grep '"tag_name"' \
        | grep -v '"draft": *true' \
        | head -1 \
        | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
        | sed 's|.*/||; s/^[vV]//'
}


# ── Версии opkg ──
# Нормализация версии: срезает путь тега (app/v2.6.0) и ведущую "v",
# чтобы сравнение локальной и удалённой версии не давало ложных срабатываний.
norm_version() {
    printf '%s' "${1:-}" | sed 's|.*/||; s/^[vV]//; s/[[:space:]]*$//'
}

# ── Сравнение версий ────────────────────────────────────────────────
# Возвращает 0, если $1 СТРОГО НОВЕЕ $2. Сравнение покомпонентное и
# числовое: строковое "26.9.8" > "26.10.1" дало бы неверный результат,
# потому что "9" > "1" посимвольно.
# Суффиксы вроде "-1" (ревизия пакета Entware) отбрасываются: они
# относятся к сборке, а не к версии апстрима.
version_gt() {
    _a="$(printf '%s' "${1:-}" | sed 's/-.*$//')"
    _b="$(printf '%s' "${2:-}" | sed 's/-.*$//')"

    [ -n "$_a" ] || return 1
    [ -n "$_b" ] && [ "$_a" != "$_b" ] || {
        [ -z "$_b" ] && return 0
        return 1
    }

    _i=1
    while [ "$_i" -le 4 ]; do
        _pa="$(printf '%s' "$_a" | cut -d. -f"$_i")"
        _pb="$(printf '%s' "$_b" | cut -d. -f"$_i")"
        # Отсутствующий компонент считаем нулём: 2.12 == 2.12.0
        case "$_pa" in ''|*[!0-9]*) _pa=0 ;; esac
        case "$_pb" in ''|*[!0-9]*) _pb=0 ;; esac
        if [ "$_pa" -gt "$_pb" ]; then
            return 0
        fi
        if [ "$_pa" -lt "$_pb" ]; then
            return 1
        fi
        _i=$((_i + 1))
    done
    return 1
}

# Выбирает новейшую из версии GitHub и версии opkg.
# Печатает: "<версия> <источник>". Пустой ввод игнорируется.
pick_newest() {
    # Ревизия пакета Entware ("26.2.6-1") срезается и в выводе: иначе
    # панель сравнивала бы "26.2.6-1" с установленной "26.2.6" и вечно
    # предлагала обновление на ту же версию.
    _gh="$(norm_version "${1:-}" | sed 's/-.*$//')"
    _op="$(norm_version "${2:-}" | sed 's/-.*$//')"

    if [ -n "$_gh" ] && [ -n "$_op" ]; then
        if version_gt "$_gh" "$_op"; then
            printf '%s github' "$_gh"
        else
            printf '%s opkg' "$_op"
        fi
    elif [ -n "$_gh" ]; then
        printf '%s github' "$_gh"
    elif [ -n "$_op" ]; then
        printf '%s opkg' "$_op"
    fi
}

# ── Есть ли на GitHub готовый бинарник под нашу архитектуру ─────────
# Проекты Trojan, Shadowsocks-libev и Tor собираемых бинарников под
# Keenetic не публикуют (проверено: Trojan — только amd64/macOS/Win,
# Shadowsocks — исходники .tar.gz, Tor — релизов с ассетами нет).
# Но это может измениться, поэтому наличие сборки проверяется по факту,
# а не задаётся жёстко: если подходящий ассет появится, панель покажет
# версию с GitHub как справочную.
#
# Ключи поиска в имени ассета — по архитектуре роутера.
case "$ARCH" in
    aarch64|arm64) ASSET_KEYS="arm64 aarch64" ;;
    armv7l|armv7)  ASSET_KEYS="armv7 arm32-v7 armhf" ;;
    armv6l|armv6)  ASSET_KEYS="arm32-v6 armv6" ;;
    armv5l|armv5tel|armv5) ASSET_KEYS="armv5 arm32-v5" ;;
    mips|mipsel|mipsle) ASSET_KEYS="mipsle mips32le mipsel" ;;
    x86_64|amd64)  ASSET_KEYS="amd64 x86_64 x64" ;;
    i386|i486|i586|i686) ASSET_KEYS="386 linux-32" ;;
    *)             ASSET_KEYS="" ;;
esac

# Печатает версию релиза, если среди ассетов есть linux-сборка под
# нашу архитектуру. Иначе не печатает ничего.
github_version_if_binary() {
    _repo="$1"
    [ -n "$ASSET_KEYS" ] || return 0

    _json="$(dl_json \
        "https://api.github.com/repos/${_repo}/releases/latest")"
    [ -n "$_json" ] || return 0

    # Имена ассетов — по одному на строку.
    _names="$(printf '%s' "$_json" \
        | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*"\([^"]*\)"$/\1/')"

    _found=0
    for _k in $ASSET_KEYS; do
        if printf '%s\n' "$_names" \
            | grep -qi -- "$_k" 2>/dev/null
        then
            # Исходники и пакеты для чужих ОС не считаем сборкой.
            if printf '%s\n' "$_names" | grep -i -- "$_k" \
                | grep -qiE 'linux|\.ipk|\.tar\.gz$' 2>/dev/null
            then
                _found=1
                break
            fi
        fi
    done

    [ "$_found" = "1" ] || return 0

    printf '%s' "$_json" \
        | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -1 \
        | sed 's/.*"\([^"]*\)"$/\1/' \
        | sed 's|.*/||; s/^[vV]//'
}

# Версия пакета в репозитории Entware — даже если пакет не установлен.
# list-upgradable показывает только установленные пакеты с апдейтом,
# поэтому для сравнения с GitHub нужен именно этот вариант.
opkg_version() {
    _pkg="$1"
    opkg info "$_pkg" 2>/dev/null \
        | awk '$1=="Version:" {print $2; exit}' || true
}

opkg_available() {
    _pkg="$1"
    # dns4.2.21 (находка B6-1): формат `opkg list-upgradable` —
    # "pkg - installed - available": $3 — УСТАНОВЛЕННАЯ версия, $5 — ДОСТУПНАЯ.
    # Прежние $3 давали version_gt(installed, installed) == false всегда,
    # и обновления ssredir/trojan/tor/dnsmasq-full никогда не показывались.
    # (Идиома $3 была перенесена из `opkg list-installed`, где она валидна.)
    opkg list-upgradable 2>/dev/null \
        | grep "^${_pkg} " \
        | awk '{print $5}' || true
}

opkg_installed() {
    _pkg="$1"
    opkg list-installed 2>/dev/null \
        | grep "^${_pkg} " \
        | awk '{print $3}' || true
}

# ── Локальные версии ──
local_xray() {
    xray version 2>/dev/null | head -1 | awk '{print $2}' || true
}

local_hysteria() {
    hysteria version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

local_ss() {
    ss-redir -h 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

local_trojan() {
    trojan --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

local_tor() {
    tor --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

local_dnsmasq() {
    dnsmasq --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+' | head -1 || true
}

# ══════════════════════════════════
#  Основная логика
# ══════════════════════════════════

REPO_OK=0
# Retain cached package lists if no bounded runner or repository is available.
REPO_PROBE_RC=0
run_bounded 90 opkg update >/dev/null 2>&1 && REPO_OK=1 || REPO_PROBE_RC=$?

# Текущие
CUR_XRAY="$(local_xray || true)"
CUR_HY="$(local_hysteria || true)"
CUR_SS="$(local_ss || true)"
CUR_TROJAN="$(local_trojan || true)"
CUR_TOR="$(local_tor || true)"
CUR_DNSMASQ="$(local_dnsmasq || true)"

# ── xray: сначала GitHub, затем opkg, ставим новейшую ───────────────
# Релизы XTLS выходят раньше, чем пакет попадает в Entware, поэтому
# опрашиваются оба источника и выбирается более свежая версия.
# opkg_version отдаёт версию в репозитории независимо от того, считает
# ли opkg её "upgradable": бинарник мог быть поставлен с GitHub, и
# тогда пакет вообще не установлен, а list-upgradable промолчит.
XRAY_GH=""
if [ "$XRAY_GH_OK" = "1" ]; then
    XRAY_GH="$(github_version "$XRAY_REPO" || true)"
fi
XRAY_OP="$(opkg_version "xray" || true)"

XRAY_PICK="$(pick_newest "$XRAY_GH" "$XRAY_OP")"
NEW_XRAY="$(printf '%s' "$XRAY_PICK" | awk '{print $1}')"
XRAY_SOURCE="$(printf '%s' "$XRAY_PICK" | awk '{print $2}')"
[ -n "$XRAY_SOURCE" ] || XRAY_SOURCE="opkg"

# ── hysteria: то же самое ───────────────────────────────────────────
# В репозитории Entware пакета hysteria нет, поэтому фактически всегда
# побеждает GitHub. Логика оставлена симметричной на случай появления
# пакета в будущем.
HY_GH=""
if [ "$HY_GH_OK" = "1" ]; then
    HY_GH="$(github_version "$HY_REPO" || true)"
fi
HY_OP="$(opkg_version "hysteria" || true)"

HY_PICK="$(pick_newest "$HY_GH" "$HY_OP")"
NEW_HY="$(printf '%s' "$HY_PICK" | awk '{print $1}')"
HY_SOURCE="$(printf '%s' "$HY_PICK" | awk '{print $2}')"
[ -n "$HY_SOURCE" ] || HY_SOURCE="github"

# ── Остальные протоколы: только opkg ────────────────────────────────
# Готовых бинарников под архитектуры Keenetic эти проекты на GitHub не
# публикуют (Trojan — только amd64, Shadowsocks — исходники, Tor —
# релизов с бинарниками нет). Сборка из исходников на роутере
# невозможна: нет компилятора и недостаточно места.
NEW_SS="$(opkg_available "shadowsocks-libev-ss-redir" || true)"
NEW_TROJAN="$(opkg_available "trojan" || true)"
NEW_TOR="$(opkg_available "tor" || true)"
NEW_DNSMASQ="$(opkg_available "dnsmasq-full" || true)"

# ── Справочно: релизы GitHub для остальных протоколов ───────────────
# Обновление этих компонентов идёт ТОЛЬКО через opkg. Версия с GitHub
# показывается лишь как информация и лишь тогда, когда там реально
# появилась сборка под архитектуру роутера. Сейчас её нет ни у одного
# из трёх проектов, поэтому поля останутся пустыми и в панели не
# отобразятся.
GH_SS="$(github_version_if_binary "$SS_REPO" || true)"
GH_TROJAN="$(github_version_if_binary "$TROJAN_REPO" || true)"
GH_TOR="$(github_version_if_binary "$TOR_REPO" || true)"

# A network failure is not "no updates". Keep local versions/cached package
# information useful but explicitly mark an incomplete remote check.
CHECK_STATUS="done"
CHECK_MESSAGE=""
[ "$REPO_OK" = 1 ] || { CHECK_STATUS=partial; CHECK_MESSAGE=OPKG_UNAVAILABLE; }
case "$REPO_PROBE_RC" in
    125|126|127) CHECK_MESSAGE="${CHECK_MESSAGE},OPKG_PROBE_UNAVAILABLE" ;;
esac
if { [ "$XRAY_GH_OK" = 1 ] && [ -z "$XRAY_GH" ]; } \
    || { [ "$HY_GH_OK" = 1 ] && [ -z "$HY_GH" ]; }; then
    CHECK_STATUS=partial
    CHECK_MESSAGE="${CHECK_MESSAGE}${CHECK_MESSAGE:+,}GITHUB_UNAVAILABLE"
fi

# Формируем JSON
HAS_UPDATES="false"
UPDATES=""
TS="$(date +%s)"


# Сравнение идёт по неравенству, а не «больше/меньше»: на роутере
# версия может оказаться и НОВЕЕ доступной (например, бинарник с
# GitHub, а сравнение с репозиторием Entware). Такой случай тоже
# показывается — пользователь видит обе версии и решает сам.
add_update() {
    _name="$1"
    _cur="$(norm_version "$2")"
    _new="$(norm_version "$3")"
    _src="$4"
    # Понижение версии обновлением НЕ считается. Раньше сравнение шло по
    # неравенству, и если установленная версия новее доступной (типовой
    # случай для mipsel: с GitHub стоит 26.7.28, в Entware лежит 26.2.6),
    # панель бесконечно предлагала «обновиться» на старую. Нажатие кнопки
    # ничего не меняло — opkg понижение не делает — и уведомление
    # появлялось снова по кругу.
    if [ -n "$_new" ] \
        && [ -n "$_cur" ] \
        && [ "$_cur" != "$_new" ] \
        && version_gt "$_new" "$_cur"; then
        if [ -n "$UPDATES" ]; then
            UPDATES="${UPDATES},"
        fi
        UPDATES="${UPDATES}{\"name\":\"${_name}\",\"current\":\"${_cur}\",\"available\":\"${_new}\",\"source\":\"${_src}\"}"
        HAS_UPDATES="true"
    fi
}

# Источник уже выбран выше (новейшая из GitHub/opkg).
add_update "xray" \
    "$CUR_XRAY" "$NEW_XRAY" "$XRAY_SOURCE"

add_update "hysteria" \
    "$CUR_HY" "$NEW_HY" "$HY_SOURCE"
add_update "shadowsocks" \
    "$CUR_SS" "$NEW_SS" "opkg"
add_update "trojan" \
    "$CUR_TROJAN" "$NEW_TROJAN" "opkg"
add_update "tor" \
    "$CUR_TOR" "$NEW_TOR" "opkg"
add_update "dnsmasq" \
    "$CUR_DNSMASQ" "$NEW_DNSMASQ" "opkg"

VERSIONS="{\"xray\":\"${CUR_XRAY:-N/A}\",\"hysteria\":\"${CUR_HY:-N/A}\",\"shadowsocks\":\"${CUR_SS:-N/A}\",\"trojan\":\"${CUR_TROJAN:-N/A}\",\"tor\":\"${CUR_TOR:-N/A}\",\"dnsmasq\":\"${CUR_DNSMASQ:-N/A}\"}"

# github_only — справочные версии тех протоколов, что обновляются
# только через opkg. Заполняется, лишь если на GitHub появилась сборка
# под нашу архитектуру. Панель показывает их отдельно, не как
# предложение обновиться.
GH_ONLY=""
gh_note() {
    [ -n "$2" ] || return 0
    [ -n "$GH_ONLY" ] && GH_ONLY="${GH_ONLY},"
    GH_ONLY="${GH_ONLY}\"$1\":\"$2\""
}
gh_note "shadowsocks" "$GH_SS"
gh_note "trojan" "$GH_TROJAN"
gh_note "tor" "$GH_TOR"

echo "{\"status\":\"${CHECK_STATUS}\",\"message\":\"${CHECK_MESSAGE}\",\"ts\":${TS},\"has_updates\":${HAS_UPDATES},\"versions\":${VERSIONS},\"updates\":[${UPDATES}],\"github_only\":{${GH_ONLY}},\"arch\":\"${ARCH}\",\"xray_source\":\"${XRAY_SOURCE}\"}" \
    > "$TMP_STATUS"
mv -f "$TMP_STATUS" "$STATUS_FILE"

# ── Уведомление ──
if [ "$HAS_UPDATES" = "true" ]; then
    MSG="🆕 <b>Обновления (${ARCH}):</b>"
    TMP_LINES="/tmp/updates_lines.$$"

    printf '%s\n' "$UPDATES" | sed 's/},{/}|{/g' | tr '|' '\n' > "$TMP_LINES"

    # while ... < файл выполняется в текущей оболочке (не в subshell),
    # поэтому накопленный MSG сохраняется после цикла.
    while IFS= read -r line; do
        [ -z "$line" ] && continue

        _n="$(printf '%s' "$line" | sed 's/.*"name":"\([^"]*\)".*/\1/')"
        _c="$(printf '%s' "$line" | sed 's/.*"current":"\([^"]*\)".*/\1/')"
        _a="$(printf '%s' "$line" | sed 's/.*"available":"\([^"]*\)".*/\1/')"
        _s="$(printf '%s' "$line" | sed 's/.*"source":"\([^"]*\)".*/\1/')"

        MSG="${MSG}
• <b>${_n}</b>: ${_c} → ${_a} (${_s})"
    done < "$TMP_LINES"

    rm -f "$TMP_LINES"
    send_telegram "$MSG"
fi

exit 0

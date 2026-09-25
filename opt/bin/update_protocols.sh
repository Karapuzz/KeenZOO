#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

ACTION="${1:-}"
ARCH="$(uname -m)"
XRAY_SOURCE="opkg"
XRAY_FILE=""
HY_FILE=""

XRAY_REPO="XTLS/Xray-core"
HY_REPO="HyNetworks/hysteria"

BINARY_VERIFY_MODE="${BINARY_VERIFY_MODE:-sha256}"
BINARY_GPG_KEYRING="${BINARY_GPG_KEYRING:-}"
XRAY_GPG_SIG_URL="${XRAY_GPG_SIG_URL:-}"
HY_GPG_SIG_URL="${HY_GPG_SIG_URL:-}"

# Only one binary transaction may stop/replace a protocol at a time. The
# mkdir lock works on BusyBox/flash filesystems and has no daemon or new
# permanent script. PID plus /proc starttime avoids PID reuse.
PROTO_LOCK_DIR="${PROTO_LOCK_DIR:-/tmp/keenzoo_protocol_update.lockdir}"
PROTO_LOCK_ACQUIRED=0
OPKG_INIT_STAGE=""
proto_lock_live() {
    if [ ! -f "$PROTO_LOCK_DIR/pid" ]; then
        _pl_mtime="$(stat -c %Y "$PROTO_LOCK_DIR" 2>/dev/null || echo 0)"
        _pl_now="$(date +%s 2>/dev/null || echo 0)"
        case "$_pl_mtime:$_pl_now" in *[!0-9:]*|0:*) return 1 ;; esac
        [ $((_pl_now - _pl_mtime)) -lt 10 ] && return 0
        return 1
    fi
    _pl_pid="$(cat "$PROTO_LOCK_DIR/pid" 2>/dev/null || true)"
    _pl_saved="$(cat "$PROTO_LOCK_DIR/start" 2>/dev/null || true)"
    case "$_pl_pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$_pl_pid" 2>/dev/null || return 1
    if [ -n "$_pl_saved" ] && [ -r "/proc/$_pl_pid/stat" ]; then
        _pl_now="$(awk '{print $22}' "/proc/$_pl_pid/stat" 2>/dev/null || true)"
        [ -n "$_pl_now" ] && [ "$_pl_now" = "$_pl_saved" ] || return 1
    fi
    return 0
}
proto_unlock() {
    if [ -n "$OPKG_INIT_STAGE" ]; then
        restore_package_inits || true
    fi
    [ "$PROTO_LOCK_ACQUIRED" -eq 1 ] && rm -rf "$PROTO_LOCK_DIR"
}
_pl_tries=0
while ! mkdir "$PROTO_LOCK_DIR" 2>/dev/null; do
    if ! proto_lock_live; then
        rm -rf "$PROTO_LOCK_DIR" 2>/dev/null || true
        continue
    fi
    _pl_tries=$((_pl_tries + 1))
    [ "$_pl_tries" -lt 30 ] || exit 75
    sleep 1
done
PROTO_LOCK_ACQUIRED=1
printf '%s\n' "$$" > "$PROTO_LOCK_DIR/pid"
awk '{print $22}' "/proc/$$/stat" 2>/dev/null > "$PROTO_LOCK_DIR/start" || true
trap proto_unlock EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

have_cmd() {
    command -v "$1" >/dev/null 2>&1
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

PORT_VLESS="$(config_number localportvless 10810)"
PORT_HYSTERIA="$(config_number localporthysteria 10830)"

# ── Управление сервисами ────────────────────────────────────────────
# Вынесено в функции: остановка выполняется в разных местах в
# зависимости от источника, дублировать killall не нужно.
# ПРЕДУПРЕЖДЕНИЕ: функция _stop_project_xray продублирована в
# opt/bin/deploy_bypass.sh (автономность деплоя, A3 H4) — ЛЮБУЮ правку вносить
# СИНХРОННО в оба файла (аудит N3c, dns4.2.22).
# dns4.2.21 (A3 H4): убивать только ПРОЕКТНЫЙ xray. `killall xray`
# сносил и любой xray, запущенный пользователем из своего конфига.
# Разбор /proc без pgrep/pkill (того нет в части сборок BusyBox, pkill -f
# ранее дисквалифицирован): argv0 basename = xray И в argv есть
# проектный путь конфигурации. sig=TERM|KILL.
_stop_project_xray() {
    _spx_sig="${1:-TERM}"
    for _spx_pid in /proc/[0-9]*; do
        [ -r "$_spx_pid/cmdline" ] || continue
        _spx_argv0="$(tr '\000' '\n' < "$_spx_pid/cmdline" 2>/dev/null | head -1 || true)"
        [ "$(basename "$_spx_argv0" 2>/dev/null)" = xray ] || continue
        _spx_cmd="$(tr "$(printf '\000')" ' ' < "$_spx_pid/cmdline" 2>/dev/null || true)"
        case "$_spx_cmd" in
            */opt/etc/xray/*|*/opt/etc/bot/*xray*) ;;
            *) continue ;;
        esac
        kill "-$_spx_sig" "${_spx_pid#/proc/}" 2>/dev/null || true
    done
}
stop_xray() {
    [ -x /opt/etc/init.d/S24xray ] \
        && /opt/etc/init.d/S24xray stop 2>/dev/null || true
    _stop_project_xray TERM
    sleep 1
    _stop_project_xray KILL
    sleep 2
}

start_xray() {
    [ -x /opt/etc/init.d/S24xray ] || return 1
    /opt/etc/init.d/S24xray start
}

stop_hysteria() {
    [ -x /opt/etc/init.d/S57hysteria ] \
        && /opt/etc/init.d/S57hysteria stop 2>/dev/null || true
}

start_hysteria() {
    [ -x /opt/etc/init.d/S57hysteria ] || return 1
    /opt/etc/init.d/S57hysteria start
}

warn() {
    printf '%s\n' "$*" >&2
}

# Verify both the process and the expected local listener. This is portable
# on Keenetic: /proc/net/{tcp,udp} is available even when ss/netstat is not.
listener_ready() {
    _lr_port="$1"
    _lr_proto="$2"
    _lr_hex="$(printf '%04X' "$_lr_port" 2>/dev/null || true)"
    [ -n "$_lr_hex" ] || return 1
    case "$_lr_proto" in
        tcp) _lr_files="/proc/net/tcp /proc/net/tcp6" ;;
        udp) _lr_files="/proc/net/udp /proc/net/udp6" ;;
        *) _lr_files="/proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6" ;;
    esac
    for _lr_file in $_lr_files; do
        [ -r "$_lr_file" ] || continue
        if awk -v p=":$_lr_hex" \
            '$2 ~ p"$" && ($4 == "0A" || FILENAME ~ /udp/) {found=1} END{exit !found}' \
            "$_lr_file" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

wait_service_ready() {
    _ws_proc="$1"
    _ws_port="$2"
    _ws_proto="$3"
    _ws_i=0
    while [ "$_ws_i" -lt 30 ]; do
        if pidof "$_ws_proc" >/dev/null 2>&1 \
            && listener_ready "$_ws_port" "$_ws_proto"; then
            return 0
        fi
        _ws_i=$((_ws_i + 1))
        sleep 1
    done
    return 1
}

# Pорядок байт MIPS определяется фактически: uname -m на Keenetic
# возвращает "mips" и для big-, и для little-endian. Байт 0x05 заголовка
# ELF: 1 = LE, 2 = BE. Запасной вариант — /proc/cpuinfo.
up_is_mips_le() {
    # Баг 5 фикс (синхронно с detect_endian в deploy_bypass.sh):
    # зонд 6-го байта ELF работает через `od` ИЛИ `hexdump` (BusyBox),
    # т.к. `od` может отсутствовать; шаблон /proc/cpuinfo расширен до
    # реального формата MIPS-ядра «byteorder : little». Консервативный
    # дефолт прежний: считать BE (обновление через Entware/opkg).
    for _up_c in /bin/busybox /bin/sh /bin/cat; do
        [ -r "$_up_c" ] || continue
        _up_b=""
        if command -v od >/dev/null 2>&1; then
            _up_b="$(dd if="$_up_c" bs=1 skip=5 count=1 2>/dev/null | od -b | awk 'NR==1 {print $2+0}')"
        elif command -v hexdump >/dev/null 2>&1; then
            _up_b="$(dd if="$_up_c" bs=1 skip=5 count=1 2>/dev/null | hexdump -e '1/1 "%d"')"
        elif command -v busybox >/dev/null 2>&1 \
            && busybox hexdump -e '1/1 "%d"' /dev/null >/dev/null 2>&1; then
            # Полировка 4.2.26: апплет может жить вкомпилированным в
            # /bin/busybox без симлинка в /usr/bin (см. deploy_bypass.sh).
            _up_b="$(dd if="$_up_c" bs=1 skip=5 count=1 2>/dev/null | busybox hexdump -e '1/1 "%d"')"
        fi
        case "$_up_b" in
            1) return 0 ;;
            2) return 1 ;;
        esac
    done
    grep -qiE 'little[-_ .]?endian|byteorder[[:space:]]*:[[:space:]]*little' \
        /proc/cpuinfo 2>/dev/null && return 0
    grep -qiE 'big[-_ .]?endian|byteorder[[:space:]]*:[[:space:]]*big' \
        /proc/cpuinfo 2>/dev/null && return 1
    return 1
}

# Источник обновления xray выбирается по НАЛИЧИЮ рабочей сборки, а не
# по версии ядра: прежняя логика на aarch64 с ядром 4.x (KN-1012)
# уводила обновление в opkg, тогда как деплой ставил бинарник с GitHub.
# Итоговый выбор между GitHub и Entware делается ниже — по тому, где
# версия новее.
# Набор архитектур синхронизирован с deploy_bypass.sh. Раньше здесь были
# только aarch64 и mips, а всё остальное уходило в "exit 1": на ARMv7,
# ARMv5 и x86 обновление протоколов падало, хотя деплой эти платформы
# поддерживает и ставит бинарники.
case "$ARCH" in
    aarch64|arm64)
        HY_FILE="hysteria-linux-arm64"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm64-v8a.zip"
        ;;
    armv7l|armv7)
        HY_FILE="hysteria-linux-arm"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v7a.zip"
        ;;
    armv6l|armv6)
        HY_FILE="hysteria-linux-armv5"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v6.zip"
        ;;
    armv5l|armv5tel|armv5)
        HY_FILE="hysteria-linux-armv5"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-arm32-v5.zip"
        ;;
    x86_64|amd64)
        HY_FILE="hysteria-linux-amd64"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-64.zip"
        ;;
    i386|i486|i586|i686)
        HY_FILE="hysteria-linux-386"
        XRAY_SOURCE="github"
        XRAY_FILE="Xray-linux-32.zip"
        ;;
    mips|mipsel|mipsle)
        # MIPS little-endian: сборки GitHub работают (проверено на
        # MT7621A, Xray 26.7.28 linux/mipsle). Прежний отказ опирался на
        # GOMIPS=hardfloat, но Go-бинарник статический и с libc Entware
        # не линкуется, а заголовки ELF пакета Entware и релиза XTLS
        # совпадают (0x50001004, cpic, o32, mips32).
        # Big-endian остаётся на opkg: данных по нему нет.
        HY_FILE="hysteria-linux-mipsle-sf"
        if up_is_mips_le; then
            XRAY_SOURCE="github"
            XRAY_FILE="Xray-linux-mips32le.zip"
        else
            HY_FILE=""
            XRAY_SOURCE="opkg"
        fi
        ;;
    *)
        echo "⚠️ $ARCH: GitHub ABI неизвестен, только Entware"
        HY_FILE=""; XRAY_SOURCE="opkg"; XRAY_FILE=""
        ;;
esac

DL=""
if have_cmd curl; then
    DL="curl"
elif have_cmd wget; then
    DL="wget"
fi

dl_file() {
    _url="$1"
    _out="$2"

    case "$_url" in
        https://*) ;;
        *) return 1 ;;
    esac

    if [ "$DL" = "curl" ]; then
        curl -fsSL --connect-timeout 20 --max-time 180 \
            -o "$_out" "$_url"
    elif [ "$DL" = "wget" ]; then
        # BusyBox wget не знает GNU-опций --https-only/--timeout= и падает
        # с "unrecognized option" ещё до скачивания. Схема https уже
        # проверена выше, поэтому достаточно -T SEC.
        if wget --help 2>&1 | grep -q -- '--https-only'; then
            wget -q --https-only --timeout=180 \
                -O "$_out" "$_url"
        else
            wget -q -T 180 -O "$_out" "$_url"
        fi
    else
        return 1
    fi
}

sha256_of_file() {
    _file="$1"

    if have_cmd sha256sum; then
        sha256sum "$_file" | awk '{print $1}'
    elif have_cmd openssl; then
        openssl dgst -sha256 "$_file" | awk '{print $NF}'
    elif have_cmd python3; then
        # dns4.2.23 (аудит A5 #6): третий источник. Без него система,
        # где нет ни sha256sum, ни openssl, навсегда отказывала в
        # обновлении бинарников, хотя python3 гарантированно есть —
        # на нём работают DNS-слой и панель.
        python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$_file"
    else
        return 1
    fi
}

extract_xray_sha256() {
    _dgst_file="$1"
    # BusyBox awk не поддерживает gawk-расширение IGNORECASE.
    # Ищем только SHA2-256, чтобы не принять SHA2-512.
    awk '/^[Ss][Hh][Aa]2?-?256[[:space:]]*=/ {
             gsub(/[[:space:]]/, "", $NF)
             print $NF
             exit
         }' "$_dgst_file"
}

extract_hysteria_sha256() {
    _hashes_file="$1"
    _asset_name="$2"
    # В hashes.txt имя часто содержит путь build/..., поэтому сравниваем
    # basename, а не всё поле $NF.
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

    [ -n "$_sig_url" ] || return 1
    [ -n "$BINARY_GPG_KEYRING" ] || return 1

    if ! have_cmd gpgv && ! have_cmd gpg; then
        return 1
    fi

    # BusyBox mktemp требует XXXXXX в САМОМ конце шаблона: суффикс после
    # них даёт "mktemp: Invalid argument" (GNU coreutils такое допускает).
    _sig_file="$(mktemp "/tmp/${_name}.asc.XXXXXX")"
    if ! dl_file "$_sig_url" "$_sig_file"; then
        rm -f "$_sig_file"
        return 1
    fi

    if have_cmd gpgv; then
        gpgv --keyring "$BINARY_GPG_KEYRING" \
            "$_sig_file" "$_file" >/dev/null 2>&1 || {
            rm -f "$_sig_file"
            return 1
        }
    else
        gpg --batch --no-default-keyring \
            --keyring "$BINARY_GPG_KEYRING" \
            --verify "$_sig_file" "$_file" >/dev/null 2>&1 || {
            rm -f "$_sig_file"
            return 1
        }
    fi

    rm -f "$_sig_file"
    return 0
}

# Базовый URL загрузки по КОНКРЕТНОМУ тегу (см. коммент в gh_latest).
# ВАЖНО: нужен ПОЛНЫЙ тег, а не версия. gh_latest срезает префикс
# ("app/v2.12.2" -> "2.12.2") для сравнения версий, но в URL загрузки
# префикс обязателен: .../download/v2.12.2/... отдаёт 404, а
# .../download/app/v2.12.2/... — 200. Поэтому тег читается отдельно.
gh_raw_tag() {
    _grt_repo="$1"
    _grt_tmp="$(mktemp /tmp/ghrtag.XXXXXX)" || return 1
    if dl_file \
        "https://api.github.com/repos/${_grt_repo}/releases?per_page=10" \
        "$_grt_tmp" >/dev/null 2>&1
    then
        tr '{' '\n' < "$_grt_tmp" \
            | grep '"tag_name"' \
            | grep -v '"draft": *true' \
            | head -1 \
            | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
    rm -f "$_grt_tmp"
}

gh_dl_base() {
    _gdb_repo="$1"
    _gdb_tag="$(gh_raw_tag "$_gdb_repo" 2>/dev/null || true)"
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
    _url="$(gh_dl_base "$XRAY_REPO")/${_asset}"
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

# ── Выбор источника: GitHub или Entware ─────────────────────────────
norm_version() {
    printf '%s' "${1:-}" | sed 's|.*/||; s/^[vV]//; s/-.*$//; s/[[:space:]]*$//'
}

# 0, если $1 строго новее $2 (покомпонентно, числами).
version_gt() {
    _a="$(norm_version "${1:-}")"
    _b="$(norm_version "${2:-}")"
    [ -n "$_a" ] || return 1
    [ -n "$_b" ] || return 0
    [ "$_a" != "$_b" ] || return 1

    _i=1
    while [ "$_i" -le 4 ]; do
        _pa="$(printf '%s' "$_a" | cut -d. -f"$_i")"
        _pb="$(printf '%s' "$_b" | cut -d. -f"$_i")"
        case "$_pa" in ''|*[!0-9]*) _pa=0 ;; esac
        case "$_pb" in ''|*[!0-9]*) _pb=0 ;; esac
        [ "$_pa" -gt "$_pb" ] && return 0
        [ "$_pa" -lt "$_pb" ] && return 1
        _i=$((_i + 1))
    done
    return 1
}

# В этом скрипте есть только dl_file (пишет в файл), функции dl_json
# нет — используем временный файл.
gh_latest() {
    _repo="$1"
    _tmp="$(mktemp /tmp/ghver.XXXXXX)" || return 1
    # НЕ /releases/latest: XTLS помечает новые релизы как prerelease,
    # и "latest" отдаёт застрявшую версию (v26.3.27, go1.26.1), рантайм
    # которой падает на MIPS с futexwakeup ... -89 / SIGSEGV.
    # Берём первый не-draft релиз из общего списка.
    if dl_file \
        "https://api.github.com/repos/${_repo}/releases?per_page=10" \
        "$_tmp" >/dev/null 2>&1
    then
        tr '{' '\n' < "$_tmp" \
            | grep '"tag_name"' \
            | grep -v '"draft": *true' \
            | head -1 \
            | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
            | sed 's|.*/||; s/^[vV]//'
    fi
    rm -f "$_tmp"
}

opkg_repo_version() {
    opkg info "$1" 2>/dev/null \
        | awk '$1=="Version:" {print $2; exit}' || true
}

# Если сборка с GitHub доступна для этой архитектуры, сравниваем её с
# версией в Entware и берём более свежую. Релизы XTLS выходят раньше,
# чем пакет появляется в репозитории, поэтому обычно побеждает GitHub.
choose_xray_source() {
    [ "$XRAY_SOURCE" = "github" ] || return 0
    [ -n "$XRAY_FILE" ] || return 0

    _gh="$(gh_latest "$XRAY_REPO" || true)"
    opkg update >/dev/null 2>&1 || true
    _op="$(opkg_repo_version xray || true)"

    if [ -z "$_gh" ]; then
        # GitHub недоступен — работаем с тем, что есть в Entware.
        [ -n "$_op" ] && XRAY_SOURCE="opkg"
        return 0
    fi

    if [ -n "$_op" ] && ! version_gt "$_gh" "$_op"; then
        echo "   Entware ($_op) не старее GitHub ($_gh) — берём opkg"
        XRAY_SOURCE="opkg"
    else
        echo "   GitHub ($_gh) новее Entware (${_op:-нет пакета})"
    fi
}

restore_xray_state() {
    stop_xray
    if [ "${XRAY_OLD_BIN_OK:-0}" = "1" ]; then
        cp -f "$XRAY_OLD_BIN" /opt/sbin/xray 2>/dev/null || true
        chmod +x /opt/sbin/xray 2>/dev/null || true
    fi
    if [ "${XRAY_OLD_CFG_OK:-0}" = "1" ]; then
        cp -f "$XRAY_OLD_CFG" /opt/etc/xray/config.json 2>/dev/null || true
    fi
    start_xray >/dev/null 2>&1 || true
    wait_service_ready xray "$PORT_VLESS" tcp || true
}

restore_hysteria_state() {
    stop_hysteria
    if [ "${HY_OLD_BIN_OK:-0}" = "1" ]; then
        cp -f "$HY_OLD_BIN" /opt/sbin/hysteria 2>/dev/null || true
        chmod +x /opt/sbin/hysteria 2>/dev/null || true
    fi
    if [ "${HY_OLD_CFG_OK:-0}" = "1" ]; then
        cp -f "$HY_OLD_CFG" /opt/etc/hysteria/config.json 2>/dev/null || true
    fi
    start_hysteria >/dev/null 2>&1 || true
    wait_service_ready hysteria "$PORT_HYSTERIA" udp || true
}

restore_package_inits() {
    [ -n "$OPKG_INIT_STAGE" ] || return 0
    _rpi_rc=0
    for _rpi_f in "$OPKG_INIT_STAGE"/S*; do
        [ -f "$_rpi_f" ] || continue
        cp -p "$_rpi_f" "/opt/etc/init.d/${_rpi_f##*/}" || _rpi_rc=1
    done
    if [ "$_rpi_rc" -eq 0 ]; then
        rm -rf "$OPKG_INIT_STAGE"
        OPKG_INIT_STAGE=""
    fi
    return "$_rpi_rc"
}

opkg_preserve_inits() {
    OPKG_INIT_STAGE="$(mktemp -d /tmp/keenzoo.opkg-init.XXXXXX)" || return 1
    for _opi_name in S24xray S22trojan S35tor S56dnsmasq S57hysteria S65shadowsocks; do
        if [ -f "/opt/etc/init.d/$_opi_name" ]; then
            cp -p "/opt/etc/init.d/$_opi_name" "$OPKG_INIT_STAGE/$_opi_name" || return 1
        fi
    done
    _opi_rc=0
    opkg "$@" || _opi_rc=$?
    restore_package_inits || _opi_rc=1
    return "$_opi_rc"
}

update_xray() {
    choose_xray_source
    XRAY_OLD_BIN="$(mktemp /tmp/xray.rollback.XXXXXX)"
    XRAY_OLD_CFG="$(mktemp /tmp/xray.config.rollback.XXXXXX)"
    XRAY_OLD_BIN_OK=0
    XRAY_OLD_CFG_OK=0
    if [ -f /opt/sbin/xray ]; then
        cp -f /opt/sbin/xray "$XRAY_OLD_BIN" || {
            echo "❌ xray: не удалось создать rollback-копию бинарника"
            rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
            return 1
        }
        XRAY_OLD_BIN_OK=1
    fi
    if [ -f /opt/etc/xray/config.json ]; then
        cp -f /opt/etc/xray/config.json "$XRAY_OLD_CFG" || {
            echo "❌ xray: не удалось создать rollback-копию config"
            rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
            return 1
        }
        XRAY_OLD_CFG_OK=1
    fi

    echo "⏳ xray ($ARCH, $XRAY_SOURCE)..."
    _rc=0

    if [ "$XRAY_SOURCE" = "opkg" ]; then
        # opkg сам заменяет файл, поэтому сервис останавливается перед ним.
        if ! opkg update >/dev/null 2>&1; then
            rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
            echo "❌ opkg update failed"
            return 1
        fi
        stop_xray
        if ! opkg_preserve_inits upgrade xray >/dev/null 2>&1; then
            restore_xray_state
            rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
            echo "❌ opkg upgrade xray failed"
            return 1
        fi
        clean_duplicate_inits
        if xray version >/dev/null 2>&1; then
            echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
        else
            echo "⚠️ opkg xray несовместим, переустановка..."
            opkg_preserve_inits install --force-reinstall xray >/dev/null 2>&1 || _rc=1
            clean_duplicate_inits
            if ! xray version >/dev/null 2>&1; then
                echo "❌ xray: рабочая версия не установлена"
                _rc=1
            fi
        fi
        if ! start_xray || ! wait_service_ready xray "$PORT_VLESS" tcp; then
            echo "❌ xray: post-start check failed, restoring previous state"
            restore_xray_state
            _rc=1
        fi
        rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
        return "$_rc"
    fi

    if [ "$XRAY_SOURCE" = "github" ] && [ -n "$XRAY_FILE" ]; then
        TMP_ZIP="$(mktemp /tmp/xray.zip.XXXXXX)"
        TMP_DGST="$(mktemp /tmp/xray.dgst.XXXXXX)"
        TMP_DIR="$(mktemp -d /tmp/xray.XXXXXX)"
        DEST_TMP="/opt/sbin/xray.new.$$"

        # ── Фаза 1: скачивание и проверка при РАБОТАЮЩЕМ сервисе ──
        # Сеть нужна именно здесь, поэтому xray не останавливается:
        # обрыв связи или неверная контрольная сумма не приводят
        # к простою прокси.
        _ready=0
        if download_verified_xray_zip "$XRAY_FILE" "$TMP_ZIP" "$TMP_DGST"; then
            if unzip -o "$TMP_ZIP" xray -d "$TMP_DIR" >/dev/null 2>&1 \
                && [ -f "$TMP_DIR/xray" ]
            then
                cp "$TMP_DIR/xray" "$DEST_TMP"
                chmod +x "$DEST_TMP"
                # Работоспособность проверяется до остановки сервиса.
                if "$DEST_TMP" version >/dev/null 2>&1; then
                    _ready=1
                else
                    echo "⚠️ Сборка GitHub нерабочая, откат на opkg..."
                fi
            else
                echo "❌ xray: распаковка архива не удалась"
                _rc=1
            fi
        else
            echo "❌ xray: скачивание или проверка контрольной суммы не пройдены"
            _rc=1
        fi

        # ── Фаза 2: замена файла ──
        # Сервис останавливается только когда новый бинарник уже
        # скачан, проверен по SHA256 и успешно запустился.
        if [ "$_ready" = "1" ]; then
            stop_xray
            mv -f "$DEST_TMP" /opt/sbin/xray
            echo "✅ xray GitHub: $(/opt/sbin/xray version 2>/dev/null | head -1 | awk '{print $2}')"
            if ! start_xray || ! wait_service_ready xray "$PORT_VLESS" tcp; then
                echo "❌ xray: post-start check failed, restoring previous state"
                restore_xray_state
                _rc=1
            fi
        elif [ "$_rc" = "0" ]; then
            # Скачали, но бинарник не запустился — ставим из opkg.
            rm -f "$DEST_TMP"
            stop_xray
            opkg_preserve_inits install --force-reinstall xray >/dev/null 2>&1 || _rc=1
            clean_duplicate_inits
            if xray version >/dev/null 2>&1; then
                echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
            else
                echo "❌ xray: рабочая версия не установлена"
                _rc=1
            fi
            if ! start_xray || ! wait_service_ready xray "$PORT_VLESS" tcp; then
                echo "❌ xray: opkg fallback post-start check failed, restoring previous state"
                restore_xray_state
                _rc=1
            fi
        fi
        # При ошибке скачивания сервис вообще не трогали — он работает.

        rm -rf "$TMP_DIR"
        rm -f "$TMP_ZIP" "$TMP_DGST" "$DEST_TMP"
    fi

    rm -f "$XRAY_OLD_BIN" "$XRAY_OLD_CFG"
    return "$_rc"
}

update_hysteria() {
    HY_OLD_BIN="$(mktemp /tmp/hysteria.rollback.XXXXXX)"
    HY_OLD_CFG="$(mktemp /tmp/hysteria.config.rollback.XXXXXX)"
    HY_OLD_BIN_OK=0
    HY_OLD_CFG_OK=0
    if [ -f /opt/sbin/hysteria ]; then
        cp -f /opt/sbin/hysteria "$HY_OLD_BIN" || {
            echo "❌ hysteria: не удалось создать rollback-копию бинарника"
            rm -f "$HY_OLD_BIN" "$HY_OLD_CFG"
            return 1
        }
        HY_OLD_BIN_OK=1
    fi
    if [ -f /opt/etc/hysteria/config.json ]; then
        cp -f /opt/etc/hysteria/config.json "$HY_OLD_CFG" || {
            echo "❌ hysteria: не удалось создать rollback-копию config"
            rm -f "$HY_OLD_BIN" "$HY_OLD_CFG"
            return 1
        }
        HY_OLD_CFG_OK=1
    fi
    echo "⏳ hysteria ($ARCH)..."

    if [ -z "$HY_FILE" ]; then
        echo "❌ hysteria: архитектура $ARCH не поддерживается"
        # dns4.2.28 (внешний отчёт, P-03): копия бинарника (~21 МБ)
        # лежит в tmpfs (ОЗУ роутера) — ранний выход обязан её убрать,
        # как это сделано на остальных выходах и в update_xray.
        rm -f "$HY_OLD_BIN" "$HY_OLD_CFG"
        return 1
    fi
    if [ -z "$DL" ]; then
        echo "❌ hysteria: нет curl/wget"
        rm -f "$HY_OLD_BIN" "$HY_OLD_CFG"
        return 1
    fi

    TMP_BIN="$(mktemp /tmp/hysteria.bin.XXXXXX)"
    TMP_HASHES="$(mktemp /tmp/hysteria.hashes.XXXXXX)"
    DEST_TMP="/opt/sbin/hysteria.new.$$"

    _hy_rc=0

    # ── Фаза 1: скачивание и проверка при РАБОТАЮЩЕМ сервисе ──
    # Пока идёт загрузка и сверка SHA256, hysteria продолжает
    # обслуживать трафик. Резервная копия рабочего бинарника больше
    # не нужна: он остаётся на месте до самого момента замены.
    _ready=0
    if download_verified_hysteria_bin "$HY_FILE" "$TMP_BIN" "$TMP_HASHES"
    then
        cp "$TMP_BIN" "$DEST_TMP"
        chmod +x "$DEST_TMP"
        # Проверка запуска до остановки сервиса.
        if "$DEST_TMP" version >/dev/null 2>&1; then
            _ready=1
        else
            echo "❌ hysteria: бинарник несовместим, обновление отменено"
            _hy_rc=1
        fi
    else
        echo "❌ hysteria: скачивание или проверка контрольной суммы не пройдены"
        _hy_rc=1
    fi

    # ── Фаза 2: замена файла ──
    # Останавливаем только при готовом проверенном бинарнике.
    if [ "$_ready" = "1" ]; then
        stop_hysteria
        mv -f "$DEST_TMP" /opt/sbin/hysteria
        echo "✅ hysteria: $(hysteria version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        if ! start_hysteria || ! wait_service_ready hysteria "$PORT_HYSTERIA" udp; then
            echo "❌ hysteria: post-start check failed, restoring previous state"
            restore_hysteria_state
            _hy_rc=1
        fi
    fi
    # При любой ошибке сервис не останавливался — старая версия работает.

    rm -f "$TMP_BIN" "$TMP_HASHES" "$DEST_TMP"
    rm -f "$HY_OLD_BIN" "$HY_OLD_CFG"
    return "$_hy_rc"
}

# Пакеты Entware кладут собственные init-скрипты, которые дублируют
# наши: shadowsocks-libev-ss-redir ставит S22shadowsocks, тогда как
# проект работает через S65shadowsocks (свой конфиг, ключ -u для UDP).
# После КАЖДОГО opkg upgrade файл возвращается на место, поэтому чистка
# нужна именно здесь, а не только в деплое: иначе два экземпляра
# ss-redir конкурируют за порт 1082 и обход отваливается непредсказуемо.
drop_duplicate_init() {
    _dup="/opt/etc/init.d/$1"
    _keep="/opt/etc/init.d/$2"

    [ -f "$_dup" ] || return 0
    [ -f "$_keep" ] || return 0

    "$_dup" stop >/dev/null 2>&1 || true
    rm -f "$_dup"
    echo "  ♻️  удалён дублирующий $1 (используется $2)"
}

# Если имя пакетного init-скрипта СОВПАДАЕТ с нашим, дубля не будет —
# opkg просто перезапишет файл своей версией. Дубль заметен (два процесса),
# а перезапись тиха: сервис поднимется с чужими ARGS. Критичен S24xray:
# наш запускает "run -confdir /opt/etc/xray", стоковый — нет, и весь
# VLESS-обход молча встаёт. Init-скрипты пакетов не conffiles, поэтому
# восстанавливаем свои значения после каждой установки.
restore_init_args() {
    _f="/opt/etc/init.d/$1"
    _procs="$2"
    _args="$3"

    [ -f "$_f" ] || return 0

    # Сравниваем ЗНАЧЕНИЯ, а не текст строки: наши скрипты пишут
    # ARGS="run -confdir /opt/etc/$PROCS", и дословное сличение с
    # "run -confdir /opt/etc/xray" давало ложное расхождение — файл
    # переписывался при каждом запуске, теряя подстановку.
    _cur_procs="$(sed -n 's/^PROCS=//p' "$_f" 2>/dev/null | head -1)"
    _cur_args="$(sed -n 's/^ARGS=//p' "$_f" 2>/dev/null | head -1)"
    # Снимаем обрамляющие кавычки и раскрываем $PROCS/${PROCS}.
    _cur_args="$(echo "$_cur_args" | sed -e 's/^"//' -e 's/"$//' \
        -e "s|\${PROCS}|$_cur_procs|g" -e "s|\$PROCS|$_cur_procs|g")"

    # Уже наш вариант — ничего не делаем (идемпотентность).
    if [ "$_cur_procs" = "$_procs" ] && [ "$_cur_args" = "$_args" ]; then
        return 0
    fi

    "$_f" stop >/dev/null 2>&1 || true
    # Правим только две строки, остальное (guard'ы пакета) сохраняем.
    # XXXXXX строго в конце шаблона — требование BusyBox mktemp.
    _tmp="$(mktemp /tmp/init.XXXXXX)" || return 0
    sed -e "s|^PROCS=.*|PROCS=$_procs|" \
        -e "s|^ARGS=.*|ARGS=\"$_args\"|" "$_f" > "$_tmp" 2>/dev/null \
        && cat "$_tmp" > "$_f"
    rm -f "$_tmp"
    chmod 755 "$_f" 2>/dev/null || true
    echo "  ♻️  восстановлены параметры запуска $1"
}

# Снимает дубли, появившиеся после установки пакетов.
clean_duplicate_inits() {
    drop_duplicate_init S23hysteria    S57hysteria
    drop_duplicate_init S22shadowsocks S65shadowsocks

    restore_init_args S24xray    xray "run -confdir /opt/etc/xray"
    restore_init_args S35tor     tor  "-f /opt/etc/tor/torrc"
    restore_init_args S22trojan  trojan "-c /opt/etc/trojan/config.json"
    restore_init_args S56dnsmasq dnsmasq ""
}

update_opkg() {
    echo "⏳ opkg..."
    _opkg_rc=0
    opkg update >/dev/null 2>&1 || { echo "❌ opkg update failed"; return 1; }
    for pkg in shadowsocks-libev-ss-redir trojan tor dnsmasq-full; do
        avail="$(opkg list-upgradable 2>/dev/null | grep "^${pkg} " || true)"
        if [ -n "$avail" ]; then
            echo "  ⏳ $pkg..."
            if opkg_preserve_inits upgrade "$pkg" >/dev/null 2>&1; then
                echo "  ✅ $pkg"
                # Пакет мог вернуть свой init-скрипт — убираем сразу,
                # пока сервис не успел подняться вторым экземпляром.
                clean_duplicate_inits
            else
                echo "  ❌ $pkg: ошибка обновления"
                _opkg_rc=1
            fi
        fi
    done
    if [ "$_opkg_rc" -eq 0 ]; then
        echo "✅ opkg"
    fi
    return "$_opkg_rc"
}

# Итоговый код возврата определяется результатом операций, а не наличием
# символа "❌" в выводе (вызывающий код в боте ориентируется на exit code).
RC=0

case "$ACTION" in
    xray)
        update_xray || RC=1
        ;;
    hysteria)
        update_hysteria || RC=1
        ;;
    github)
        update_xray || RC=1
        update_hysteria || RC=1
        ;;
    opkg)
        update_opkg || RC=1
        ;;
    all)
        update_xray || RC=1
        update_hysteria || RC=1
        update_opkg || RC=1
        ;;
    *)
        echo "Использование:"
        echo "  $0 {xray|hysteria|github|opkg|all}"
        exit 2
        ;;
esac

[ -x /opt/bin/check_updates.sh ] && /opt/bin/check_updates.sh >/dev/null 2>&1 || true

exit "$RC"
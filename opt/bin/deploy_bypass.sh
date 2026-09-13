#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

# Деплой импортирует bot_config для проверки конфигурации, а это создаёт
# __pycache__ в /opt/etc/bot от имени root — потом он подменял правленый
# модуль. Кэш байткода на USB-накопителе не нужен: модули читаются один
# раз за старт сервиса.
export PYTHONDONTWRITEBYTECODE=1

echo "════════════════════════════════════"
echo "  Разворачивание проекта"
echo "════════════════════════════════════"

ARCHIVE="${1:-}"
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
    return 1
}

warn() {
    printf '%s\n' "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

if [ -z "$ARCHIVE" ]; then
    echo "Использование:"
    echo "  $0 /tmp/bypass_project.tar.gz"
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
        _de_b="$(od -An -tu1 -j5 -N1 "$_de_probe" 2>/dev/null | tr -d ' ')"
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

    # Значение по умолчанию: подавляющее большинство Keenetic на MIPS —
    # little-endian (mipsel).
    printf 'le\n'
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
        ENTWARE_ARCH="armv7sf-k3.2"
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
        if [ "$(detect_endian)" = "be" ]; then
            # Big-endian MIPS: сборок Hysteria под него не выпускают.
            ENTWARE_ARCH="mipssf-k3.4"
            HY_FILE=""
            XRAY_SOURCE="github"
            XRAY_FILE="Xray-linux-mips32.zip"
            echo "ℹ️ MIPS big-endian: Hysteria2 недоступна (нет сборок)"
        else
            ENTWARE_ARCH="mipselsf-k3.4"
            # Entware — soft-float, поэтому именно вариант "-sf".
            HY_FILE="hysteria-linux-mipsle-sf"
            XRAY_SOURCE="github"
            XRAY_FILE="Xray-linux-mips32le.zip"
        fi
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
    if have_cmd nslookup; then
        nslookup github.com >/dev/null 2>&1 && return 0
        return 1
    fi
    if have_cmd dig; then
        [ -n "$(dig +short +time=3 +tries=1 github.com 2>/dev/null)" ] \
            && return 0
        return 1
    fi
    # Ни одной утилиты — не мешаем, пусть решает сам загрузчик.
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
    # BusyBox awk НЕ поддерживает IGNORECASE (это расширение gawk), поэтому
    # прежний вариант с BEGIN{IGNORECASE=1} не находил строку вообще и
    # проверка контрольной суммы молча срывалась. Ищем строго "SHA2-256",
    # чтобы не поймать SHA2-512, и берём последнее поле.
    _dgst_file="$1"
    awk '/^[Ss][Hh][Aa]2?-?256[[:space:]]*=/ {
             gsub(/[[:space:]]/, "", $NF); print $NF; exit
         }' "$_dgst_file"
}

extract_hysteria_sha256() {
    # Формат hashes.txt у Hysteria:
    #   <sha256>  build/hysteria-linux-mipsle-sf
    # Имя идёт с префиксом каталога, поэтому точное сравнение "$NF == asset"
    # не срабатывало никогда. Сравниваем по basename.
    _hashes_file="$1"
    _asset_name="$2"
    awk -v asset="$_asset_name" '
        {
            n = $NF
            sub(/^.*\//, "", n)
            if (n == asset) { print $1; exit }
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
    if [ -x "/opt/etc/init.d/$_svc" ]; then
        "/opt/etc/init.d/$_svc" start >/dev/null 2>&1 || true
    fi
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
    S99telegram_bot S24xray \
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
if tar tzf "$ARCHIVE" 2>/dev/null | grep -qvE '^(\./)?(opt/|opt$|$)'; then
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

cd /
if tar xzf "$ARCHIVE" >/dev/null 2>&1; then
    echo "✅ Архив"
else
    echo "❌ Ошибка распаковки архива"
    exit 1
fi

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

                        # Сверяем с официальной контрольной суммой.
                        # "|| true" обязателен: sha256_of_file возвращает
                        # 1, если в системе нет ни sha256sum, ни openssl,
                        # а скрипт работает под set -e — присваивание из
                        # $(...) с ненулевым кодом обрывает ВЕСЬ деплой
                        # (проверено запуском в dash и busybox ash).
                        # Пустая сумма ниже трактуется как "сверить не с
                        # чем" и обрабатывается штатной веткой.
                        _hw_sum="$(sha256_of_file \
                            "$TMP_IDIR/opt/sbin/hysteria" || true)"
                        _hw_exp="$(extract_hysteria_sha256 \
                            "$TMP_HASHES" "$HY_FILE" 2>/dev/null)"

                        if [ -z "$_hw_exp" ] || \
                            [ "$_hw_sum" = "$_hw_exp" ]; then
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
print("%s %s %s" % (
    "ok" if getattr(c, 'token', '') else "empty",
    "ok" if getattr(c, 'allowed_user_ids', []) else "empty",
    "ok" if getattr(c, 'web_password', '') else "empty"))
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
    [ "${1:-empty}" = "ok" ] || { warn "⚠️ token не задан"; NEED_CONFIG=1; }
    [ "${2:-empty}" = "ok" ] || { warn "⚠️ allowed_user_ids пуст"; NEED_CONFIG=1; }
    [ "${3:-empty}" = "ok" ] || { warn "⚠️ web_password пуст"; NEED_CONFIG=1; }
fi
rm -f "$CFG_ERR"
[ "$NEED_CONFIG" -eq 0 ] && echo "✅ Секреты заданы"

echo ""
echo "⏳ [10/11] Запуск..."
# dnsmasq работал во время скачивания (чтобы не потерять DNS), но конфиг
# на шаге 9 мог измениться — поэтому именно ПЕРЕзапуск, а не start.
safe_stop_service "S56dnsmasq"
safe_start_service "S56dnsmasq"
safe_start_service "S24xray"
safe_start_service "S65shadowsocks"
safe_start_service "S35tor"
safe_start_service "S22trojan"
safe_start_service "S57hysteria"

# Наборы ipset должны существовать до применения правил netfilter,
# иначе правила с --match-set не добавятся.
if [ -x /opt/etc/ndm/fs.d/100-ipset.sh ]; then
    /opt/etc/ndm/fs.d/100-ipset.sh >/dev/null 2>&1 || true
fi
safe_start_service "S99unblock"

# Списки наполняются синхронно: правила ниже и проверка в конце должны
# видеть готовые наборы. Прежде запуск уходил в фон, и деплой рапортовал
# об успехе, когда наборы были ещё пусты.
if [ -x /opt/bin/unblock_update.sh ]; then
    echo "   Наполнение списков (до нескольких минут)..."
    if /opt/bin/unblock_update.sh >/dev/null 2>&1; then
        echo "✅ Списки обновлены"
    else
        warn "⚠️ unblock_update.sh вернул ошибку"
    fi
fi

# Перезапуск строго после появления конфигов: xray обязан стартовать
# заново, иначе не проставит sockopt.mark и собственный исходящий трафик
# завернётся в его же inbound (петля).
safe_stop_service "S24xray"
safe_start_service "S24xray"

# Правила перехвата применяются для обеих таблиц: nat (TCP/DNS) и
# mangle (UDP через TPROXY).
if [ -x /opt/etc/ndm/netfilter.d/100-redirect.sh ]; then
    type=iptable table=nat \
        /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    # mangle отвечает за TPROXY (UDP в туннель). Вывод сохраняется:
    # при ошибке нужна конкретная причина, а не молчание.
    RD_LOG="$(mktemp /tmp/redirect.XXXXXX)"
    type=iptable table=mangle \
        /opt/etc/ndm/netfilter.d/100-redirect.sh >"$RD_LOG" 2>&1 || true
    # filter — правила доступа к веб-панели (порт 8080 только из LAN).
    type=iptable table=filter \
        /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    # IPv6: xray слушает dual-stack (:::10810), правила iptables на него
    # не действуют — закрываем порты отдельно через ip6tables.
    type=ip6tables table=filter \
        /opt/etc/ndm/netfilter.d/100-redirect.sh >/dev/null 2>&1 || true
    # Проверяем результат сразу, пока известна причина.
    TP_NOW="$($IPT_BIN -t mangle -S PREROUTING 2>/dev/null \
        | grep -c 'TPROXY' 2>/dev/null || true)"
    if [ "${TP_NOW:-0}" -gt 0 ] 2>/dev/null; then
        echo "✅ Правила netfilter применены (TPROXY: ${TP_NOW})"
    else
        warn "⚠️ Правила применены, но TPROXY не создан"
        [ -s "$RD_LOG" ] && sed 's/^/     /' "$RD_LOG" | head -8 >&2
        warn "     Подробности: tail -20 /opt/var/log/100-redirect.log"
    fi
    rm -f "$RD_LOG"
fi

safe_start_service "S99telegram_bot"
safe_start_service "S99generator"

echo "✅ Запущены"

echo ""
echo "⏳ [11/11] DNS Override..."
# Освобождает порт 53 у системного DNS Keenetic, чтобы его занял dnsmasq
# из Entware. Без этого dnsmasq не поднимется на :53 и обход по доменам
# не заработает. Выполняется ДО финальной перезагрузки и результат
# проверяется: прежде команда шла с "|| true" и молча проглатывала отказ.
DNS_OVERRIDE_OK=0

if have_cmd ndmc; then
    if ndmc -c "show running-config" 2>/dev/null \
        | grep -q "opkg dns-override"; then
        DNS_OVERRIDE_OK=1
        echo "✅ DNS Override уже включён"
    else
        ndmc -c "opkg dns-override" >/dev/null 2>&1 || true
        sleep 2
        ndmc -c "system configuration save" >/dev/null 2>&1 || true
        sleep 1

        if ndmc -c "show running-config" 2>/dev/null \
            | grep -q "opkg dns-override"; then
            DNS_OVERRIDE_OK=1
            echo "✅ DNS Override включён и сохранён"
        else
            warn "⚠️ Не удалось подтвердить DNS Override."
            warn "   Выполните вручную и проверьте:"
            warn "     ndmc -c \"opkg dns-override\""
            warn "     ndmc -c \"system configuration save\""
            warn "     ndmc -c \"show running-config\" | grep dns-override"
        fi
    fi
else
    warn "⚠️ ndmc не найден — DNS Override не настроен."
    warn "   Порт 53 может остаться занят системным DNS Keenetic."
fi

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
    pid="$(pidof "$svc" 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        echo "    ✅ $svc"
        continue
    fi

    # Служба не поднялась. Причины различаются, и молчаливое "—"
    # не позволяет понять, что делать.
    # Служба установлена, но без ключа стартовать не может — это
    # штатное состояние после установки с нуля, а не ошибка.
    # Подсказка объясняет, что делать дальше.
    need_key_msg() {
        echo "    ⏸ $1 — успешно установлен."
        echo "         Добавьте ключ $2, чтобы запустить:"
        echo "         бот: меню «$3»"
        echo "         панель: http://${LAN_IP}:8080"
        echo "         вкладка «$4»"
    }

    # Ключ есть, но служба всё равно не поднялась — вот это ошибка.
    failed_msg() {
        echo "    ❌ $1 — установлен, ключ задан, но не запустился."
        echo "         Проверьте: $2"
        echo "         Логи: logread | grep $1"
    }

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
printf "    xray:     "
xray version 2>/dev/null | head -1 | awk '{print $2}' || echo "N/A"
printf "    hysteria: "
hysteria version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "N/A"

echo ""
echo "  Python:"
python3 -c "
import flask, telebot
print('    flask:', flask.__version__)
print('    telebot: OK')
" 2>/dev/null || echo "    ❌ Нет модулей"

echo ""
echo "  Бот:"
if ps | grep -q "python3.*main.py"; then
    echo "    ✅ Запущен"
else
    echo "    — Не запущен"
fi
if ps | grep -q "python3.*generator.py"; then
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

echo "  Веб-панель: http://${LAN_IP}:8080 (admin, только из LAN)"
WEB_ACC="$($IPT_BIN -S INPUT 2>/dev/null \
    | grep -c -- '--dport 8080 -j ACCEPT' 2>/dev/null || true)"
WEB_ACC="${WEB_ACC:-0}"
if [ "$WEB_ACC" -gt 0 ] 2>/dev/null; then
    echo "    ✅ Доступ из LAN разрешён ($WEB_ACC правил)"
else
    warn "    ⚠️ Нет разрешающих правил для порта 8080"
    warn "       Выполните: type=iptable table=filter \\"
    warn "         /opt/etc/ndm/netfilter.d/100-redirect.sh"
fi

# Панель обязана СЛУШАТЬ порт: connection refused означает, что процесс
# не запущен, и правила firewall тут ни при чём.
if netstat -ltn 2>/dev/null | grep -q ":8080 " \
    || ss -ltn 2>/dev/null | grep -q ":8080 "; then
    echo "    ✅ Порт 8080 слушается"
else
    warn "    ⚠️ Порт 8080 НЕ слушается — панель не запущена"
    warn "       Причина будет видна в логе:"
    warn "         tail -40 /opt/etc/bot/generator.log"
    warn "         /opt/etc/init.d/S99generator restart"
fi

# Резолвинг для процессов самого роутера (бот, curl, check_updates).
# При включённом dns-override прошивочный резолвер отключён, и если
# /etc/resolv.conf не указывает на локальный dnsmasq, процессы получают
# "Temporary failure in name resolution" — именно из-за этого падал
# телеграм-бот с ошибкой на api.telegram.org.
if ! dns_ok; then
    warn "    ⚠️ Роутер не резолвит имена — бот работать не сможет"
    if [ -w /etc/resolv.conf ] || [ ! -e /etc/resolv.conf ]; then
        if ! grep -q '^nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null
        then
            printf 'nameserver 127.0.0.1\n' >> /etc/resolv.conf \
                2>/dev/null || true
            warn "       Добавлен nameserver 127.0.0.1"
        fi
    fi
    if dns_ok; then
        echo "    ✅ Резолвинг восстановлен"
    else
        warn "       Проверьте: cat /etc/resolv.conf"
        warn "       и: nslookup api.telegram.org 127.0.0.1"
    fi
else
    echo "    ✅ Резолвинг на роутере работает"
fi

# Прокси-порты не должны быть доступны из внешней сети.
PROXY_DROP=0
for _pp in 1082 9141 10810 10829 10830; do
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

# IPv6: xray слушает dual-stack, поэтому нужны отдельные правила.
if command -v ip6tables >/dev/null 2>&1; then
    V6_DROP="$(ip6tables -w -S INPUT 2>/dev/null \
        | grep -c -- '--dport 10810 -j DROP' || true)"
    if [ "${V6_DROP:-0}" -gt 0 ] 2>/dev/null; then
        echo "    ✅ IPv6: прокси-порты закрыты"
    else
        warn "    ⚠️ IPv6: правила не применены"
        warn "       type=ip6tables table=filter \\"
        warn "         /opt/etc/ndm/netfilter.d/100-redirect.sh"
    fi
fi

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
echo "  ⚠️ Завершите установку перезагрузкой: reboot"
echo ""
echo "  🔴 Отзовите и перевыпустите секреты из репозитория"
echo "     (токен @BotFather /revoke, ключи VLESS/Trojan/Hysteria)."
echo ""
echo "════════════════════════════════════"
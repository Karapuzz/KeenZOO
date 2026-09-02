#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

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

ARCH="$(uname -m)"
KERNEL="$(uname -r | cut -d. -f1-2)"

echo "Архитектура: $ARCH"
echo "Ядро: $(uname -r)"

case "$ARCH" in
    aarch64)
        HY_FILE="hysteria-linux-arm64"
        case "$KERNEL" in
            3.*|4.*)
                XRAY_SOURCE="opkg"
                XRAY_FILE=""
                echo "⚠️ Ядро $KERNEL: xray из opkg"
                ;;
            *)
                XRAY_SOURCE="github"
                XRAY_FILE="Xray-linux-arm64-v8a.zip"
                ;;
        esac
        ;;
    mips|mipsel)
        HY_FILE="hysteria-linux-mipsle"
        XRAY_SOURCE="opkg"
        XRAY_FILE=""
        echo "ℹ️ mips: xray из opkg (Entware)"
        ;;
    *)
        echo "⚠️ Архитектура $ARCH"
        HY_FILE=""
        XRAY_SOURCE="opkg"
        XRAY_FILE=""
        ;;
esac

DL_CMD=""
if have_cmd curl; then
    DL_CMD="curl"
elif have_cmd wget; then
    DL_CMD="wget"
fi

dl_file() {
    _url="$1"
    _out="$2"

    if [ "$DL_CMD" = "curl" ]; then
        curl -fsSL --connect-timeout 20 --max-time 180 \
            -o "$_out" "$_url"
    elif [ "$DL_CMD" = "wget" ]; then
        wget -q --https-only --timeout=180 \
            -O "$_out" "$_url"
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
    else
        return 1
    fi
}

extract_xray_sha256() {
    _dgst_file="$1"
    awk 'BEGIN{IGNORECASE=1}
         /sha(2|-)?256/ {print $NF; exit}' "$_dgst_file"
}

extract_hysteria_sha256() {
    _hashes_file="$1"
    _asset_name="$2"
    awk -v asset="$_asset_name" '$NF == asset {print $1; exit}' "$_hashes_file"
}

verify_sha256() {
    _file="$1"
    _expected="$2"

    _actual="$(sha256_of_file "$_file" 2>/dev/null || true)"
    [ -n "$_actual" ] || return 1
    [ "$_actual" = "$_expected" ]
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

    _sig_file="$(mktemp "/tmp/${_name}.XXXXXX.asc")"
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

download_verified_xray_zip() {
    _asset="$1"
    _zip_file="$2"
    _dgst_file="$3"
    _url="https://github.com/${XRAY_REPO}/releases/latest/download/${_asset}"
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
    _url="https://github.com/${HY_REPO}/releases/latest/download/${_asset}"
    _hashes_url="https://github.com/${HY_REPO}/releases/latest/download/hashes.txt"

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

echo ""
echo "⏳ [1/9] Пакеты..."
opkg update >/dev/null 2>&1 || true

if [ -z "$DL_CMD" ]; then
    opkg install curl >/dev/null 2>&1 || true
    if have_cmd curl; then
        DL_CMD="curl"
    else
        opkg install wget-ssl >/dev/null 2>&1 || true
        if have_cmd wget; then
            DL_CMD="wget"
        fi
    fi
fi

FAILED=""
for pkg in \
    tor tor-geoip bind-dig cron \
    dnsmasq-full ipset iptables \
    obfs4 webtunnel-client \
    shadowsocks-libev-ss-redir \
    shadowsocks-libev-config \
    xray trojan coreutils-split unzip \
    python3-pip python3-requests
do
    if ! opkg install "$pkg" >/dev/null 2>&1; then
        FAILED="${FAILED} ${pkg}"
    fi
done

if have_cmd pip3; then
    pip3 install --no-deps pyTelegramBotAPI >/dev/null 2>&1 || true
    pip3 install flask >/dev/null 2>&1 || true
else
    python3 -m ensurepip >/dev/null 2>&1 || true
    if have_cmd pip3; then
        pip3 install --no-deps pyTelegramBotAPI >/dev/null 2>&1 || true
        pip3 install flask >/dev/null 2>&1 || true
    else
        FAILED="${FAILED} pip3"
    fi
fi

if ! python3 -c "import flask; import telebot" >/dev/null 2>&1; then
    FAILED="${FAILED} flask/telebot"
fi

if [ -n "$FAILED" ]; then
    echo "⚠️ Нет:${FAILED}"
else
    echo "✅ Пакеты"
fi

echo ""
echo "⏳ [2/9] Остановка..."
for svc in \
    S99telegram_bot S24xray \
    S65shadowsocks S22trojan \
    S23hysteria S35tor S56dnsmasq
do
    safe_stop_service "$svc"
done
killall xray >/dev/null 2>&1 || true
killall -9 xray >/dev/null 2>&1 || true
sleep 2
echo "✅ Остановлены"

echo ""
echo "⏳ [3/9] Директории..."
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
echo "⏳ [4/9] Распаковка..."
cd /
if tar xzf "$ARCHIVE" >/dev/null 2>&1; then
    echo "✅ Архив"
else
    echo "❌ Ошибка!"
    exit 1
fi

find /opt/bin -name "*.sh" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
find /opt/etc/init.d -name "S*" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true
find /opt/etc/ndm -name "*.sh" \
    -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

echo ""
echo "⏳ [5/9] xray ($XRAY_SOURCE)..."
if [ "$XRAY_SOURCE" = "opkg" ]; then
    opkg install --force-reinstall xray >/dev/null 2>&1 || true
    if xray version >/dev/null 2>&1; then
        echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
    else
        echo "❌ xray из opkg не работает"
    fi
elif [ "$XRAY_SOURCE" = "github" ] && [ -n "$XRAY_FILE" ] && [ -n "$DL_CMD" ]; then
    TMP_ZIP="$(mktemp /tmp/xray.XXXXXX.zip)"
    TMP_DGST="$(mktemp /tmp/xray.XXXXXX.dgst)"
    TMP_DIR="$(mktemp -d /tmp/xray.XXXXXX)"
    DEST_TMP="/opt/sbin/xray.new.$$"

    if download_verified_xray_zip "$XRAY_FILE" "$TMP_ZIP" "$TMP_DGST"; then
        if unzip -o "$TMP_ZIP" xray -d "$TMP_DIR" >/dev/null 2>&1 \
            && [ -f "$TMP_DIR/xray" ]; then
            cp "$TMP_DIR/xray" "$DEST_TMP"
            chmod +x "$DEST_TMP"
            mv -f "$DEST_TMP" /opt/sbin/xray

            if xray version >/dev/null 2>&1; then
                echo "✅ xray GitHub: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
            else
                echo "⚠️ GitHub SIGSEGV, opkg..."
                rm -f /opt/sbin/xray
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
    echo "⚠️ Пропущено"
fi

echo ""
echo "⏳ [6/9] hysteria ($ARCH)..."
if [ -n "$HY_FILE" ] && [ -n "$DL_CMD" ]; then
    TMP_BIN="$(mktemp /tmp/hysteria.XXXXXX.bin)"
    TMP_HASHES="$(mktemp /tmp/hysteria.XXXXXX.hashes)"
    DEST_TMP="/opt/sbin/hysteria.new.$$"

    if [ ! -x /opt/sbin/hysteria ]; then
        if download_verified_hysteria_bin "$HY_FILE" "$TMP_BIN" "$TMP_HASHES"; then
            cp "$TMP_BIN" "$DEST_TMP"
            chmod +x "$DEST_TMP"
            mv -f "$DEST_TMP" /opt/sbin/hysteria

            if hysteria version >/dev/null 2>&1; then
                echo "✅ hysteria: $(hysteria version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
            else
                echo "⚠️ Несовместима"
                rm -f /opt/sbin/hysteria
            fi
        else
            echo "⚠️ Скачивание/верификация"
            rm -f /opt/sbin/hysteria
        fi
    else
        echo "✅ hysteria: есть"
    fi

    rm -f "$TMP_BIN" "$TMP_HASHES" "$DEST_TMP"
else
    echo "⚠️ Пропущено"
fi

echo ""
echo "⏳ [7/9] Права..."
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
    /opt/etc/ndm/fs.d/100-ipset.sh
do
    [ -f "$f" ] && chmod +x "$f"
done

for f in /opt/etc/init.d/S*; do
    [ -f "$f" ] && chmod +x "$f"
done

[ -f /opt/sbin/xray ] && chmod +x /opt/sbin/xray
[ -f /opt/sbin/hysteria ] && chmod +x /opt/sbin/hysteria

for f in shadowsocks tor vless trojan hysteria bot; do
    touch "/opt/etc/unblock/${f}.txt"
done

touch /opt/etc/bot/error.log
echo "✅ Права"

echo ""
echo "⏳ [8/9] Запуск..."
safe_start_service "S56dnsmasq"
safe_start_service "S24xray"
safe_start_service "S65shadowsocks"
safe_start_service "S35tor"
safe_start_service "S22trojan"
safe_start_service "S23hysteria"

if [ -x /opt/bin/unblock_update.sh ]; then
    /opt/bin/unblock_update.sh >/dev/null 2>&1 &
fi
safe_start_service "S99telegram_bot"

echo "✅ Запущены"

echo ""
echo "⏳ [9/9] DNS Override..."
ndmc -c "opkg dns-override" 2>/dev/null || true
sleep 2
ndmc -c "system configuration save" 2>/dev/null || true
echo "✅ DNS Override"

echo ""
echo "════════════════════════════════════"
echo "  ✅ Проект развёрнут!"
echo ""
echo "  Архитектура: $ARCH"
echo "  Ядро: $(uname -r)"
echo "  xray источник: $XRAY_SOURCE"
echo ""
echo "  Сервисы:"
for svc in xray ss-redir trojan tor hysteria dnsmasq; do
    pid="$(pidof "$svc" 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        echo "    ✅ $svc"
    else
        echo "    — $svc"
    fi
done
echo ""
echo "  Версии:"
echo -n "    xray:     "
xray version 2>/dev/null | head -1 | awk '{print $2}' || echo "N/A"
echo -n "    hysteria: "
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
echo "  ⚠️ Перезагрузите: reboot"
echo ""
echo "  Если бот не отвечает:"
echo "    vi /opt/etc/bot/bot_config.py"
echo "    /opt/etc/init.d/S99telegram_bot restart"
echo ""
echo "════════════════════════════════════"
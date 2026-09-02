#!/bin/sh
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 022

ACTION="${1:-}"
ARCH="$(uname -m)"
KERNEL="$(uname -r | cut -d. -f1-2)"
XRAY_SOURCE="opkg"
XRAY_FILE=""
HY_FILE=""

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

case "$ARCH" in
    aarch64)
        HY_FILE="hysteria-linux-arm64"
        case "$KERNEL" in
            3.*|4.*)
                XRAY_SOURCE="opkg"
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
        ;;
    *)
        echo "❌ $ARCH"
        exit 1
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

    if [ "$DL" = "curl" ]; then
        curl -fsSL --connect-timeout 20 --max-time 180 \
            -o "$_out" "$_url"
    elif [ "$DL" = "wget" ]; then
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

    [ -n "$_sig_url" ] || return 1
    [ -n "$BINARY_GPG_KEYRING" ] || return 1

    if ! have_cmd gpgv && ! have_cmd gpg; then
        return 1
    fi

    _sig_file="$(mktemp "/tmp/${_name}.XXXXXX.asc")"
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

update_xray() {
    echo "⏳ xray ($ARCH, $XRAY_SOURCE)..."
    [ -x /opt/etc/init.d/S24xray ] && /opt/etc/init.d/S24xray stop 2>/dev/null || true
    killall xray 2>/dev/null || true
    killall -9 xray 2>/dev/null || true
    sleep 2

    if [ "$XRAY_SOURCE" = "opkg" ]; then
        opkg update >/dev/null 2>&1 || true
        opkg upgrade xray >/dev/null 2>&1 || true
        if xray version >/dev/null 2>&1; then
            echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
        else
            echo "⚠️ opkg xray несовместим"
            echo "   Переустановка..."
            opkg install --force-reinstall xray >/dev/null 2>&1 || true
        fi
    elif [ "$XRAY_SOURCE" = "github" ] && [ -n "$XRAY_FILE" ]; then
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
                    echo "⚠️ SIGSEGV, opkg..."
                    rm -f /opt/sbin/xray
                    opkg install --force-reinstall xray >/dev/null 2>&1 || true
                    echo "✅ xray opkg: $(xray version 2>/dev/null | head -1 | awk '{print $2}')"
                fi
            else
                echo "❌ Распаковка/верификация"
            fi
        else
            echo "❌ Скачивание/верификация"
        fi

        rm -rf "$TMP_DIR"
        rm -f "$TMP_ZIP" "$TMP_DGST" "$DEST_TMP"
    fi

    [ -x /opt/etc/init.d/S24xray ] && /opt/etc/init.d/S24xray start || true
}

update_hysteria() {
    echo "⏳ hysteria ($ARCH)..."
    [ -x /opt/etc/init.d/S23hysteria ] && /opt/etc/init.d/S23hysteria stop 2>/dev/null || true

    TMP_BIN="$(mktemp /tmp/hysteria.XXXXXX.bin)"
    TMP_HASHES="$(mktemp /tmp/hysteria.XXXXXX.hashes)"
    DEST_TMP="/opt/sbin/hysteria.new.$$"

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
        echo "❌ Скачивание/верификация"
    fi

    rm -f "$TMP_BIN" "$TMP_HASHES" "$DEST_TMP"
    [ -x /opt/etc/init.d/S23hysteria ] && /opt/etc/init.d/S23hysteria start 2>/dev/null || true
}

update_opkg() {
    echo "⏳ opkg..."
    opkg update >/dev/null 2>&1 || true
    for pkg in shadowsocks-libev-ss-redir trojan tor dnsmasq-full; do
        avail="$(opkg list-upgradable 2>/dev/null | grep "^${pkg} " || true)"
        if [ -n "$avail" ]; then
            echo "  ⏳ $pkg..."
            opkg upgrade "$pkg" || true
            echo "  ✅ $pkg"
        fi
    done
    echo "✅ opkg"
}

case "$ACTION" in
    xray)
        update_xray
        ;;
    hysteria)
        update_hysteria
        ;;
    opkg)
        update_opkg
        ;;
    all)
        update_xray
        update_hysteria
        update_opkg
        ;;
    *)
        echo "Использование:"
        echo "  $0 {xray|hysteria|opkg|all}"
        exit 1
        ;;
esac

[ -x /opt/bin/check_updates.sh ] && /opt/bin/check_updates.sh 2>/dev/null || true
#!/bin/sh

STATUS_FILE="/tmp/updates_status.json"
TMP_STATUS="${STATUS_FILE}.tmp"
BOT_CHAT_ID_FILE="/opt/var/run/bot_chat_id_notify.txt"
BOT_TOKEN_FILE="/opt/etc/bot/bot_config.py"

XRAY_REPO="XTLS/Xray-core"
HY_REPO="HyNetworks/hysteria"

ARCH=$(uname -m)
KERNEL=$(uname -r | cut -d. -f1-2)

# Стратегия xray:
#   aarch64 + ядро 5+ → GitHub
#   mips/mipsel        → opkg
#   aarch64 + ядро 4   → opkg
case "$ARCH" in
    aarch64)
        case "$KERNEL" in
            3.*|4.*)
                XRAY_SOURCE="opkg"
                ;;
            *)
                XRAY_SOURCE="github"
                ;;
        esac
        ;;
    *)
        XRAY_SOURCE="opkg"
        ;;
esac

# ── Загрузчик ──
DL=""
command -v curl >/dev/null 2>&1 \
    && DL="curl"
[ -z "$DL" ] \
    && command -v wget >/dev/null 2>&1 \
    && DL="wget"

dl_json() {
    _url="$1"
    if [ "$DL" = "curl" ]; then
        curl -s --max-time 15 \
            "$_url" 2>/dev/null
    elif [ "$DL" = "wget" ]; then
        wget -q --timeout=15 \
            -O - "$_url" 2>/dev/null
    else
        echo ""
    fi
}

# ── Telegram ──
get_bot_token() {
    grep "^token" "$BOT_TOKEN_FILE" \
        2>/dev/null | \
        sed "s/.*= *['\"]//;s/['\"].*//"
}

send_telegram() {
    _msg="$1"
    _token=$(get_bot_token)
    _chat_id=""
    if [ -f "$BOT_CHAT_ID_FILE" ]; then
        _chat_id=$(cat \
            "$BOT_CHAT_ID_FILE" \
            2>/dev/null)
    fi
    if [ -z "$_chat_id" ] \
        && [ -f /opt/var/run/bot_chat_id.txt ]
    then
        _chat_id=$(cat \
            /opt/var/run/bot_chat_id.txt \
            2>/dev/null)
    fi
    if [ -n "$_token" ] \
        && [ -n "$_chat_id" ]; then
        if [ "$DL" = "curl" ]; then
            curl -s --max-time 10 \
                -X POST \
                "https://api.telegram.org/bot${_token}/sendMessage" \
                -d "chat_id=${_chat_id}" \
                -d "text=${_msg}" \
                -d "parse_mode=HTML" \
                >/dev/null 2>&1
        elif [ "$DL" = "wget" ]; then
            wget -q --timeout=10 \
                --post-data="chat_id=${_chat_id}&text=${_msg}&parse_mode=HTML" \
                "https://api.telegram.org/bot${_token}/sendMessage" \
                -O /dev/null 2>&1
        fi
    fi
}

# ── Версии GitHub ──
github_version() {
    _repo="$1"
    dl_json "https://api.github.com/repos/${_repo}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 | sed 's/^v//'
}

# ── Версии opkg ──
opkg_available() {
    _pkg="$1"
    opkg list-upgradable 2>/dev/null \
        | grep "^${_pkg} " \
        | awk '{print $3}'
}

opkg_installed() {
    _pkg="$1"
    opkg list-installed 2>/dev/null \
        | grep "^${_pkg} " \
        | awk '{print $3}'
}

# ── Локальные версии ──
local_xray() {
    xray version 2>/dev/null \
        | head -1 | awk '{print $2}'
}

local_hysteria() {
    hysteria version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1
}

local_ss() {
    ss-redir -h 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1
}

local_trojan() {
    trojan --version 2>&1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1
}

local_tor() {
    tor --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1
}

local_dnsmasq() {
    dnsmasq --version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+' \
        | head -1
}

# ══════════════════════════════════
#  Основная логика
# ══════════════════════════════════

opkg update >/dev/null 2>&1

# Текущие
CUR_XRAY=$(local_xray)
CUR_HY=$(local_hysteria)
CUR_SS=$(local_ss)
CUR_TROJAN=$(local_trojan)
CUR_TOR=$(local_tor)
CUR_DNSMASQ=$(local_dnsmasq)

# Доступные xray
if [ "$XRAY_SOURCE" = "github" ]; then
    NEW_XRAY=$(github_version \
        "$XRAY_REPO")
else
    # opkg: проверить доступное обновление
    NEW_XRAY=$(opkg_available "xray")
fi

# Доступные hysteria (всегда GitHub)
NEW_HY=$(github_version "$HY_REPO")

# Доступные opkg
NEW_SS=$(opkg_available \
    "shadowsocks-libev-ss-redir")
NEW_TROJAN=$(opkg_available "trojan")
NEW_TOR=$(opkg_available "tor")
NEW_DNSMASQ=$(opkg_available \
    "dnsmasq-full")

# Формируем JSON
HAS_UPDATES="false"
UPDATES=""
TS=$(date +%s)

add_update() {
    _name="$1"
    _cur="$2"
    _new="$3"
    _src="$4"
    if [ -n "$_new" ] \
        && [ -n "$_cur" ] \
        && [ "$_cur" != "$_new" ]; then
        [ -n "$UPDATES" ] \
            && UPDATES="${UPDATES},"
        UPDATES="${UPDATES}{\"name\":\"${_name}\",\"current\":\"${_cur}\",\"available\":\"${_new}\",\"source\":\"${_src}\"}"
        HAS_UPDATES="true"
    fi
}

# xray: источник зависит от архитектуры
if [ "$XRAY_SOURCE" = "github" ]; then
    add_update "xray" \
        "$CUR_XRAY" "$NEW_XRAY" "github"
else
    add_update "xray" \
        "$CUR_XRAY" "$NEW_XRAY" "opkg"
fi

add_update "hysteria" \
    "$CUR_HY" "$NEW_HY" "github"
add_update "shadowsocks" \
    "$CUR_SS" "$NEW_SS" "opkg"
add_update "trojan" \
    "$CUR_TROJAN" "$NEW_TROJAN" "opkg"
add_update "tor" \
    "$CUR_TOR" "$NEW_TOR" "opkg"
add_update "dnsmasq" \
    "$CUR_DNSMASQ" "$NEW_DNSMASQ" "opkg"

VERSIONS="{\"xray\":\"${CUR_XRAY:-N/A}\",\"hysteria\":\"${CUR_HY:-N/A}\",\"shadowsocks\":\"${CUR_SS:-N/A}\",\"trojan\":\"${CUR_TROJAN:-N/A}\",\"tor\":\"${CUR_TOR:-N/A}\",\"dnsmasq\":\"${CUR_DNSMASQ:-N/A}\"}"

echo "{\"ts\":${TS},\"has_updates\":${HAS_UPDATES},\"versions\":${VERSIONS},\"updates\":[${UPDATES}],\"arch\":\"${ARCH}\",\"xray_source\":\"${XRAY_SOURCE}\"}" \
    > "$TMP_STATUS"
mv -f "$TMP_STATUS" "$STATUS_FILE"

# ── Уведомление ──
if [ "$HAS_UPDATES" = "true" ]; then
    MSG="🆕 <b>Обновления (${ARCH}):</b>"
    TMP_LINES="/tmp/updates_lines.$$"

    printf '%s\n' "$UPDATES" | sed 's/},{/}|{/g' | tr '|' '\n' > "$TMP_LINES"

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        _n=$(echo "$line" | sed 's/.*"name":"\([^"]*\)".*/\1/')
        _c=$(echo "$line" | sed 's/.*"current":"\([^"]*\)".*/\1/')
        _a=$(echo "$line" | sed 's/.*"available":"\([^"]*\)".*/\1/')
        _s=$(echo "$line" | sed 's/.*"source":"\([^"]*\)".*/\1/')

        MSG="${MSG}
• <b>${_n}</b>: ${_c} → ${_a} (${_s})"
    done < "$TMP_LINES"

    rm -f "$TMP_LINES"
    send_telegram "$MSG"
fi

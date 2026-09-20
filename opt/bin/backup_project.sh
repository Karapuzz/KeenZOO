#!/bin/sh
# /opt/bin/backup_project.sh — резервная копия всех файлов проекта.
# Оболочка: BusyBox ash.
set -eu

PATH="/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
umask 077

echo "════════════════════════════════════"
echo "  Создание бэкапа проекта"
echo "════════════════════════════════════"

ARCH="$(uname -m)"
KERNEL="$(uname -r)"
BACKUP_DIR="${BACKUP_DIR:-/tmp}"
BACKUP_FILE="${BACKUP_DIR}/bypass_project_${ARCH}_$(date +%Y%m%d_%H%M%S).tar.gz"

echo "Архитектура: $ARCH"
echo "Ядро: $KERNEL"

# Полный перечень артефактов проекта. Ранее отсутствовали init.d/S99generator,
# ndm/ifstatechanged.d, секрет веб-панели и справка о платформе.
#
# Каталог /opt/etc/bot архивируется целиком, поэтому в копию попадают и
# скрытые файлы — в том числе .secret_key (ключ подписи сессий веб-панели).
# Без него после восстановления сбрасывались бы все сессии и CSRF-токены.
#
# Бинарники xray/hysteria/tor СОЗНАТЕЛЬНО не сохраняются: они весят десятки
# мегабайт и жёстко привязаны к архитектуре. Вместо них в справку пишутся
# версии и sha256, чтобы при восстановлении поставить ровно то же самое.
BACKUP_ITEMS="
/opt/etc/bot
/opt/etc/unblock
/opt/etc/xray
/opt/etc/trojan
/opt/etc/hysteria
/opt/etc/tor
/opt/etc/shadowsocks.json
/opt/etc/dnsmasq.conf
/opt/etc/crontab
/opt/etc/hosts
/opt/etc/iproute2
/opt/etc/unblock.dnsmasq
/opt/etc/unblock.dnsmasq.cidr
/opt/etc/init.d/S22trojan
/opt/etc/init.d/S57hysteria
/opt/etc/init.d/S24xray
/opt/etc/init.d/S35tor
/opt/etc/init.d/S56dnsmasq
/opt/etc/init.d/S65shadowsocks
/opt/etc/init.d/S99telegram_bot
/opt/etc/init.d/S99generator
/opt/etc/init.d/S99unblock
/opt/etc/ndm/netfilter.d/100-redirect.sh
/opt/etc/ndm/fs.d/100-ipset.sh
/opt/etc/ndm/ifstatechanged.d
/opt/bin/unblock_dnsmasq.sh
/opt/bin/unblock_ipset.sh
/opt/bin/unblock_update.sh
/opt/bin/check_updates.sh
/opt/bin/update_protocols.sh
/opt/bin/backup_project.sh
/opt/bin/deploy_bypass.sh
/opt/bin/rotate_logs.sh
/opt/root/KeenSnap/keensnap.sh
/opt/var/run/bot_chat_id.txt
/opt/var/run/bot_chat_id_notify.txt
"

EXISTING=""
MISSING=""
for item in $BACKUP_ITEMS; do
    if [ -e "$item" ]; then
        EXISTING="${EXISTING}${EXISTING:+ }${item}"
    else
        MISSING="${MISSING}${MISSING:+ }${item}"
    fi
done

if [ -z "$EXISTING" ]; then
    echo "❌ Нечего архивировать"
    exit 1
fi

if [ -n "$MISSING" ]; then
    echo "ℹ️ Отсутствуют (пропущены): $MISSING"
fi

# ── Справка о платформе ──────────────────────────────────────────────────
# Нужна при восстановлении: бинарники xray/hysteria/tor в архив не попадают,
# и поставить надо ровно ту же сборку под ту же архитектуру. Дополнительно
# фиксируются модель Keenetic, наличие модулей ядра для TPROXY (без них не
# работает UDP) и список установленных пакетов Entware.
# Справка кладётся прямо в /opt/etc/bot, который и так архивируется целиком.
# Через отдельный каталог и второй "-C" её добавить нельзя: BusyBox tar
# поддерживает только ОДИН -C и применяет его ко всему списку файлов,
# из-за чего справка молча терялась, а архив выглядел успешным.
INFO_FILE="/opt/etc/bot/PLATFORM_INFO.txt"

# Модель и версия прошивки Keenetic: ndmc есть не на всех сборках,
# поэтому перебираем источники и не падаем при отсутствии любого из них.
kn_model="N/A"
if command -v ndmc >/dev/null 2>&1; then
    kn_model="$(ndmc -c 'show version' 2>/dev/null \
        | tr -d '\r' \
        | awk -F':' '/model|device/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
fi
[ -n "$kn_model" ] || kn_model="N/A"

kn_fw="N/A"
if command -v ndmc >/dev/null 2>&1; then
    kn_fw="$(ndmc -c 'show version' 2>/dev/null \
        | tr -d '\r' \
        | awk -F':' '/^[ \t]*(title|release)/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
fi
[ -n "$kn_fw" ] || kn_fw="N/A"

bin_info() {
    # Версия и sha256 бинарника — чтобы восстановить идентичную сборку.
    _bi_name="$1"
    _bi_path="$(command -v "$_bi_name" 2>/dev/null || true)"
    if [ -z "$_bi_path" ]; then
        printf '%s=N/A\n' "$_bi_name"
        return 0
    fi
    _bi_ver="$("$_bi_path" version 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [ -n "$_bi_ver" ] || _bi_ver="unknown"
    _bi_sum="$(sha256sum "$_bi_path" 2>/dev/null | awk '{print $1}')"
    [ -n "$_bi_sum" ] || _bi_sum="unknown"
    printf '%s=%s path=%s sha256=%s\n' \
        "$_bi_name" "$_bi_ver" "$_bi_path" "$_bi_sum"
}

{
    echo "# KeenZOO backup — справка о платформе"
    echo "date=$(date '+%Y-%m-%d %H:%M:%S')"
    echo "arch=$ARCH"
    # Архитектура Entware и порядок байт: по ним deploy_bypass.sh выбирает
    # правильные сборки xray/hysteria. Для MIPS это критично — big-endian
    # и little-endian неразличимы по `uname -m`.
    echo "entware_arch=$(opkg print-architecture 2>/dev/null \
        | awk '$1=="arch" && $2!="all" && $2!="noarch" {print $2; exit}' \
        || echo N/A)"
    echo "endian=$(dd if=/bin/busybox bs=1 skip=5 count=1 2>/dev/null \
        | od -b | awk 'NR==1 {print $2+0}' \
        | awk '{if($1==1) print "little"; else if($1==2) print "big"; else print "unknown"}')"
    echo "kernel=$KERNEL"
    echo "libc=$(readlink -f /opt/lib/ld-*.so 2>/dev/null | head -1 || echo N/A)"
    echo "keenetic_model=$kn_model"
    echo "keenetic_firmware=$kn_fw"
    echo "bot_version=$(cat /opt/etc/bot/version.md 2>/dev/null || echo N/A)"
    echo ""
    echo "ВНИМАНИЕ: архив содержит секреты (ключ сессий панели, токен бота,"
    echo "пароль веб-панели в /opt/etc/bot). Храните файл приватно и не"
    echo "передавайте третьим лицам — иначе замените эти значения после"
    echo "восстановления."
    echo ""
    echo "[binaries]"
    bin_info xray
    bin_info hysteria
    bin_info tor
    bin_info trojan
    bin_info ss-redir
    echo ""
    echo "[kernel_modules]"
    # Без xt_TPROXY и xt_socket не работает UDP через VLESS/Hysteria.
    for m in xt_TPROXY xt_socket xt_set ip_set nf_tproxy_ipv4; do
        if lsmod 2>/dev/null | grep -q "^${m} "; then
            echo "$m=loaded"
        else
            echo "$m=absent"
        fi
    done
    echo ""
    echo "[ipset]"
    ipset list -n 2>/dev/null || echo "N/A"
    echo ""
    echo "[opkg_installed]"
    opkg list-installed 2>/dev/null | awk '{print $1}' || echo "N/A"
} > "$INFO_FILE" 2>/dev/null || true

# ── Упаковка ─────────────────────────────────────────────────────────────
# Пути в архиве относительные (единственный -C /), чтобы распаковка шла
# предсказуемо и работала на BusyBox tar.
REL_ITEMS=""
for item in $EXISTING; do
    REL_ITEMS="${REL_ITEMS}${REL_ITEMS:+ }${item#/}"
done

# __pycache__ исключается: скомпилированные .pyc привязаны к версии
# Python и после восстановления на другой прошивке только мешают
# (устаревший кэш может подменить обновлённый исходник).
tar czf "$BACKUP_FILE" \
    --exclude='*/__pycache__' \
    --exclude='*.pyc' \
    -C / $REL_ITEMS 2>/dev/null \
    || tar czf "$BACKUP_FILE" -C / $REL_ITEMS 2>/dev/null \
    || true

rm -f "$INFO_FILE"

# Архив обязан быть читаемым — иначе это не бэкап, а мусор.
if ! tar tzf "$BACKUP_FILE" >/dev/null 2>&1; then
    echo "❌ Архив повреждён или нечитаем"
    rm -f "$BACKUP_FILE"
    exit 1
fi

if [ -f "$BACKUP_FILE" ]; then
    chmod 0600 "$BACKUP_FILE" 2>/dev/null || true
    SIZE="$(ls -lh "$BACKUP_FILE" | awk '{print $5}')"
    FILES="$(tar tzf "$BACKUP_FILE" 2>/dev/null | wc -l)"

    # Контроль ключевых артефактов: молчаливая потеря S99generator уже
    # приводила к тому, что бэкап выглядел успешным, но был неполным.
    MUST="opt/etc/init.d/S99generator opt/etc/bot/bot_config.py"
    LIST="$(tar tzf "$BACKUP_FILE" 2>/dev/null)"
    LOST=""
    for m in $MUST; do
        printf '%s\n' "$LIST" | grep -qx "$m" || LOST="${LOST}${LOST:+ }${m}"
    done
    if [ -n "$LOST" ]; then
        echo "⚠️ В архиве отсутствуют: $LOST"
    fi

    echo ""
    echo "✅ Бэкап: $BACKUP_FILE"
    echo "   Размер: $SIZE"
    echo "   Файлов: $FILES"
    echo "   Архитектура: $ARCH"
    echo "   Ядро: $KERNEL"
    echo ""
    echo "   Скачать:"
    echo "   scp root@192.168.1.1:${BACKUP_FILE} ."
    echo ""
    echo "⚠️ В архиве есть секреты (сессии панели, токен бота, пароль)."
    echo "   Храните файл приватно (права уже 0600)."
    echo ""
    echo "════════════════════════════════════"
    exit 0
else
    echo "❌ Ошибка создания архива"
    exit 1
fi

#!/bin/sh
echo "════════════════════════════════════"
echo "  Создание бэкапа проекта"
echo "════════════════════════════════════"

ARCH=$(uname -m)
BACKUP_FILE="/tmp/bypass_project_${ARCH}_$(date +%Y%m%d_%H%M%S).tar.gz"

echo "Архитектура: $ARCH"

tar czf "$BACKUP_FILE" \
    /opt/etc/bot/ \
    /opt/etc/unblock/ \
    /opt/etc/xray/ \
    /opt/etc/trojan/ \
    /opt/etc/hysteria/ \
    /opt/etc/tor/torrc \
    /opt/etc/shadowsocks.json \
    /opt/etc/dnsmasq.conf \
    /opt/etc/init.d/S22trojan \
    /opt/etc/init.d/S23hysteria \
    /opt/etc/init.d/S24xray \
    /opt/etc/init.d/S35tor \
    /opt/etc/init.d/S56dnsmasq \
    /opt/etc/init.d/S65shadowsocks \
    /opt/etc/init.d/S99telegram_bot \
    /opt/etc/init.d/S99unblock \
    /opt/etc/ndm/netfilter.d/100-redirect.sh \
    /opt/etc/ndm/fs.d/100-ipset.sh \
    /opt/etc/ndm/ifstatechanged.d/ \
    /opt/bin/unblock_dnsmasq.sh \
    /opt/bin/unblock_ipset.sh \
    /opt/bin/unblock_update.sh \
    /opt/bin/check_updates.sh \
    /opt/bin/update_protocols.sh \
    /opt/bin/backup_project.sh \
    /opt/bin/deploy_bypass.sh \
    /opt/bin/rotate_logs.sh \
    /opt/etc/crontab \
    /opt/etc/iproute2/ \
    2>/dev/null

if [ -f "$BACKUP_FILE" ]; then
    SIZE=$(ls -lh "$BACKUP_FILE" \
        | awk '{print $5}')
    echo ""
    echo "✅ Бэкап: $BACKUP_FILE"
    echo "   Размер: $SIZE"
    echo "   Архитектура: $ARCH"
    echo ""
    echo "   Скачать:"
    echo "   scp root@192.168.1.1:${BACKUP_FILE} ."
    echo ""
    echo "════════════════════════════════════"
else
    echo "❌ Ошибка создания"
fi
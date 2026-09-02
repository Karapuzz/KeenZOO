#!/bin/sh
MAX=524288

rotate() {
    [ -f "$1" ] || return
    _sz=$(wc -c < "$1" 2>/dev/null)
    if [ "$_sz" -gt "$MAX" ] 2>/dev/null
    then
        tail -100 "$1" > "${1}.tmp"
        mv -f "${1}.tmp" "$1"
    fi
}

rotate /opt/etc/bot/error.log
rotate /opt/etc/bot/generator.log
rotate /opt/etc/xray/error.log
rotate /opt/etc/xray/access.log
rotate /opt/root/KeenSnap/backup.log

rm -f /tmp/xray_debug*.log 2>/dev/null
rm -f /tmp/xray_client*.log 2>/dev/null
rm -f /tmp/xray_test*.log 2>/dev/null
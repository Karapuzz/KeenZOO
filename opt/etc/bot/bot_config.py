# -*- coding: utf-8 -*-
"""
/opt/etc/bot/bot_config.py
"""

lan_ifaces = ['br0', 'br1']
web_password = 'Надежный_пароль'
web_username = 'admin'

token = 'ТОКЕН_БОТА'
allowed_user_ids = [123456789]  # замените на свой Telegram user_id
usernames = ['ИМЯ_ЮЗЕРА']
MAX_RESTARTS = 5
RESTART_DELAY = 60

routerip = '192.168.1.1'
vpn_allowed = "IKE|SSTP|OpenVPN|Wireguard|L2TP"

localportsh = 1082
dnsporttor = 9053
localporttor = 9141
localportvless = 10810
localporttrojan = 10829
localporthysteria = 10830
localportrouter = 10810
dnsovertls_ports = [40500, 40501, 40502, 40503]
dnsoverhttps_ports = [40508, 40509, 40510, 40511]

ipset_names = {
    'shadowsocks': 'unblocksh',
    'tor':         'unblocktor',
    'vless':       'unblockvless',
    'trojan':      'unblocktroj',
    'hysteria':    'unblockhysteria',
    'bot':         'unblockrouter',
}

list_files = {
    'shadowsocks': '/opt/etc/unblock/shadowsocks.txt',
    'trojan':      '/opt/etc/unblock/trojan.txt',
    'vless':       '/opt/etc/unblock/vless.txt',
    'tor':         '/opt/etc/unblock/tor.txt',
    'hysteria':    '/opt/etc/unblock/hysteria.txt',
    'bot':         '/opt/etc/unblock/bot.txt',
}

generator_settings = {
    'listen_ip': routerip,
    'listen_port': 8080,
    'max_list_lines': 5000,
    'unblock_timeout': 300,
    'log_file': '/opt/etc/bot/generator.log',
    'lock_dir': '/tmp/unblock_update.lockdir',
    'status_file': '/tmp/unblock_update_status.json',
    'update_log': '/tmp/unblock_update.log',
}

packages = [
    "tor", "tor-geoip", "bind-dig", "cron",
    "dnsmasq-full", "ipset", "iptables",
    "obfs4", "webtunnel-client",
    "shadowsocks-libev-ss-redir",
    "shadowsocks-libev-config",
    "xray", "trojan", "hysteria",
    "coreutils-split",
    "python3-pip", "python3-requests",
    "python3-flask", "python3-pytelegrambotapi",
]

paths = {
    "unblock_dir": "/opt/etc/unblock/",
    "bot_list": "/opt/etc/unblock/bot.txt",
    "tor_config": "/opt/etc/tor/torrc",
    "shadowsocks_config": "/opt/etc/shadowsocks.json",
    "trojan_config": "/opt/etc/trojan/config.json",
    "vless_config": "/opt/etc/xray/config.json",
    "hysteria_config": "/opt/etc/hysteria/config.json",
    "templates_dir": "/opt/etc/bot/templates/",
    "dnsmasq_conf": "/opt/etc/dnsmasq.conf",
    "crontab": "/opt/etc/crontab",
    "hosts_file": "/opt/etc/hosts",
    "redirect_script":
        "/opt/etc/ndm/netfilter.d/100-redirect.sh",
    "vpn_script":
        "/opt/etc/ndm/ifstatechanged.d/"
        "100-unblock-vpn.sh",
    "ipset_script":
        "/opt/etc/ndm/fs.d/100-ipset.sh",
    "unblock_ipset": "/opt/bin/unblock_ipset.sh",
    "unblock_dnsmasq": "/opt/bin/unblock_dnsmasq.sh",
    "unblock_update": "/opt/bin/unblock_update.sh",
    "check_updates": "/opt/bin/check_updates.sh",
    "update_protocols":
        "/opt/bin/update_protocols.sh",
    "updates_status":
        "/tmp/updates_status.json",
    "chat_id_notify":
        "/opt/var/run/bot_chat_id_notify.txt",
    "keensnap_dir": "/opt/root/KeenSnap/",
    "script_bu": "/opt/root/KeenSnap/keensnap.sh",
    "log_bu": "/opt/root/KeenSnap/backup.log",
    "bot_dir": "/opt/etc/bot",
    "bot_path": "/opt/etc/bot/main.py",
    "bot_config": "/opt/etc/bot/bot_config.py",
    "generator_path": "/opt/etc/bot/generator.py",
    "generator_log": "/opt/etc/bot/generator.log",
    "error_log": "/opt/etc/bot/error.log",
    "chat_id_path":
        "/opt/var/run/bot_chat_id.txt",
    "init_shadowsocks":
        "/opt/etc/init.d/S65shadowsocks",
    "init_trojan": "/opt/etc/init.d/S22trojan",
    "init_xray": "/opt/etc/init.d/S24xray",
    "init_tor": "/opt/etc/init.d/S35tor",
    "init_hysteria": "/opt/etc/init.d/S23hysteria",
    "init_dnsmasq": "/opt/etc/init.d/S56dnsmasq",
    "init_unblock": "/opt/etc/init.d/S99unblock",
    "init_bot": "/opt/etc/init.d/S99telegram_bot",
    "tor_tmp_dir": "/opt/tmp/tor",
    "tor_dir": "/opt/etc/tor",
    "xray_dir": "/opt/etc/xray",
    "trojan_dir": "/opt/etc/trojan",
    "hysteria_dir": "/opt/etc/hysteria",
    "script_sh": "/opt/root/script.sh",
}

services = {
    "tor_restart": [paths["init_tor"], "restart"],
    "shadowsocks_restart": [
        paths["init_shadowsocks"], "restart"],
    "trojan_restart": [
        paths["init_trojan"], "restart"],
    "vless_restart": [
        paths["init_xray"], "restart"],
    "hysteria_restart": [
        paths["init_hysteria"], "restart"],
    "dnsmasq_restart": [
        paths["init_dnsmasq"], "restart"],
    "service_script": [
        paths["init_bot"], "restart"],
    "unblock_update": [paths["unblock_update"]],
}

bot_url = (
    "https://raw.githubusercontent.com/"
    "Karapuzz/KeenZOO/main/opt/etc/bot"
)

backup_settings = {
    "LOG_FILE": paths["log_bu"],
    "MAX_SIZE_MB": 45,
    "CUSTOM_BACKUP_PATHS": " ".join([
        paths["bot_dir"],
        paths["vless_config"],
        paths["tor_config"],
        paths["script_sh"],
        paths["script_bu"],
        paths["bot_list"],
    ]),
}
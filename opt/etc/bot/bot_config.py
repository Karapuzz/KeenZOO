# -*- coding: utf-8 -*-
"""
/opt/etc/bot/bot_config.py
"""

# ─── Заполнить при установке с нуля: 4 поля ниже помечены [!] ───────

# Интерфейсы, на которых работает обход: LAN, гостевая, WireGuard-сервер.
# Свои посмотреть: ip -o link | awk -F": " '{print $2}'
# Kernel names are discovered dynamically by 100-redirect.sh and
# unblock_dnsmasq.sh. nwg0 is the current Wireguard0 server device;
# nwg1 is added only when ip link reports it.
lan_ifaces = ['br0', 'br1', 'nwg0']

# Веб-панель. Пустой пароль = панель отключена (503).
web_username = 'admin'
web_password = ''               # [!] задайте пароль

# [!] Токен от @BotFather
token = 'ТОКЕН_БОТА'

# [!] Свой ID узнать у @userinfobot (число). Доступ к боту — только по ID.
allowed_user_ids = [123456789]
usernames = ['ИМЯ_ЮЗЕРА']       # справочно, в проверке доступа не участвует
MAX_RESTARTS = 5
RESTART_DELAY = 60

routerip = '192.168.1.1'        # [!] IP роутера, если не 192.168.1.1
vpn_allowed = "IKE|SSTP|OpenVPN|Wireguard|L2TP"

# ─── Закрепление адресов прокси-серверов (пиннинг) ──────────────────
# Если адрес сервера в конфиге задан доменом, при блокировке DNS его
# невозможно разрешить — и туннель не поднимется. Поэтому пока DNS
# работает, домен резолвится заранее, а результат закрепляется в
# /opt/etc/hosts. Дальше xray/hysteria получают IP локально, без сети.
# Пин обновляется при каждом штатном запуске unblock_dnsmasq.sh.
pin_server_hosts = True

# DNS policy v4: fastest validated Primary -> next DNSSEC backup ->
# Hysteria -> Xray -> Trojan -> authorized emergency public DNS TCP/UDP53.
# Preferred Primary survives fallback and is restored after positive checks.
# These bootstrap IPv4 addresses are also the ordered emergency client pool.
bootstrap_resolvers = ['9.9.9.9', '8.8.8.8', '1.1.1.1']
tunnel_doh_hosts = ['dns.google', 'cloudflare-dns.com', 'dns11.quad9.net']
tunnel_protocol_priority = ['hysteria', 'xray', 'trojan']
# Возраст pin в секундах: мягкий предел для diagnostics/recovery и жёсткий
# предел, после которого адрес не потребляется.
pin_max_age = 604800
pin_hard_max_age = 2592000
# Safety expiry, not a polling interval: the daily refresh runs every 24h,
# with one hour of margin. A snapshot older than this is fail-closed.
dns_snapshot_max_age = 21600  # 6h: fail-closed быстрее; recovery 300s всё равно выводит из emergency (dns4.2.21, was 25h)
dns_health_log = '/opt/var/log/unblock_dns_health.log'

# Контрольная DNSSEC-подписанная зона для health-check локальных
# DoT/DoH-портов. torproject.org намеренно не используется: домен
# может быть заблокирован в России, и это дало бы ложный отказ DNS.
dns_health_domain = 'example.com'

localportsh = 1082
dnsporttor = 9053
localporttor = 9141
localportvless = 10810
localporttrojan = 10829
localporthysteria = 10830
# Порт, куда перенаправляется собственный трафик роутера (bot.txt).
# Legacy default. Web selection is stored in /opt/etc/unblock/.router_protocol
# (xray/trojan/hysteria); netfilter uses the selected local protocol port.
# deprecated: legacy-дубль без собственных потребителей (dns4.2.20, аудит A2);
# реальный переключатель router-пути — /opt/etc/unblock/.router_protocol,
# порт совпадает с localportvless. Удалить после окна миграции.
localportrouter = localportvless
dnsovertls_ports = [40500, 40501, 40502, 40503]
dnsoverhttps_ports = [40508, 40509, 40510, 40511]
# dnsmasq uses stable loopback facade 127.0.0.1:40512 (utils.py controller).
# Local DoT/DoH candidates are never auto-redirected just for an active proxy.
# Tunnel fallback uses explicitly marked TCP DNS through tcpRedirect/dokodemo.
dns_endpoint_hosts = ['dns11.quad9.net', 'dns.google', 'cloudflare-dns.com', 'opennic1.eth-services.de', 'opennic2.eth-services.de']

ipset_names = {
    'shadowsocks': 'unblocksh',
    'tor':         'unblocktor',
    'vless':       'unblockvless',
    'trojan':      'unblocktroj',
    'hysteria':    'unblockhysteria',
    'bot':         'unblockrouter',
}

# A sidecar marker is written only after the user submits a tunnel key or
# full tunnel config through the bot/web panel. Init scripts require it in
# addition to non-placeholder JSON, so a preserved stale config cannot start
# a tunnel after deployment/reboot.
tunnel_configured_dir = '/opt/etc/unblock/.configured'

list_files = {
    'shadowsocks': '/opt/etc/unblock/shadowsocks.txt',
    'trojan':      '/opt/etc/unblock/trojan.txt',
    'vless':       '/opt/etc/unblock/vless.txt',
    'tor':         '/opt/etc/unblock/tor.txt',
    'hysteria':    '/opt/etc/unblock/hysteria.txt',
    'bot':         '/opt/etc/unblock/bot.txt',
}

# Единый источник настроек веб-панели. generator.py читает значения
# отсюда, дублирующих констант в нём больше нет — это устраняло дрейф
# конфигурации (например, разные lock_dir в панели и в shell-скрипте).
web_port = 8080
generator_settings = {
    'listen_ip': routerip,
    'listen_port': web_port,        # занят? поправьте и 100-redirect.sh
    'max_list_lines': 5000,
    'unblock_timeout': 300,
    'log_file': '/opt/etc/bot/generator.log',
    'lock_dir': '/tmp/unblock_update.lockdir',
    'status_file': '/tmp/unblock_update_status.json',
    'update_log': '/tmp/unblock_update.log',
    'secret_file': '/opt/etc/bot/.secret_key',
}

# hysteria, python3-flask и python3-pytelegrambotapi в Entware
# отсутствуют — deploy_bypass.sh ставит их через pip и с GitHub.
# dns4.2.21 (находка B6-6): СПРАВОЧНЫЙ манифест (нигде в коде не
# читается — задокументировать установку, не модель установки).
# Внимание к точке: «python3-flask» и «python3-pytelegrambotapi» — это
# ИМЕНА pip-пакетов, а не opkg (ставятся через pip в deploy_bypass.sh);
# hysteria в Entware существует и обновляется через opkg — заявление
# внешнего отчёта «несуществующие пакеты» к ней не относится.
packages = [
    "tor", "tor-geoip", "bind-dig", "cron",
    "dnsmasq-full", "ipset", "iptables",
    "obfs4", "webtunnel-client",
    "shadowsocks-libev-ss-redir",
    "shadowsocks-libev-config",
    "xray", "trojan", "hysteria",
    "coreutils-split",
    "python3-pip", "python3-requests",
    # pip (не opkg):
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
    "init_hysteria": "/opt/etc/init.d/S57hysteria",
    "init_dnsmasq": "/opt/etc/init.d/S56dnsmasq",
    "init_unblock": "/opt/etc/init.d/S99unblock",
    "init_bot": "/opt/etc/init.d/S99telegram_bot",
    "tor_tmp_dir": "/opt/tmp/tor",
    "tor_dir": "/opt/etc/tor",
    "xray_dir": "/opt/etc/xray",
    "trojan_dir": "/opt/etc/trojan",
    "hysteria_dir": "/opt/etc/hysteria",
    "script_sh": "/opt/root/script.sh",
    "deploy_script": "/opt/bin/deploy_bypass.sh",
    "rotate_logs": "/opt/bin/rotate_logs.sh",
    "backup_project": "/opt/bin/backup_project.sh",
    "init_generator": "/opt/etc/init.d/S99generator",
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
    "generator_restart": [
        paths["init_generator"], "restart"],
}

# Внешний base_url удалён намеренно: прежде бот скачивал script.sh с
# GitHub и запускал его с правами root без проверки подписи или
# контрольной суммы — это позволяло выполнить произвольный код при
# компрометации репозитория или подмене трафика. Обновление и установка
# выполняются локальными проверенными скриптами из /opt/bin.

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
# Hybrid DNS policy: monotonic idle/recovery timers, calendar pool in router TZ.
# AD is upstream validation evidence, NOT local signature verification; AA ignored.
dns_policy_version = 4
dns_policy_mode = 'hybrid'
dns_policy_interval = 3600
dns_policy_pool_hours = [11, 23]
dns_policy_recovery_interval = 300

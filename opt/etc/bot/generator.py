#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/opt/etc/bot/generator.py
"""

import os
import sys
import json
import ipaddress
import logging
import shutil
import shlex
import subprocess
import time
import hashlib
import hmac
import html
import re
import glob
import threading
from urllib.parse import urlparse

from flask import (
    Flask, render_template_string,
    request, flash, redirect,
    url_for, abort, session, jsonify, Response,
)
from werkzeug.serving import make_server

sys.path.insert(0, '/opt/etc/bot')

try:
    import bot_config as config
except Exception as _cfg_err:
    # Ошибка в bot_config.py (частый случай — значение без кавычек,
    # например usernames = [Иванов] вместо ['Иванов']) роняла панель
    # с NameError ещё до старта Flask, и порт 8080 не открывался.
    # Сообщаем причину явно и в лог, и в консоль.
    sys.stderr.write(
        "\n[!] Ошибка в /opt/etc/bot/bot_config.py: %s: %s\n"
        "    Проверьте синтаксис: строковые значения нужно брать\n"
        "    в кавычки, например usernames = ['ИМЯ'].\n"
        "    Быстрая проверка:\n"
        "      cd /opt/etc/bot && python3 -c 'import bot_config'\n\n"
        % (type(_cfg_err).__name__, _cfg_err))
    sys.stderr.flush()
    raise SystemExit(1)
from utils import (
    shadowsocks_config,
    trojan_config,
    vless_config,
    tor_config,
    hysteria_config,
    apply_direct_config,
    log_error,
)

# Журналирование: в лог попадают ТОЛЬКО ошибки. По умолчанию werkzeug
# пишет строку на КАЖДЫЙ HTTP-запрос, и generator.log неограниченно рос
# на накопителе с Entware. Оставляем уровень ERROR.
logging.basicConfig(level=logging.ERROR)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

app = Flask(__name__)

# ── Единый источник настроек: bot_config.generator_settings ──────────────
# Раньше панель дублировала пути и порты собственными константами, из-за
# чего значения расходились с bot_config.py и shell-скриптами (характерный
# пример — lock_dir). Теперь всё читается из одного места.
_GS = getattr(config, 'generator_settings', {})

SECRET_FILE = _GS.get(
    'secret_file', '/opt/etc/bot/.secret_key')


def _load_or_create_secret():
    """Load a persistent session key or fail closed.

    An ephemeral Flask key makes every restart invalidate sessions and CSRF
    tokens and can hide a broken read-only filesystem. The panel must not
    advertise a healthy production state in that situation, so creation and
    persistence are mandatory. The temporary file is created next to the
    final path and atomically replaced, which is safe on the flash-backed
    Keenetic filesystem and does not add a daemon or a permanent state file.
    """
    try:
        secret_dir = os.path.dirname(SECRET_FILE) or '.'
        os.makedirs(secret_dir, exist_ok=True)
        if os.path.exists(SECRET_FILE):
            st = os.stat(SECRET_FILE)
            if not os.path.isfile(SECRET_FILE):
                raise OSError('secret path is not a regular file')
            key = open(SECRET_FILE, 'r', encoding='utf-8').read().strip()
            if len(key) < 32:
                raise OSError('secret file is too short')
            if st.st_mode & 0o077:
                os.chmod(SECRET_FILE, 0o600)
            return key

        key = hashlib.sha256(os.urandom(64)).hexdigest()
        tmp = f'{SECRET_FILE}.tmp.{os.getpid()}'
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600)
        try:
            with os.fdopen(fd, 'w', encoding='ascii') as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, SECRET_FILE)
            os.chmod(SECRET_FILE, 0o600)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return key
    except (OSError, ValueError) as err:
        sys.stderr.write(
            f"[!] Панель остановлена: невозможно безопасно сохранить "
            f"{SECRET_FILE}: {err}\n")
        sys.stderr.flush()
        raise SystemExit(1)


app.secret_key = _load_or_create_secret()
app.jinja_env.autoescape = True


def generate_csrf():
    """
    CSRF-токен хранится в серверной сессии и переиспользуется в течение
    всей сессии. Ключ подписи сессии сохраняется в SECRET_FILE и не
    меняется при перезапуске панели, поэтому токен остаётся стабильным
    между открытиями страниц, а не генерируется каждый раз заново.
    """
    token = session.get('csrf_token')

    if isinstance(token, str) and len(token) >= 32:
        return token

    token = hmac.new(
        app.secret_key.encode(),
        os.urandom(32),
        hashlib.sha256).hexdigest()

    session['csrf_token'] = token
    session.permanent = True
    session.modified = True
    return token


def validate_csrf(token):
    expected = session.get(
        'csrf_token', '')
    if (not expected
            or not isinstance(token, str)):
        return False
    return hmac.compare_digest(
        token, expected)


LAN_IP = _GS.get('listen_ip', getattr(config, 'routerip', '192.168.1.1'))
LISTEN_PORT = int(_GS.get('listen_port', 8080))
MAX_CONTENT_LENGTH = 1 * 1024 * 1024
UNBLOCK_TIMEOUT = int(_GS.get('unblock_timeout', 300))

# Панель обслуживает только внутренние сети. Публичные адреса и любые
# внешние подключения отклоняются до аутентификации.
# Учёт неудачных входов: {ip: (число_неудач, заблокирован_до)}.
# Хранится в памяти процесса — перезапуск панели сбрасывает счётчики,
# что приемлемо: панель доступна только из LAN.
_auth_fails = {}
_AUTH_MAX_FAILS = 5
_AUTH_BLOCK_SEC = 300

ALLOWED_SUBNETS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
]

GENERATOR_LOG = _GS.get(
    'log_file', '/opt/etc/bot/generator.log')
UNBLOCK_DIR = config.paths.get(
    'unblock_dir', '/opt/etc/unblock').rstrip('/')
LOCK_DIR = _GS.get(
    'lock_dir', '/tmp/unblock_update.lockdir')
UPDATE_STATUS_FILE = _GS.get(
    'status_file', '/tmp/unblock_update_status.json')
UPDATE_LOG_FILE = _GS.get(
    'update_log', '/tmp/unblock_update.log')
WRAPPER_SCRIPT = (
    '/tmp/unblock_update_wrapper.sh')

# ── Обновление протоколов из веб-панели ──────────────────────────────
# Отдельные файлы состояния: обновление протоколов и пересборка списков
# запускаются независимо и не должны затирать статус друг друга.
PROTO_UPD_STATUS = (
    '/tmp/proto_update_status.json')
PROTO_UPD_LOG = (
    '/tmp/proto_update.log')
PROTO_UPD_WRAPPER = (
    '/tmp/proto_update_wrapper.sh')
# Обновление всех компонентов может занимать минуты; после этого срока
# зависший запуск считается мёртвым и разрешается новый.
PROTO_UPD_TIMEOUT = 900
UNBLOCK_LAUNCH_LOCK = LOCK_DIR + '.launcher.lockdir'
PROTO_LAUNCH_LOCK = '/tmp/proto_update.launch.lockdir'
UPDATES_CHECK_LOCK = '/tmp/keenzoo_updates_check.lockdir'

DNS_PORTS_DOT = list(
    getattr(config, 'dnsovertls_ports',
            [40500, 40501, 40502, 40503]))
DNS_PORTS_DOH = list(
    getattr(config, 'dnsoverhttps_ports',
            [40508, 40509, 40510, 40511]))
# Не использовать torproject.org как health-check: домен может быть
# заблокирован в России. Контрольная зона должна быть DNSSEC-подписанной,
# стабильной и не относиться к спискам обхода.
DNS_HEALTH_DOMAIN = str(getattr(
    config, 'dns_health_domain', 'example.com'))
DNS_HEALTH_LOG = str(getattr(
    config, 'dns_health_log', '/opt/var/log/unblock_dns_health.log'))
DNS_SNAPSHOT_MAX_AGE = int(getattr(
    config, 'dns_snapshot_max_age', 90000))

SERVICE_SCRIPTS = {
    'shadowsocks': config.paths['init_shadowsocks'],
    'trojan': config.paths['init_trojan'],
    'vless': config.paths['init_xray'],
    'tor': config.paths['init_tor'],
    'hysteria': config.paths['init_hysteria'],
}

BYPASS_FILES = {
    key: path
    for key, path in config.list_files.items()
    if key != 'bot'
}

BOT_BYPASS_FILE = config.list_files['bot']

BYPASS_IPSETS = dict(config.ipset_names)

MAX_LIST_LINES = int(_GS.get('max_list_lines', 5000))


def rotate_log():
    if not os.path.exists(GENERATOR_LOG):
        return
    try:
        if os.path.getsize(
                GENERATOR_LOG) > 524288:
            with open(GENERATOR_LOG, 'r',
                      encoding='utf-8') as f:
                lines = f.readlines()
            with open(GENERATOR_LOG, 'w',
                      encoding='utf-8') as f:
                f.writelines(lines[-50:])
    except Exception:
        pass


def web_log(message):
    """Запись в журнал панели (раньше функция была пустой заглушкой)."""
    try:
        rotate_log()
        with open(GENERATOR_LOG, 'a', encoding='utf-8') as f:
            f.write(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
                f" - {message}\n")
    except OSError:
        pass


def _is_local_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(
        addr in s for s in ALLOWED_SUBNETS)


def _client_ip():
    """
    Реальный адрес клиента. Заголовки X-Forwarded-For / X-Real-IP
    сознательно игнорируются: панель не работает за доверенным обратным
    прокси, а эти заголовки подделываются клиентом и позволяли бы обойти
    ограничение «только LAN».
    """
    return request.remote_addr or ''


def _is_local_request():
    ip_str = _client_ip()
    if not _is_local_ip(ip_str):
        return False

    # Решение принимается по адресу КЛИЕНТА (проверен выше): он не
    # подделывается, так как берётся из TCP-соединения.
    # Заголовок Host дополнительно НЕ ограничивается: у роутера несколько
    # внутренних адресов (гостевая сеть, отдельный бридж 5 ГГц, VPN
    # прошивки), а клиенты обращаются и по имени my.keenetic.net —
    # прежняя проверка отклоняла такие запросы с 403.
    return True


@app.before_request
def security_checks():
    # 1. Только внутренние сети.
    if not _is_local_request():
        log_error(
            f"[w] отклонён внешний запрос от {_client_ip()}")
        return ('⛔ Доступ разрешён только из локальной сети.', 403)

    # 2. Обязательная аутентификация. Пустой пароль в bot_config.py
    #    означает «панель не настроена» — доступ закрыт полностью,
    #    вместо прежнего поведения с открытым входом.
    web_user = str(getattr(config, 'web_username', '') or '')
    web_pass = str(getattr(config, 'web_password', '') or '')

    if not web_user or not web_pass:
        return (
            '⛔ Веб-панель не настроена: задайте web_username и '
            'web_password в /opt/etc/bot/bot_config.py',
            503)

    auth = request.authorization
    client = _client_ip()

    # Защита от подбора пароля. Панель доступна только из LAN, но
    # заражённое устройство внутри сети могло перебирать пароль без
    # ограничений. Счётчик неудач ведётся по адресу клиента в памяти
    # процесса; после _AUTH_MAX_FAILS попыток адрес блокируется на
    # _AUTH_BLOCK_SEC секунд. Успешный вход счётчик сбрасывает.
    now = time.time()
    fails, blocked_until = _auth_fails.get(client, (0, 0.0))

    # Сравнение строго в БАЙТАХ. hmac.compare_digest на str падает с
    # TypeError, если хоть один символ вне ASCII: пароль с кириллицей
    # ронял КАЖДЫЙ запрос к панели в 500, включая /api/dns-status.
    def _cmp(a, b):
        try:
            return hmac.compare_digest(
                str(a or '').encode('utf-8'),
                str(b or '').encode('utf-8'))
        except (UnicodeError, TypeError):
            return False

    ok = bool(
        auth
        and _cmp(auth.username, web_user)
        and _cmp(auth.password, web_pass))

    # ВАЖНО: блокировка применяется только к НЕВЕРНЫМ попыткам.
    # Если отвергать и правильный пароль, администратор запирает сам
    # себя, а злоумышленник из LAN легко устраивает отказ в
    # обслуживании, просто перебирая пароль с чужого адреса.
    if ok:
        if client in _auth_fails:
            del _auth_fails[client]
    else:
        if blocked_until > now:
            # Пауза уже идёт: не наращиваем счётчик, просто отказываем.
            return Response(
                'Too many failed attempts',
                429,
                {'Retry-After':
                 str(int(blocked_until - now)),
                 'WWW-Authenticate':
                 'Basic realm="Keenetic bypass panel"'})

        fails += 1
        if fails >= _AUTH_MAX_FAILS:
            _auth_fails[client] = (
                0, now + _AUTH_BLOCK_SEC)
            log_error(
                f'[w] {_AUTH_MAX_FAILS} неудачных входов '
                f'с {client} — пауза {_AUTH_BLOCK_SEC}с')
        else:
            _auth_fails[client] = (fails, 0.0)

        # Задержка замедляет автоматический перебор.
        time.sleep(0.5)
        return Response(
            'Authentication required',
            401,
            {'WWW-Authenticate':
             'Basic realm="Keenetic bypass panel"'})

    # 3. Защита от CSRF на уровне источника запроса.
    if request.method == 'POST':
        allowed_hosts = {
            f'{LAN_IP}:{LISTEN_PORT}',
            f'localhost:{LISTEN_PORT}',
            f'127.0.0.1:{LISTEN_PORT}',
            str(request.host),
        }

        def _same_origin(value):
            if not value:
                return False
            try:
                parsed = urlparse(value)
            except Exception:
                return False
            return (
                parsed.scheme in ('http', 'https')
                and parsed.netloc in allowed_hosts
            )

        origin = request.headers.get('Origin', '')
        referer = request.headers.get('Referer', '')

        if origin:
            if not _same_origin(origin):
                return ('⛔ CSRF.', 403)
        elif referer:
            if not _same_origin(referer):
                return ('⛔ CSRF.', 403)
        else:
            return ('⛔ CSRF.', 403)


def _run_command(args, timeout=30, env=None, check=False, label='command'):
    """Run a bounded command with one error/reporting policy.

    The wrapper deliberately keeps argv execution (no shell=True), truncates
    captured diagnostics for flash-backed logs, and turns timeout/OS errors
    into a normal CompletedProcess-like result unless the caller requests
    ``check``. This keeps BusyBox/Entware failures visible without allowing a
    hung child to hang the web worker forever.
    """
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env)
    except subprocess.TimeoutExpired:
        log_error(f'[!] {label}: timeout after {timeout}s')
        result = subprocess.CompletedProcess(
            args=args, returncode=124, stdout='', stderr='timeout')
    except OSError as err:
        log_error(f'[!] {label}: {err}')
        result = subprocess.CompletedProcess(
            args=args, returncode=127, stdout='', stderr=str(err))

    result.stdout = (result.stdout or '')[-4000:]
    result.stderr = (result.stderr or '')[-4000:]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-400:]
        log_error(
            f'[!] {label}: rc={result.returncode}'
            f'{": " + detail if detail else ""}')
        if check:
            raise RuntimeError(
                f'{label}: rc={result.returncode}'
                f'{": " + detail if detail else ""}')
    return result


def _proc_alive(proc_name):
    for proc_dir in glob.glob('/proc/[0-9]*'):
        try:
            with open(os.path.join(proc_dir, 'cmdline'), 'rb') as f:
                argv = f.read().split(b'\0')
            argv0 = os.path.basename((argv[0] if argv else b'').decode(
                'utf-8', 'replace'))
            if argv0 == proc_name:
                return True
        except OSError:
            continue
    return False


def _port_ready(port, udp=False):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if not 1 <= port <= 65535:
        return False
    hex_port = f'{port:04X}'
    paths = ('/proc/net/udp', '/proc/net/udp6') if udp else (
        '/proc/net/tcp', '/proc/net/tcp6')
    for path in paths:
        try:
            with open(path, 'r', encoding='ascii', errors='replace') as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 4:
                        continue
                    local = fields[1].rsplit(':', 1)[-1].upper()
                    if local != hex_port:
                        continue
                    if udp or fields[3] == '0A':
                        return True
        except OSError:
            continue
    return False


def _config_port(name):
    """Return a configured local port, or None without inventing one."""
    value = getattr(config, name, None)
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 1 <= value <= 65535 else None


SERVICE_READINESS = {
    'shadowsocks': ('ss-redir', _config_port('localportsh'), True),
    'trojan': ('trojan', _config_port('localporttrojan'), False),
    'vless': ('xray', _config_port('localportvless'), False),
    'tor': ('tor', _config_port('localporttor'), False),
    'hysteria': ('hysteria', _config_port('localporthysteria'), True),
}


def _service_ready(service):
    item = SERVICE_READINESS.get(service)
    if not item:
        return True
    proc, port, udp = item
    if port is None:
        return False
    return _proc_alive(proc) and _port_ready(port, udp=udp)


def _wait_service_ready(service, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _service_ready(service):
            return True
        time.sleep(0.5)
    return _service_ready(service)


def _iptables_bin():
    """
    Пакет Entware "iptables" кладёт /opt/sbin/iptables без расширений
    TPROXY/socket/set и перекрывает прошивочный бинарник в PATH.
    Для правил панели нужен рабочий iptables, поэтому выбираем явно.
    """
    # На Keenetic прошивочный iptables лежит НЕ в /usr/sbin: этого пути
    # там нет вовсе. Реально встречаются /opt/sbin (Entware) и внутренние
    # пути прошивки, поэтому список кандидатов расширен, а в конце —
    # поиск через PATH.
    for cand in ('/usr/sbin/iptables', '/sbin/iptables',
                 '/bin/iptables', '/usr/bin/iptables',
                 '/opt/sbin/iptables', '/opt/bin/iptables'):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    found = shutil.which('iptables')
    if found:
        return found
    return 'iptables'


IPTABLES = _iptables_bin()


def _ipt(*args):
    """Bounded iptables call using the common subprocess policy."""
    return _run_command(
        [IPTABLES, '-w'] + list(args),
        timeout=15,
        label='iptables ' + ' '.join(str(a) for a in args))


def setup_firewall(port):
    """
    Ограничивает доступ к порту панели на уровне netfilter.

    Разрешение выдаётся по ИСХОДНОЙ ПОДСЕТИ, а не по имени интерфейса.
    Прежняя версия перечисляла br0/br1/wlan0/..., после чего вешала DROP
    без "-i". На Keenetic Wi-Fi-клиенты часто приходят через другой мост
    (гостевая сеть, отдельный бридж для 5 ГГц, иные имена вида wl0/ra0),
    и тогда ACCEPT для них не создавался, а общий DROP блокировал доступ:
    панель открывалась с роутера, но не с телефона по Wi-Fi.
    Список подсетей совпадает с ALLOWED_SUBNETS, который проверяет Flask.
    """
    wan = ['eth0', 'eth1', 'ppp0', 'ppp1', 'wan0', 'usb0']

    # Снять возможные разрешения на WAN.
    for i in wan:
        while _ipt('-D', 'INPUT', '-p', 'tcp', '--dport', str(port),
                   '-i', i, '-j', 'ACCEPT').returncode == 0:
            pass

    # Снять прежний DROP, чтобы затем добавить его последним.
    while _ipt('-D', 'INPUT', '-p', 'tcp', '--dport', str(port),
               '-j', 'DROP').returncode == 0:
        pass

    # Снять устаревшие ACCEPT по именам интерфейсов, оставшиеся
    # от предыдущих версий, — иначе они накапливаются.
    for i in list(getattr(config, 'lan_ifaces', ['br0', 'br1'])) + \
            ['lo', 'wlan0', 'wlan1']:
        while _ipt('-D', 'INPUT', '-p', 'tcp', '--dport', str(port),
                   '-i', i, '-j', 'ACCEPT').returncode == 0:
            pass

    # Разрешить доступ из локальных подсетей независимо от интерфейса.
    for net in [str(n) for n in ALLOWED_SUBNETS]:
        if _ipt('-C', 'INPUT', '-p', 'tcp', '--dport', str(port),
                '-s', net, '-j', 'ACCEPT').returncode != 0:
            _ipt('-I', 'INPUT', '-p', 'tcp', '--dport', str(port),
                 '-s', net, '-j', 'ACCEPT')

    # Всё остальное (в первую очередь WAN) — запретить.
    _ipt('-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP')


def _check_csrf():
    token = request.form.get(
        'csrf_token', '')
    if not validate_csrf(token):
        abort(403)


# ── Включение/отключение протоколов ──────────────────────────────────────
# Состояние хранится в самом init-скрипте (ENABLED=yes|no) — это штатный
# механизм Entware: rc.func не запускает сервис при ENABLED=no, поэтому
# выбор переживает перезагрузку роутера без отдельного файла состояния.
# Конфигурации протоколов при отключении НЕ трогаются: повторное включение
# поднимает сервис с прежними ключами.
TAB_TO_SERVICE = {
    'ss': 'shadowsocks',
    'tr': 'trojan',
    'vl': 'vless',
    'to': 'tor',
    'hy': 'hysteria',
}


def _read_enabled(sn):
    """Читает ENABLED= из init-скрипта. Нет файла — считаем включённым."""
    sc = SERVICE_SCRIPTS.get(sn)
    if not sc or not os.path.exists(sc):
        return True
    try:
        with open(sc, 'r', encoding='utf-8',
                  errors='replace') as f:
            for line in f:
                m = re.match(
                    r'\s*ENABLED\s*=\s*([A-Za-z]+)', line)
                if m:
                    return m.group(1).lower() == 'yes'
    except OSError:
        pass
    return True


def get_services_enabled():
    """Состояние всех протоколов для отрисовки ползунков."""
    return {
        tab: _read_enabled(sn)
        for tab, sn in TAB_TO_SERVICE.items()
    }


def _write_enabled(sn, value):
    """Атомарно переписывает строку ENABLED= в init-скрипте."""
    sc = SERVICE_SCRIPTS.get(sn)
    if not sc:
        raise ValueError(f"?: {sn}")
    if not os.path.exists(sc):
        raise FileNotFoundError(f"!: {sc}")

    with open(sc, 'r', encoding='utf-8',
              errors='replace') as f:
        lines = f.readlines()

    word = 'yes' if value else 'no'
    found = False
    for i, line in enumerate(lines):
        if re.match(r'\s*ENABLED\s*=', line):
            lines[i] = f'ENABLED={word}\n'
            found = True
            break
    if not found:
        # Строки нет — добавляем после shebang.
        pos = 1 if lines and lines[0].startswith('#!') else 0
        lines.insert(pos, f'ENABLED={word}\n')

    # Запись через временный файл: обрыв не оставит битый init-скрипт.
    tmp = f'{sc}.tmp.{os.getpid()}'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        os.chmod(tmp, 0o755)
        os.replace(tmp, sc)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _refresh_dns_health_async(reason):
    """Refresh canonical DNS once after a real lifecycle/config event.

    There is deliberately no timer here. The existing health owner performs
    the complete DoT/DoH and tunnel fallback check only after an event such as
    a tunnel/service transition. The health-only mode avoids rebuilding all
    resource lists. The script's shared update lock serializes it with the
    normal daily/WAN update path.
    """
    script = config.paths.get(
        'unblock_dnsmasq', '/opt/bin/unblock_dnsmasq.sh')
    if not os.path.exists(script):
        return
    env = dict(os.environ)
    env['DNS_HEALTH_ONLY'] = '1'
    env['DNS_EVENT_REASON'] = str(reason)
    try:
        argv = ([script] if os.access(script, os.X_OK)
                else ['/bin/sh', script])
        subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True)
    except Exception as e:
        log_error(f"DNS event refresh ({reason}): {e}")


def set_service_enabled(sn, value):
    """
    Переключает протокол: правит ENABLED, затем запускает или
    останавливает сервис. Правила netfilter переприменяются, чтобы
    трафик не уходил на порт остановленного сервиса.
    """
    _write_enabled(sn, value)

    sc = SERVICE_SCRIPTS.get(sn)
    action = 'start' if value else 'stop'
    try:
        result = _run_command(
            [sc, action], timeout=30, label=f'{sn} {action}')
        if result.returncode != 0:
            raise RuntimeError(
                f"{sn}: {action} завершился с rc={result.returncode}")
        if value and not _wait_service_ready(sn):
            raise RuntimeError(
                f"{sn}: процесс или listener не готов после start")

        if not _reapply_netfilter():
            raise RuntimeError(
                f"{sn}: netfilter не подтвердил применение правил")
    finally:
        # A stop/start changes whether tunnel-DNS is required. Refresh even
        # after a failed start so a stale healthy snapshot cannot win.
        _refresh_dns_health_async(f'{sn} {action}')


def _reapply_netfilter():
    """
    Переприменяет правила перехвата. Хук сам пропускает протоколы,
    у которых ENABLED=no, и снимает их прежние правила. Все три таблицы
    проверяются: filter также содержит raw-DNS fail-closed состояние.
    """
    hook = '/opt/etc/ndm/netfilter.d/100-redirect.sh'
    if not os.path.exists(hook):
        return True
    ok = True
    for table in ('nat', 'mangle', 'filter'):
        env = dict(os.environ,
                   type='iptable', table=table)
        result = None
        # 100-redirect.sh returns 75 only when another atomic update owns
        # the shared lock. That is a transient condition, not a failed
        # service operation. Retry the same table instead of leaving the
        # router in a half-applied interception state.
        for attempt in range(3):
            result = _run_command(
                [hook], env=env, timeout=90,
                label=f'netfilter table={table}')
            if result.returncode != 75:
                break
            time.sleep(2)
        if result is None or result.returncode != 0:
            ok = False
    return ok


def restart_service(sn):
    sc = SERVICE_SCRIPTS.get(sn)
    if not sc:
        raise ValueError(f"?: {sn}")
    if not os.path.exists(sc):
        raise FileNotFoundError(f"!: {sc}")
    os.chmod(sc, 0o755)
    # Истёкшее ожидание превращается в понятную ошибку: вызывающий код
    # ловит RuntimeError и показывает её пользователю.
    try:
        r = _run_command(
            [sc, 'restart'], timeout=30,
            label=f'{sn} restart')
        if r.returncode != 0:
            err = (r.stderr.strip() or r.stdout.strip())
            raise RuntimeError(f"{sn}: {err or 'restart failed'}")
        if not _wait_service_ready(sn):
            raise RuntimeError(
                f'{sn}: процесс или listener не готов после restart')
    finally:
        # Service restart is an explicit event; it is the only health refresh
        # here, not a recurring poll.
        _refresh_dns_health_async(f'{sn} restart')


def _pid_start_time(pid):
    try:
        with open(f'/proc/{int(pid)}/stat', 'r') as f:
            fields = f.read().split()
        return fields[21] if len(fields) > 21 else ''
    except (OSError, ValueError):
        return ''


def _lock_is_live(path):
    try:
        with open(os.path.join(path, 'pid'), 'r') as f:
            pid = int(f.read().strip())
        with open(os.path.join(path, 'start'), 'r') as f:
            saved = f.read().strip()
    except (OSError, ValueError):
        try:
            # os.mkdir is the atomic operation; pid/start are written just
            # after it. Do not let a concurrent caller remove that fresh
            # directory during the small metadata-write window.
            return time.time() - os.stat(path).st_mtime < 10
        except OSError:
            return False
    return bool(saved and _pid_start_time(pid) == saved)


def _acquire_launcher_lock(path):
    """Atomic launcher gate; status JSON alone is not a mutex."""
    for _ in range(2):
        try:
            os.mkdir(path)
        except FileExistsError:
            if _lock_is_live(path):
                return False
            shutil.rmtree(path, ignore_errors=True)
            continue
        except OSError:
            return False
        try:
            with open(os.path.join(path, 'pid'), 'w') as f:
                f.write(str(os.getpid()))
            start = _pid_start_time(os.getpid())
            with open(os.path.join(path, 'start'), 'w') as f:
                f.write(start)
            return True
        except OSError:
            shutil.rmtree(path, ignore_errors=True)
            return False
    return False


def _release_launcher_lock(path):
    shutil.rmtree(path, ignore_errors=True)


def _write_update_status(
        status, message=''):
    try:
        data = {
            'status': status,
            'ts': int(time.time()),
            'message': message}
        tmp = UPDATE_STATUS_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.rename(tmp, UPDATE_STATUS_FILE)
    except Exception:
        pass


def _read_update_status():
    if not os.path.exists(
            UPDATE_STATUS_FILE):
        return {
            'status': 'idle',
            'ts': 0, 'message': ''}
    try:
        with open(
                UPDATE_STATUS_FILE, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {
                'status': 'idle',
                'ts': 0, 'message': ''}
        return data
    except (json.JSONDecodeError,
            IOError, ValueError):
        return {
            'status': 'idle',
            'ts': 0, 'message': ''}


def _build_wrapper(sp, only_sets='', launcher_lock=''):
    # only_sets — частичное обновление: обрабатывается лишь указанный
    # набор ipset. Правка одной записи в списке раньше запускала полный
    # цикл по всем доменам всех протоколов (сотни DNS-запросов).
    lines = [
        '#!/bin/sh',
        'export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin',]
    if launcher_lock:
        lines += [
            'LAUNCH_LOCK=' + shlex.quote(launcher_lock),
            "trap 'rm -rf \"$LAUNCH_LOCK\" 2>/dev/null || true' EXIT INT TERM HUP",
            'printf \'%s\\n\' "$$" > "$LAUNCH_LOCK/pid"',
            'awk \'{print $22}\' "/proc/$$/stat" 2>/dev/null > "$LAUNCH_LOCK/start" || true',
        ]
    if only_sets:
        # shlex.quote защищает от подстановки: имя набора приходит из
        # таблицы BYPASS_FILES, но экранирование дешевле доверия.
        lines.append('export ONLY_SETS=' + shlex.quote(only_sets))
    lines += [
        'STATUS_FILE="' + UPDATE_STATUS_FILE + '"',
        'TMP_STATUS="' + UPDATE_STATUS_FILE + '.wtmp"',
        'LOG_FILE="' + UPDATE_LOG_FILE + '"',
        'SCRIPT="' + sp + '"',
        '',
        '# Lock и основной статус обслуживает SCRIPT.',
        '"$SCRIPT" >"$LOG_FILE" 2>&1',
        'RC=$?',
        '',
        '# Резервный статус только если SCRIPT не успел',
        '# записать собственный done/error.',
        'NEED_FALLBACK=0',
        '[ -f "$STATUS_FILE" ] || NEED_FALLBACK=1',
        'if [ -f "$STATUS_FILE" ]; then',
        '    grep -Eq '
        '\'"status"[[:space:]]*:[[:space:]]*"running"\' '
        '"$STATUS_FILE" && NEED_FALLBACK=1',
        'fi',
        '',
        'if [ "$NEED_FALLBACK" -eq 1 ]; then',
        '    TS=$(date +%s)',
        '    if [ "$RC" -eq 0 ]; then',
        '        printf '
        '\'{"status":"done","ts":%s,'
        '"message":"ok"}\n\' '
        '"$TS" > "$TMP_STATUS"',
        '    else',
        '        printf '
        '\'{"status":"error","ts":%s,'
        '"message":"exit code %s"}\n\' '
        '"$TS" "$RC" > "$TMP_STATUS"',
        '    fi',
        '    mv -f "$TMP_STATUS" "$STATUS_FILE"',
        'fi',
        '',
        'exit "$RC"',
    ]
    return '\n'.join(lines) + '\n'


def apply_unblock_async(only_sets=''):
    sc = '/opt/bin/unblock_update.sh'
    if not os.path.exists(sc):
        raise FileNotFoundError(sc)
    os.chmod(sc, 0o755)
    st = _read_update_status()
    if st.get('status') == 'running':
        age = time.time() - st.get('ts', 0)
        if age < UNBLOCK_TIMEOUT and _lock_is_live(UNBLOCK_LAUNCH_LOCK):
            raise RuntimeError(
                f"Уже ({int(age)}с).")
        if age < UNBLOCK_TIMEOUT:
            raise RuntimeError('Операция уже запускается')

    if not _acquire_launcher_lock(UNBLOCK_LAUNCH_LOCK):
        raise RuntimeError('Обновление уже запускается')
    try:
        _write_update_status('running', 'starting')
        with open(WRAPPER_SCRIPT, 'w') as f:
            f.write(_build_wrapper(
                sc, only_sets, UNBLOCK_LAUNCH_LOCK))
        os.chmod(WRAPPER_SCRIPT, 0o755)
        subprocess.Popen(
            ['/bin/sh', WRAPPER_SCRIPT],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except Exception:
        _release_launcher_lock(UNBLOCK_LAUNCH_LOCK)
        raise


# DNS health and AD/DNSSEC decisions belong to unblock_dnsmasq.sh. The panel
# consumes its bounded canonical snapshot below; it does not issue a second
# set of dig probes that could disagree with the owner or select an upstream.

def read_pinned_hosts():
    """Закреплённые адреса прокси-серверов из /opt/etc/hosts.

    Пин создаёт unblock_dnsmasq.sh, пока штатный DNS работает. Панель
    только показывает результат — если адрес сервера задан доменом,
    видно, какой IP закреплён на случай блокировки DNS.
    """
    path = config.paths.get(
        'hosts_file', '/opt/etc/hosts')
    begin = '# --- KeenZOO pinned'
    end = '# --- end KeenZOO pinned'
    out = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            inside = False
            for line in f:
                line = line.strip()
                if line.startswith(begin):
                    inside = True
                    continue
                if line.startswith(end):
                    break
                if inside and line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ipaddress.IPv4Address(parts[0])
                        except ipaddress.AddressValueError:
                            continue
                        out.append({
                            'ip': parts[0],
                            'host': parts[1]})
    except OSError:
        pass
    return out


def _netfilter_health():
    """Read-only netfilter/TPROXY readiness summary for the panel."""
    if not shutil.which(IPTABLES):
        return {'ok': False, 'state': 'iptables-unavailable'}
    rules = _run_command(
        [IPTABLES, '-w', '-t', 'mangle', '-S', 'PREROUTING'],
        timeout=5, label='netfilter health')
    policy = _run_command(
        ['ip', '-4', 'rule', 'show'],
        timeout=5, label='policy routing health')
    required = any(
        _service_ready(name)
        for name in ('vless', 'hysteria'))
    has_tproxy = 'TPROXY' in (rules.stdout or '')
    has_policy = bool(re.search(
        r'(?m)^.*(?:priority\s+1770|1770).*lookup\s+100',
        policy.stdout or ''))
    ok = rules.returncode == 0 and policy.returncode == 0 \
        and (not required or (has_tproxy and has_policy))
    return {
        'ok': ok,
        'state': 'ready' if ok else 'degraded',
        'tproxy_required': required,
        'tproxy_rules': has_tproxy,
        'policy_rule': has_policy,
    }


def read_dns_decision():
    """Read the canonical DNS owner state for display only.

    The bounded health log is already the snapshot consumed by
    unblock_ipset.sh; the panel must not make a second DNS decision. Unknown,
    stale, or malformed data is shown fail-closed as DNS_UNAVAILABLE.
    """
    allowed = {
        'LOCAL_DNSSEC': 'DNSSEC_OK',
        'DNS_OK_NO_DNSSEC': 'DNS_OK_NO_DNSSEC',
        'TUNNEL_DNS': 'TUNNEL_DNS',
        'DNS_UNAVAILABLE': 'DNS_UNAVAILABLE',
    }
    line = ''
    try:
        with open(DNS_HEALTH_LOG, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536), os.SEEK_SET)
            tail = f.read(65536).decode('utf-8', 'replace')
        for candidate in reversed(tail.splitlines()):
            if 'decision=final ' in candidate:
                line = candidate
                break
    except OSError:
        pass

    fields = dict(re.findall(r'([a-z_]+)=([^ ]+)', line))
    mode = fields.get('mode', '')
    level = fields.get('level', '')
    state = allowed.get(mode, '')
    if state == 'DNSSEC_OK' and level != 'DNSSEC_OK':
        state = ''
    if state == 'DNS_OK_NO_DNSSEC' and level != 'DNS_OK_NO_DNSSEC':
        state = ''
    if state == 'TUNNEL_DNS' and level != 'TUNNEL_DNS':
        state = ''
    if state in ('DNSSEC_OK', 'DNS_OK_NO_DNSSEC') \
            and fields.get('required') != '0':
        state = ''
    if state == 'DNSSEC_OK' and fields.get('verified') != '0':
        state = ''
    if state == 'TUNNEL_DNS' and fields.get('verified') != '1':
        state = ''
    if state == 'TUNNEL_DNS' \
            and fields.get('tunnel') not in ('xray', 'trojan', 'hysteria'):
        state = ''
    epoch = int(fields['epoch']) if fields.get('epoch', '').isdigit() else 0
    if not epoch or time.time() < epoch \
            or time.time() - epoch > DNS_SNAPSHOT_MAX_AGE:
        state = ''

    def _port_values(value):
        values = []
        for raw in value.replace(',', ' ').split():
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                values.append(str(int(raw)))
        return values

    working_ports = _port_values(fields.get('ports', '')) if state else []
    secure_ports = _port_values(fields.get('secure', '')) if state else []
    insecure_ports = _port_values(fields.get('insecure', '')) if state else []
    # Accept snapshots written by the previous release during a bounded
    # migration window. Their mode still identifies LOCAL_DNSSEC and the
    # insecure fallback; tunnel snapshots remain non-DNSSEC per fail-closed UI.
    if state == 'DNSSEC_OK' and not secure_ports:
        secure_ports = list(working_ports)
    elif state == 'DNS_OK_NO_DNSSEC' and not insecure_ports:
        insecure_ports = list(working_ports)
    if not state:
        state = 'DNS_UNAVAILABLE'
    return {
        'state': state,
        'mode': mode or 'unknown',
        'level': level or 'unknown',
        'epoch': epoch,
        'line_present': bool(line),
        'working_ports': working_ports,
        'secure_ports': secure_ports,
        'insecure_ports': insecure_ports,
    }


def _snapshot_port_result(port, decision):
    """Render one configured DoT/DoH port from the canonical DNS snapshot."""
    port = str(port)
    canonical = decision.get('state', 'DNS_UNAVAILABLE')
    secure = set(decision.get('secure_ports', []))
    insecure = set(decision.get('insecure_ports', []))
    working = set(decision.get('working_ports', []))
    if canonical == 'TUNNEL_DNS':
        if port in working:
            return {
                'ok': True,
                'secure': False,
                'state': 'tunnel-dns',
                'detail': 'canonical TUNNEL_DNS',
            }
        return {
            'ok': False,
            'secure': False,
            'state': 'dns-failed',
            'detail': 'not present in canonical tunnel DNS ports',
        }
    if port in secure:
        return {
            'ok': True,
            'secure': True,
            'state': 'dnssec-ok',
            'detail': 'canonical DNSSEC_OK',
        }
    if port in insecure or port in working:
        return {
            'ok': True,
            'secure': False,
            'state': 'dns-ok-no-dnssec',
            'detail': 'canonical DNS response without AD',
        }
    return {
        'ok': False,
        'secure': False,
        'state': 'dns-failed',
        'detail': 'not present in canonical working ports',
    }


def check_dns_ports():
    decision = read_dns_decision()
    res = {
        'dot': {},
        'doh': {},
        'health_domain': DNS_HEALTH_DOMAIN,
    }
    for p in DNS_PORTS_DOT:
        res['dot'][str(p)] = _snapshot_port_result(p, decision)
    for p in DNS_PORTS_DOH:
        res['doh'][str(p)] = _snapshot_port_result(p, decision)
    res['services'] = {
        name: {
            'ready': _service_ready(name),
            'process': _proc_alive(data[0]),
            'port': data[1],
        }
        for name, data in SERVICE_READINESS.items()
    }
    res['netfilter'] = _netfilter_health()
    res['pinned'] = read_pinned_hosts()
    res['decision'] = decision
    res['dns_state'] = decision['state']
    res['netfilter_state'] = (
        'NETFILTER_DEGRADED'
        if not res['netfilter'].get('ok') else 'NETFILTER_OK')
    # Keep the canonical DNS state and firewall health as separate contracts.
    # NETFILTER_* must never become a DNS legend/state colour.
    res['states'] = [res['dns_state']]
    return res

def _clean_entry(entry):
    return entry.split('#')[0].strip()


def _validate_cidr(entry):
    m = re.match(
        r'^(\d{1,3})\.(\d{1,3})\.'
        r'(\d{1,3})\.(\d{1,3})'
        r'/(\d{1,2})$', entry)
    if not m:
        return False
    o = [int(m.group(i))
         for i in range(1, 5)]
    p = int(m.group(5))
    return (all(x <= 255 for x in o)
            and 0 <= p <= 32)


def _validate_ip(entry):
    m = re.match(
        r'^(\d{1,3})\.(\d{1,3})\.'
        r'(\d{1,3})\.(\d{1,3})$', entry)
    if not m:
        return False
    return all(
        int(m.group(i)) <= 255
        for i in range(1, 5))


def _validate_entry(ce):
    if '/' in ce:
        return (('cidr', ce)
                if _validate_cidr(ce)
                else None)
    if _validate_ip(ce):
        return ('ip', ce)
    if ce.startswith('#'):
        return None
    if re.match(
        r'^(\*\.)?[a-zA-Z0-9]'
        r'([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]'
        r'([a-zA-Z0-9\-]*'
        r'[a-zA-Z0-9])?)*$', ce):
        return ('domain', ce)
    return None


def read_file_text(fp):
    if not os.path.exists(fp):
        return ''
    with open(fp, 'r',
              encoding='utf-8') as f:
        return f.read().rstrip('\n\r')


def _atomic_write_text(filepath, text):
    directory = os.path.dirname(filepath)
    base = os.path.basename(filepath)
    tmp = os.path.join(
        directory,
        f'.{base}.{os.getpid()}.tmp')

    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, filepath)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def _read_blocks(fp):
    if not os.path.exists(fp):
        return []
    secs = []
    cc = None
    ce = []
    with open(fp, 'r',
              encoding='utf-8') as f:
        for raw in f:
            s = (raw.rstrip('\n')
                 .rstrip('\r').strip())
            if not s:
                if ce:
                    secs.append((cc, ce))
                    cc = None
                    ce = []
                continue
            if s.startswith('#'):
                if ce:
                    secs.append((cc, ce))
                    ce = []
                cc = s[1:].strip()
            else:
                ce.append(s)
    if ce:
        secs.append((cc, ce))
    return secs


def _all_bypass_filepaths():
    fps = list(BYPASS_FILES.values())
    try:
        for n in os.listdir(UNBLOCK_DIR):
            if (n.startswith('vpn-')
                    and n.endswith('.txt')):
                fps.append(os.path.join(
                    UNBLOCK_DIR, n))
    except Exception:
        pass
    return fps


def _build_global_bypass_index(
        exclude_filepath=None):
    gm = {}
    for fp in _all_bypass_filepaths():
        if (exclude_filepath
                and os.path.realpath(fp)
                == os.path.realpath(
                    exclude_filepath)):
            continue
        fl = os.path.splitext(
            os.path.basename(fp))[0]
        for comment, entries in (
                _read_blocks(fp)):
            for entry in entries:
                c = _clean_entry(entry)
                if c and c not in gm:
                    gm[c] = {
                        'file': fl,
                        'comment': comment}
    return gm


def _count_entries(text):
    d = ip = cidr = 0
    for line in text.split('\n'):
        s = line.strip()
        if s and not s.startswith('#'):
            c = _clean_entry(s)
            if c:
                r = _validate_entry(c)
                if r:
                    if r[0] == 'cidr':
                        cidr += 1
                    elif r[0] == 'ip':
                        ip += 1
                    else:
                        d += 1
    return d, ip, cidr


def _format_details(d, ip, cidr):
    p = []
    if d:
        p.append(f'{d} доменов')
    if ip:
        p.append(f'{ip} IP')
    if cidr:
        p.append(f'{cidr} CIDR')
    return (', '.join(p)
            if p else '0 записей')


def _optimize_networks(sections):
    an = []
    nte = {}
    for _c, entries in sections:
        for entry in entries:
            cl = _clean_entry(entry)
            r = _validate_entry(cl)
            if r and r[0] in ('ip', 'cidr'):
                try:
                    net = ipaddress.ip_network(
                        cl if '/' in cl
                        else cl + '/32',
                        strict=False)
                    if net not in nte:
                        an.append(net)
                        nte[net] = entry
                except ValueError:
                    pass
    if len(an) < 2:
        return sections, []
    oc = len(nte)
    col = set(
        ipaddress.collapse_addresses(an))
    cc = len(col)
    if cc >= oc:
        return sections, []
    os_set = set(nte.keys())
    surv = os_set & col
    nfm = col - os_set
    del an, os_set
    rt = 0
    ns = []
    bi = 0
    bd = 0
    for idx, (comment, entries) in (
            enumerate(sections)):
        ne = []
        sr = 0
        for entry in entries:
            cl = _clean_entry(entry)
            r = _validate_entry(cl)
            if r and r[0] in ('ip', 'cidr'):
                try:
                    net = ipaddress.ip_network(
                        cl if '/' in cl
                        else cl + '/32',
                        strict=False)
                    if net in surv:
                        ne.append(entry)
                    else:
                        sr += 1
                except ValueError:
                    ne.append(entry)
            else:
                ne.append(entry)
        rt += sr
        ns.append((comment, ne))
        if sr > bd:
            bd = sr
            bi = idx
    del surv, nte
    if nfm:
        merged = []
        for net in sorted(nfm):
            merged.append(
                str(net.network_address)
                if net.prefixlen == 32
                else str(net))
        if bd > 0:
            c, e = ns[bi]
            ns[bi] = (c, e + merged)
        else:
            ns.append((
                'Оптимизированные', merged))
    rep = []
    saved = oc - cc
    if rt > 0:
        rep.append(
            f"\U0001f4e6 CIDR: "
            f"удалено {rt}")
    if nfm:
        rep.append(
            f"\U0001f4e6 CIDR: "
            f"создано {len(nfm)}")
    if saved > 0:
        rep.append(
            f"\U0001f4e6 {oc}"
            f"\u2192{cc} "
            f"(\u2248"
            f"{saved*100//oc}%)")
    return ns, rep


def _sort_key(entry):
    cl = _clean_entry(entry)
    try:
        net = ipaddress.ip_network(
            cl, strict=False)
        return (
            1,
            net.network_address.packed,
            net.prefixlen)
    except ValueError:
        pass
    try:
        addr = ipaddress.ip_address(cl)
        return (1, addr.packed, 32)
    except ValueError:
        pass
    return (0, cl.lower().encode(), 0)


def parse_and_save(
        filepath, text,
        skip_global_dedup=False):
    rb = os.path.realpath(UNBLOCK_DIR)
    rp = os.path.realpath(filepath)
    if not rp.startswith(rb + os.sep):
        raise ValueError("Путь")
    lines = text.split('\n')
    if len(lines) > MAX_LIST_LINES:
        raise ValueError(
            f"Строк: {len(lines)}")
    os.makedirs(UNBLOCK_DIR, exist_ok=True)
    secs = []
    cc = None
    ce = []
    errors = []
    dups = []
    seen = {}
    gs = (
        {} if skip_global_dedup
        else _build_global_bypass_index(
            exclude_filepath=filepath))
    for line in lines:
        s = line.strip()
        if not s:
            if ce:
                secs.append((cc, ce))
                cc = None
                ce = []
            continue
        if s.startswith('#'):
            if ce:
                secs.append((cc, ce))
                ce = []
            cc = s[1:].strip()
        else:
            cl = _clean_entry(s)
            if not cl:
                continue
            r = _validate_entry(cl)
            if r is None:
                errors.append(
                    f"\u26a0\ufe0f {cl}")
                continue
            if cl in seen:
                c = seen[cl]
                dups.append(
                    f"\u26a0\ufe0f {cl}"
                    + (f" (#{c})"
                       if c else ""))
                continue
            if cl in gs:
                info = gs[cl]
                dups.append(
                    f"\u26a0\ufe0f {cl}"
                    f" ({info['file']}.txt"
                    + (f", #{info['comment']}"
                       if info['comment']
                       else "")
                    + ")")
                continue
            seen[cl] = cc
            ce.append(s)
    if ce:
        secs.append((cc, ce))
    del seen, gs
    secs, cr = _optimize_networks(secs)
    out = []
    named = sorted(
        [(c, e) for c, e in secs
         if c is not None and e],
        key=lambda item: item[0].lower())
    unnamed = [
        e for c, e in secs
        if c is None for e in e]
    cd = ci = cc2 = 0
    for i, (comment, entries) in (
            enumerate(named)):
        if i > 0:
            out.append('')
        out.append(f'#{comment}')
        for entry in sorted(
                entries, key=_sort_key):
            out.append(entry)
            cl = _clean_entry(entry)
            r = _validate_entry(cl)
            if r:
                if r[0] == 'cidr':
                    cc2 += 1
                elif r[0] == 'ip':
                    ci += 1
                else:
                    cd += 1
    if unnamed:
        if named:
            out.append('')
        for entry in sorted(
                unnamed, key=_sort_key):
            out.append(entry)
            cl = _clean_entry(entry)
            r = _validate_entry(cl)
            if r:
                if r[0] == 'cidr':
                    cc2 += 1
                elif r[0] == 'ip':
                    ci += 1
                else:
                    cd += 1
    _atomic_write_text(
        filepath,
        '\n'.join(out) + '\n'
        if out else '')
    return {
        'total': cd + ci + cc2,
        'domains': cd, 'ips': ci,
        'cidr': cc2, 'errors': errors,
        'duplicates': dups,
        'cidr_report': cr,
    }


def _lookup_resource(query):
    results = {
        'query': query, 'ips': [],
        'cidrs': [], 'domains': [],
        'in_lists': {}, 'errors': [],
        'missing': [], 'found': [],
        'covered': {},
    }
    q = query.strip().lower()

    presets = {
        'telegram': {
            'cidr_url': (
                'https://core.telegram.org'
                '/resources/cidr.txt'),
            'domains': [
                'api.telegram.org',
                'cdn-telegram.org',
                'telegram.org', 't.me',
                'core.telegram.org',
                'telegra.ph',
                'telegram.me',
            ],
        },
        'whatsapp': {
            'domains': [
                'whatsapp.com',
                'whatsapp.net', 'wa.me',
                'web.whatsapp.com',
                'static.whatsapp.net',
                'mmg.whatsapp.net',
                'media.fna.whatsapp.net',
                'pps.whatsapp.net',
                'fbcdn.com', 'fbcdn.net',
            ],
        },
        'youtube': {
            'domains': [
                'youtube.com',
                'youtu.be',
                'googlevideo.com',
                'ytimg.com',
                'ggpht.com',
                'googleusercontent.com',
                'youtube-nocookie.com',
                'googleapis.com',
            ],
        },
    }

    # IPv4-only фильтр
    _ip4 = re.compile(
        r'^\d+\.\d+\.\d+\.\d+$')
    # Имя хоста: буквы/цифры/дефис/точка, без ведущего дефиса.
    _host_re = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}'
        r'(?:\.(?!-)[a-z0-9-]{1,63})*\.?$')
    _cidr4 = re.compile(
        r'^\d+\.\d+\.\d+\.\d+/\d+$')

    if q in presets:
        preset = presets[q]
        results['domains'] = list(
            preset.get('domains', []))
        cidr_url = preset.get('cidr_url')
        if cidr_url:
            try:
                r = _run_command(
                    ['curl', '-s',
                     '--max-time', '10',
                     cidr_url],
                    timeout=15,
                    label='preset CIDR lookup')
                if r.returncode == 0:
                    for line in (
                            r.stdout.strip()
                            .split('\n')):
                        line = line.strip()
                        if (line
                                and _cidr4.match(
                                    line)):
                            results[
                                'cidrs'
                            ].append(line)
            except Exception:
                pass
        for domain in results['domains']:
            try:
                r = _run_command(
                    ['dig', '+short',
                     domain, '@localhost'],
                    timeout=10,
                    label=f'preset DNS lookup {domain}')
                for ip in (
                        r.stdout.strip()
                        .split('\n')):
                    ip = ip.strip()
                    if (_ip4.match(ip)
                            and ip not in
                            results['ips']):
                        results[
                            'ips'
                        ].append(ip)
            except Exception:
                pass
    elif _ip4.match(q):
        results['ips'] = [q]
    elif _cidr4.match(q):
        results['cidrs'] = [q]
    elif (q.startswith('as')
          and q[2:].isdigit()):
        asn = q.upper()
        try:
            r = _run_command(
                ['curl', '-s',
                 '--max-time', '15',
                 'https://stat.ripe.net'
                 '/data/announced-prefixes'
                 '/data.json'
                 f'?resource={asn}'],
                timeout=20,
                label=f'ASN lookup {asn}')
            if r.returncode == 0:
                data = json.loads(
                    r.stdout)
                for p in (
                        data.get('data', {})
                        .get('prefixes',
                             [])):
                    prefix = p.get(
                        'prefix', '')
                    if (prefix
                            and _cidr4.match(
                                prefix)):
                        results[
                            'cidrs'
                        ].append(prefix)
        except Exception as e:
            results['errors'].append(
                str(e))
    else:
        # Валидация домена перед передачей во внешнюю утилиту.
        # Раньше в dig уходила произвольная строка: значение вида
        # "-f/etc/passwd" трактовалось бы как ОПЦИЯ, а не имя хоста
        # (аргументы передаются списком, поэтому shell-инъекция была
        # невозможна, но подмена опции — вполне).
        if not _host_re.match(q) or len(q) > 253:
            results['errors'].append(
                'Недопустимое имя хоста')
            results['domains'] = []
            return results
        results['domains'] = [q]
        try:
            r = _run_command(
                ['dig', '+short', '--', q,
                 '@localhost'],
                timeout=10,
                label=f'DNS lookup {q}')
            for ip in (
                    r.stdout.strip()
                    .split('\n')):
                ip = ip.strip()
                if _ip4.match(ip):
                    results[
                        'ips'
                    ].append(ip)
        except Exception:
            pass
        try:
            r = _run_command(
                ['dig', '+short', 'CNAME',
                 '--', q, '@localhost'],
                timeout=10,
                label=f'CNAME lookup {q}')
            for cname in (
                    r.stdout.strip()
                    .split('\n')):
                cname = (
                    cname.strip()
                    .rstrip('.'))
                if (cname and cname != q
                        and ':' not in
                        cname):
                    results[
                        'domains'
                    ].append(cname)
        except Exception:
            pass

    # ═══════════════════════════════
    # Загрузить все записи из списков
    # ═══════════════════════════════

    list_domains = {}  # domain → [files]
    list_cidrs = []    # [(network, file)]

    for fp in _all_bypass_filepaths():
        fname = os.path.splitext(
            os.path.basename(fp))[0]
        if not os.path.exists(fp):
            continue
        for line in (
                read_file_text(fp)
                .split('\n')):
            entry = line.split('#')[0].strip()
            if not entry:
                continue
            if _cidr4.match(entry):
                try:
                    net = (
                        ipaddress.ip_network(
                            entry,
                            strict=False))
                    list_cidrs.append(
                        (net, fname))
                except ValueError:
                    pass
            elif _ip4.match(entry):
                try:
                    net = (
                        ipaddress.ip_network(
                            entry + '/32',
                            strict=False))
                    list_cidrs.append(
                        (net, fname))
                except ValueError:
                    pass
            elif entry and '/' not in entry:
                if entry not in list_domains:
                    list_domains[entry] = []
                list_domains[entry].append(
                    fname)

    # ═══════════════════════════════
    # Проверка доменов
    # (точное + родительский домен)
    # ═══════════════════════════════

    all_items = set()
    found_anywhere = set()
    covered = {}

    for domain in results['domains']:
        all_items.add(domain)
        # Точное совпадение
        if domain in list_domains:
            found_anywhere.add(domain)
            for f in list_domains[domain]:
                results['in_lists']. \
                    setdefault(f, []) \
                    .append(domain)
            continue
        # Родительский домен
        parts = domain.split('.')
        parent_found = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in list_domains:
                found_anywhere.add(domain)
                covered[domain] = parent
                for f in (
                        list_domains[parent]):
                    results['in_lists']. \
                        setdefault(f, []) \
                        .append(
                            f"{domain} "
                            f"({parent})")
                parent_found = True
                break
        if not parent_found:
            pass  # пойдёт в missing

    # ═══════════════════════════════
    # Проверка IP
    # (точное + вхождение в CIDR)
    # ═══════════════════════════════

    for ip_str in results['ips']:
        all_items.add(ip_str)
        try:
            ip_addr = ipaddress.ip_address(
                ip_str)
        except ValueError:
            continue
        ip_found = False
        # Точное
        if ip_str in list_domains:
            found_anywhere.add(ip_str)
            ip_found = True
            for f in list_domains[ip_str]:
                results['in_lists']. \
                    setdefault(f, []) \
                    .append(ip_str)
        # Вхождение в CIDR
        if not ip_found:
            for net, fname in list_cidrs:
                if ip_addr in net:
                    found_anywhere.add(
                        ip_str)
                    covered[ip_str] = (
                        str(net))
                    results['in_lists']. \
                        setdefault(
                            fname, []) \
                        .append(
                            f"{ip_str} "
                            f"({net})")
                    ip_found = True
                    break

    # ═══════════════════════════════
    # Проверка CIDR
    # (точное + вхождение в больший)
    # ═══════════════════════════════

    for cidr_str in results['cidrs']:
        all_items.add(cidr_str)
        try:
            check_net = (
                ipaddress.ip_network(
                    cidr_str, strict=False))
        except ValueError:
            continue
        for net, fname in list_cidrs:
            if (check_net.subnet_of(net)
                    and check_net != net):
                # Вложен в больший
                found_anywhere.add(cidr_str)
                covered[cidr_str] = (
                    str(net))
                results['in_lists']. \
                    setdefault(fname, []) \
                    .append(
                        f"{cidr_str} "
                        f"({net})")
                break
            elif check_net == net:
                # Точное совпадение
                found_anywhere.add(cidr_str)
                results['in_lists']. \
                    setdefault(fname, []) \
                    .append(cidr_str)
                break

    results['missing'] = sorted(
        all_items - found_anywhere)
    results['found'] = sorted(
        found_anywhere)
    results['covered'] = covered

    return results


PAGE_TEMPLATE = r'''
<!DOCTYPE html><html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport"
  content="width=device-width,
  initial-scale=1">
<title>Генератор конфигураций</title>
<style>
/* Glassmorphism: полупрозрачные панели над мягким градиентом.
   Градиент задан фиксированным слоем (background-attachment:fixed),
   чтобы при прокрутке не пересчитывался — это заметно экономит
   ресурсы на слабых клиентах. Размытие backdrop-filter применяется
   только к крупным контейнерам, а не к каждому элементу. */
:root{--txt:#eaf0ff;--muted:#93a2c9;
  --accent:#4dd0ff;--accent2:#7c8cff;
  --green:#3ddc97;--red:#ff6b7a;
  --yellow:#ffc15a;--blue:#70a7ff;
  --orange:#ffab5e;
  --gl:rgba(255,255,255,.07);
  --gl2:rgba(255,255,255,.12);
  --brd:rgba(255,255,255,.16);
  --shd:0 8px 32px rgba(0,0,0,.28);
  /* Используется инлайн-стилем поля результатов поиска. */
  --bg:rgba(0,0,0,.22)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;
  color:var(--txt);min-height:100vh;
  background:#0b1020;
  background-image:
    radial-gradient(at 12% 18%,
      rgba(80,90,255,.32) 0,transparent 45%),
    radial-gradient(at 85% 12%,
      rgba(0,200,255,.24) 0,transparent 45%),
    radial-gradient(at 70% 88%,
      rgba(160,80,255,.24) 0,transparent 45%);
  background-attachment:fixed;
  display:flex;flex-direction:column;
  align-items:center;padding:1.2rem 1rem}
h1{font-size:1.35rem;margin-bottom:1rem;
  font-weight:600;letter-spacing:.3px;
  color:var(--txt);text-align:center}

/* ── Каркас: меню слева, настройки справа ── */
.shell{display:flex;gap:1rem;width:100%;
  max-width:1080px;align-items:flex-start}
.tabs{display:flex;flex-direction:column;
  gap:.4rem;width:190px;flex-shrink:0;
  background:var(--gl);
  border:1px solid var(--brd);
  border-radius:16px;padding:.7rem;
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  box-shadow:var(--shd);
  position:sticky;top:1rem}
.tab-btn{padding:.6rem .8rem;
  border:1px solid transparent;
  border-radius:11px;background:transparent;
  color:var(--muted);cursor:pointer;
  font-size:.84rem;text-align:left;
  width:100%;transition:.15s}
.tab-btn:hover{background:var(--gl2);
  color:var(--txt)}
.tab-btn.active{background:var(--gl2);
  border-color:var(--accent);
  color:var(--accent);font-weight:600}
.card{flex:1;min-width:0;
  background:var(--gl);
  border:1px solid var(--brd);
  border-radius:16px;padding:1.4rem;
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  box-shadow:var(--shd)}
.tab-content{display:none}
.tab-content.active{display:block}

label{display:block;font-size:.78rem;
  color:var(--muted);margin-bottom:.35rem}
textarea,input[type=text]{width:100%;
  padding:.65rem .85rem;
  background:rgba(0,0,0,.22);
  border:1px solid var(--brd);
  border-radius:11px;color:var(--txt);
  font-size:.85rem;
  font-family:'Consolas',monospace;
  resize:vertical;transition:.15s}
textarea:focus,input:focus{outline:none;
  border-color:var(--accent);
  background:rgba(0,0,0,.3)}
textarea::placeholder,input::placeholder{
  color:#6b789b}
.key-area{min-height:88px}
.list-area{min-height:250px;line-height:1.5}
.hint{font-size:.7rem;color:var(--muted);
  margin:.3rem 0 .8rem;line-height:1.4}
.hint code{background:rgba(0,0,0,.28);
  padding:.1rem .35rem;border-radius:5px}
.divider{height:1px;background:var(--brd);
  margin:1.2rem 0;display:flex;
  align-items:center;justify-content:center}
.divider span{background:#131a30;
  color:var(--accent);font-size:.76rem;
  font-weight:600;padding:0 .8rem;
  border-radius:8px}

.btn{width:100%;padding:.65rem;
  border:1px solid var(--brd);
  border-radius:11px;background:var(--gl2);
  color:var(--txt);font-size:.86rem;
  font-weight:600;cursor:pointer;
  transition:.15s;min-height:2.6rem;
  display:flex;align-items:center;
  justify-content:center;gap:.4rem}
.btn:hover{background:rgba(255,255,255,.18)}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.5;
  cursor:not-allowed;transform:none}
.btn-key{border-color:rgba(77,208,255,.5);
  color:var(--accent)}
.btn-cfg{border-color:rgba(255,171,94,.5);
  color:var(--orange);margin-top:.4rem}
.btn-save{border-color:rgba(61,220,151,.5);
  color:var(--green);margin-top:.4rem}
.btn .spinner-ring{display:none;
  width:1rem;height:1rem;
  border:2px solid rgba(255,255,255,.25);
  border-top-color:currentColor;
  border-radius:50%;
  animation:spin .6s linear infinite}
.btn.loading .spinner-ring{
  display:inline-block}
.btn.loading .btn-label{opacity:.7}
@keyframes spin{to{
  transform:rotate(360deg)}}

.msg{margin:.7rem auto;padding:.7rem 1rem;
  border-radius:12px;font-size:.83rem;
  max-width:1080px;width:100%;
  background:var(--gl);
  border:1px solid var(--brd);
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px);
  white-space:pre-line}
.msg-ok{border-left:3px solid var(--green);
  color:var(--green)}
.msg-err{border-left:3px solid var(--red);
  color:var(--red)}
.counter{font-size:.7rem;color:var(--muted);
  text-align:right;margin-top:.2rem}

#update-bar{display:none;max-width:1080px;
  width:100%;margin:.5rem auto;
  padding:.65rem 1rem;border-radius:12px;
  font-size:.83rem;text-align:center;
  background:var(--gl);
  border:1px solid var(--brd);
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px)}
#update-bar.running{display:block;
  border-left:3px solid var(--accent);
  color:var(--accent)}
#update-bar.done{display:block;
  border-left:3px solid var(--green);
  color:var(--green)}
#update-bar.error{display:block;
  border-left:3px solid var(--red);
  color:var(--red)}

/* Доступность серверов обхода. Пишется unblock_dnsmasq.sh. */
#pin-bar{display:none;max-width:1080px;
  width:100%;margin:.5rem auto;
  padding:.65rem 1rem;border-radius:12px;
  font-size:.83rem;text-align:center;
  white-space:pre-wrap;
  background:var(--gl);
  border:1px solid var(--brd);
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px)}
#pin-bar.warn{display:block;
  border-left:3px solid var(--red);
  color:var(--red)}
#pin-bar.ok{display:block;
  border-left:3px solid var(--green);
  color:var(--green)}

/* ── Переключатель протокола ── */
.svc-row{display:flex;align-items:center;
  justify-content:space-between;
  background:rgba(0,0,0,.2);
  border:1px solid var(--brd);
  border-radius:12px;padding:.6rem .9rem;
  margin-bottom:1.1rem}
.svc-name{font-size:.82rem;font-weight:600;
  color:var(--muted);margin-right:.6rem;
  min-width:0;overflow-wrap:anywhere}
.svc-name.on{color:var(--green)}
.svc-name.off{color:var(--red)}
.switch{position:relative;display:inline-block;
  width:50px;height:26px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;
  inset:0;background:rgba(255,255,255,.12);
  border:1px solid var(--brd);
  border-radius:26px;transition:.2s}
.slider:before{position:absolute;content:"";
  height:18px;width:18px;left:3px;bottom:3px;
  background:var(--muted);border-radius:50%;
  transition:.2s}
.switch input:checked+.slider{
  background:rgba(61,220,151,.28);
  border-color:var(--green)}
.switch input:checked+.slider:before{
  transform:translateX(23px);
  background:var(--green)}

/* ── Нижние панели ── */
.dns-panel{max-width:1080px;width:100%;
  margin-top:1rem}
.dns-toggle{background:var(--gl);
  border:1px solid var(--brd);
  border-radius:12px;padding:.55rem .8rem;
  color:var(--muted);font-size:.75rem;
  cursor:pointer;width:100%;
  text-align:center;transition:.15s;
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px)}
.dns-toggle:hover{color:var(--accent);
  border-color:var(--accent)}
.dns-grid{display:none;
  grid-template-columns:repeat(4,1fr);
  gap:.5rem;margin-top:.5rem;
  background:var(--gl);
  border:1px solid var(--brd);
  border-radius:14px;padding:.85rem;
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px)}
.dns-grid.open{display:grid}
.dns-port{text-align:center;padding:.35rem;
  border-radius:9px;font-size:.72rem;
  font-family:monospace;
  background:rgba(0,0,0,.2);
  border:1px solid var(--brd)}
.dns-port.dnssec{color:var(--green);
  border-color:rgba(61,220,151,.4)}
.dns-port.no-dnssec{color:var(--yellow);
  border-color:rgba(255,193,7,.45)}
.dns-port.tunnel{color:var(--blue);
  border-color:rgba(112,167,255,.5)}
.dns-port.unavailable{color:var(--red);
  border-color:rgba(255,107,122,.4)}
.dns-port.checking{color:var(--muted)}
.dns-state{grid-column:span 2;text-align:center;
  padding:.5rem;border-radius:9px;font-size:.74rem;
  font-family:ui-monospace,monospace;
  background:rgba(0,0,0,.2);border:1px solid var(--brd)}
.dns-state.dnssec{color:var(--green);
  border-color:rgba(61,220,151,.4)}
.dns-state.no-dnssec{color:var(--yellow);
  border-color:rgba(255,193,7,.45)}
.dns-state.tunnel{color:var(--blue);
  border-color:rgba(112,167,255,.5)}
.dns-state.unavailable{color:var(--red);
  border-color:rgba(255,107,122,.4)}
.netfilter-status{grid-column:span 2;text-align:center;
  padding:.5rem;border-radius:9px;font-size:.68rem;
  font-family:ui-monospace,monospace;background:rgba(0,0,0,.14);
  border:1px dashed var(--brd);color:var(--muted)}
.netfilter-status.ok{color:var(--green);
  border-color:rgba(61,220,151,.35)}
.netfilter-status.degraded{color:var(--orange);
  border-color:rgba(255,171,94,.45)}
.dns-legend{grid-column:1/-1;display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));gap:.3rem;
  font:600 .58rem ui-monospace,monospace;text-align:center}
.dns-legend span{padding:.35rem .2rem;border:1px solid var(--brd);
  border-radius:6px;color:var(--muted);overflow-wrap:anywhere}
.dns-legend .dnssec{color:var(--green);border-color:rgba(61,220,151,.4)}
.dns-legend .no-dnssec{color:var(--yellow);border-color:rgba(255,193,7,.45)}
.dns-legend .tunnel{color:var(--blue);border-color:rgba(112,167,255,.5)}
.dns-legend .unavailable{color:var(--red);border-color:rgba(255,107,122,.4)}
.dns-label{font-size:.7rem;color:var(--muted);
  margin:.4rem 0 .1rem;font-weight:600;
  grid-column:1/-1;background:none;
  border:none;text-align:left}
.ver-grid{display:none;
  grid-template-columns:1fr 1fr;gap:.5rem;
  margin-top:.5rem;background:var(--gl);
  border:1px solid var(--brd);
  border-radius:14px;padding:.85rem;
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px)}
.ver-grid.open{display:grid}
/* Ячейка протокола: строка версии, под ней — кнопка обновления,
   которая показывается только при наличии обновления. */
.ver-item{display:flex;flex-direction:column;
  gap:.35rem}
.upd-all-row{grid-column:1/-1;display:none}
.upd-all-row.on{display:block}
.upd-btn{display:none;width:100%;
  font-size:.78rem;padding:.42rem .6rem;
  border-color:rgba(255,171,94,.5);
  color:var(--orange)}
.upd-btn.on{display:block}
.upd-all-row .upd-btn{display:block}
.upd-out{display:none;white-space:pre-wrap;
  font-family:ui-monospace,monospace;
  font-size:.78rem;line-height:1.35;
  max-height:15rem;overflow:auto;
  padding:.6rem .7rem;border-radius:.5rem;
  background:rgba(0,0,0,.28);
  border:1px solid rgba(255,255,255,.12);
  word-break:break-word}
.upd-out.on{display:block}
/* Закреплённые в /opt/etc/hosts адреса прокси-серверов. */
.pin-box{display:none;grid-column:1/-1;
  white-space:pre-wrap;
  font-family:ui-monospace,monospace;
  font-size:.74rem;line-height:1.5;
  color:var(--muted);padding:.45rem .6rem;
  border-radius:.5rem;
  background:rgba(0,0,0,.22);
  border:1px solid rgba(255,255,255,.1);
  word-break:break-all}
.pin-box.on{display:block}

.info-box{background:rgba(255,171,94,.1);
  border:1px solid rgba(255,171,94,.35);
  border-radius:12px;padding:.8rem;
  margin-bottom:1rem;font-size:.77rem;
  line-height:1.5;color:var(--orange)}
.info-box code{background:rgba(0,0,0,.3);
  padding:.1rem .35rem;border-radius:5px}
.lk-presets{display:flex;gap:.5rem;
  flex-wrap:wrap;margin-bottom:.9rem}
.lk-presets button{padding:.35rem .8rem;
  border:1px solid var(--brd);
  border-radius:10px;background:var(--gl2);
  color:var(--muted);cursor:pointer;
  font-size:.75rem;transition:.15s}
.lk-presets button:hover{color:var(--accent);
  border-color:var(--accent)}

/* Узкий экран: меню становится горизонтальным */
@media(max-width:760px){
  .shell{flex-direction:column}
  .tabs{width:100%;flex-direction:row;
    flex-wrap:wrap;position:static}
  .tab-btn{width:auto;flex:1 1 auto;
    text-align:center}
  /* В колонке flex:1 не растягивает по ширине — задаём явно,
     иначе карточка занимала лишь часть экрана. */
  .card{width:100%;padding:1rem}
}</style></head><body>
<h1>&#9881;&#65039;
  Генератор конфигураций</h1>
<div id="update-bar"></div>
<div id="pin-bar"></div>
{% with msgs = get_flashed_messages(
  with_categories=true) %}
{% if msgs %}{% for cat, msg in msgs %}
<div class="msg {{ 'msg-ok'
  if cat=='ok' else 'msg-err' }}">
  {{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<div class="shell">
<div class="tabs">
  <button id="btn-ss" class="tab-btn
    {% if active=='ss' %}active{% endif %}"
    onclick="go('ss')">Shadowsocks</button>
  <button id="btn-tr" class="tab-btn
    {% if active=='tr' %}active{% endif %}"
    onclick="go('tr')">Trojan</button>
  <button id="btn-vl" class="tab-btn
    {% if active=='vl' %}active{% endif %}"
    onclick="go('vl')">VLESS</button>
  <button id="btn-to" class="tab-btn
    {% if active=='to' %}active{% endif %}"
    onclick="go('to')">Tor</button>
  <button id="btn-hy" class="tab-btn
    {% if active=='hy' %}active{% endif %}"
    onclick="go('hy')">Hysteria</button>
  <button id="btn-bt" class="tab-btn
    {% if active=='bt' %}active{% endif %}"
    onclick="go('bt')">&#129302; Бот</button>
  <button id="btn-lk" class="tab-btn
    {% if active=='lk' %}active{% endif %}"
    onclick="go('lk')">&#128269; Поиск</button>
</div>
<div class="card">
  {% for tid, tname, fkey in [
    ('ss','Shadowsocks','shadowsocks'),
    ('tr','Trojan','trojan'),
    ('vl','VLESS','vless'),
    ('to','Tor','tor'),
    ('hy','Hysteria','hysteria')] %}
  <div id="tab-{{ tid }}"
    class="tab-content
    {% if active==tid %}active{% endif %}">
    <form method="post"
      action="{{ url_for('toggle_service',
        tab=tid) }}"
      id="tgl-{{ tid }}">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <input type="hidden" name="enabled"
        value="{{ '0' if svc_enabled[tid]
          else '1' }}">
      <div class="svc-row">
        <span class="svc-name
          {{ 'on' if svc_enabled[tid]
            else 'off' }}">
          {{ '\u25cf' }} {{ tname }}:
          {{ 'включён' if svc_enabled[tid]
            else 'отключён' }}</span>
        <label class="switch">
          <input type="checkbox"
            {% if svc_enabled[tid] %}checked{% endif %}
            onchange="document.getElementById(
              'tgl-{{ tid }}').submit()">
          <span class="slider"></span>
        </label>
      </div>
    </form>
    {% if tid == 'to' %}
    <form method="post"
      action="{{ url_for('key_to') }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <div style="font-size:.88rem;
        color:var(--accent);
        font-weight:600;
        margin-bottom:.4rem">
        &#128274; obfs4</div>
      <label>Мосты (по одному)</label>
      <textarea name="obfs4_bridges"
        class="key-area"
        placeholder="obfs4 ..."></textarea>
      <div style="font-size:.88rem;
        color:var(--accent);
        font-weight:600;
        margin:.6rem 0 .4rem">
        &#127760; Webtunnel</div>
      <label>Мосты (по одному)</label>
      <textarea name="webtunnel_bridges"
        class="key-area"
        placeholder="webtunnel ..."></textarea>
      <button type="submit"
        class="btn btn-key">
        <span class="spinner-ring"></span>
        <span class="btn-label">
          &#128273; Применить</span>
      </button>
    </form>
    {% else %}
    <form method="post"
      action="{{ url_for('key_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label>Ключ {{ tname }}</label>
      <input type="text" name="key"
        placeholder="Ключ {{ tname }}">
      <p class="hint">
        Формат {{ tname }}</p>
      <button type="submit"
        class="btn btn-key">
        <span class="spinner-ring"></span>
        <span class="btn-label">
          &#128273; Применить ключ</span>
      </button>
    </form>
    <div class="divider">
      <span>&#128196;
        или JSON-конфиг</span></div>
    <form method="post"
      action="{{ url_for('config_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label>config.json</label>
      <textarea name="config_data"
        class="key-area"
        placeholder='{"outbounds":[...]}'
        style="min-height:120px"></textarea>
      <p class="hint">
        Содержимое config.json.
        Inbound заменяется.</p>
      <button type="submit"
        class="btn btn-cfg">
        <span class="spinner-ring"></span>
        <span class="btn-label">
          &#128196; Применить конфиг</span>
      </button>
    </form>
    {% endif %}
    <div class="divider">
      <span>&#128195;
        {{ fkey }}.txt &mdash;
        {{ list_details[tid] }}</span>
    </div>
    <form method="post"
      action="{{ url_for('list_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label>Список
        ({{ ipsets[tid] }})</label>
      <textarea name="content"
        class="list-area"
        id="ta-{{ tid }}">{{ contents[tid] }}</textarea>
      <div class="counter"
        id="cnt-{{ tid }}"></div>
      <p class="hint">
        <code>#Секция</code>
        <code>site.com #заметка</code>
        <code>1.2.3.0/24</code></p>
      <button type="submit"
        class="btn btn-save">
        <span class="spinner-ring"></span>
        <span class="btn-label">
          &#128190; Сохранить</span>
      </button>
    </form>
  </div>
  {% endfor %}
  <div id="tab-bt" class="tab-content
    {% if active=='bt' %}active{% endif %}">
    <div class="info-box">
      &#129302; <b>Обход роутера</b><br>
      OUTPUT &rarr; xray :10810.<br>
      &#9888;&#65039; Не IP VPS!<br>
      &#128204; Совпадения ОК.</div>
    <div class="divider">
      <span>&#128195; bot.txt &mdash;
        {{ list_details.bt }}</span></div>
    <form method="post"
      action="{{ url_for('list_bt') }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label>Список
        ({{ ipsets.bt }})</label>
      <textarea name="content"
        class="list-area"
        id="ta-bt">{{ contents.bt }}</textarea>
      <div class="counter"
        id="cnt-bt"></div>
      <p class="hint">
        <code>api.telegram.org</code></p>
      <button type="submit"
        class="btn btn-save">
        <span class="spinner-ring"></span>
        <span class="btn-label">
          &#128190; Сохранить</span>
      </button>
    </form>
  </div>
  <div id="tab-lk" class="tab-content
    {% if active=='lk' %}active{% endif %}">
    <div class="info-box">
      &#128269; <b>Поиск IP и CIDR</b><br>
      Введите сайт, IP, AS-номер
      или выберите сервис.</div>
    <div class="lk-presets">
      <button onclick="lkSet('telegram')">
        Telegram</button>
      <button onclick="lkSet('whatsapp')">
        WhatsApp</button>
      <button onclick="lkSet('youtube')">
        YouTube</button>
    </div>
    <div style="display:flex;gap:.5rem;
      margin-bottom:1rem">
      <input type="text" id="lk-query"
        placeholder="Сайт, IP, AS32934">
      <button class="btn btn-key"
        style="width:auto;padding:0 1.2rem"
        onclick="doLookup()">
        <span class="spinner-ring"
          id="lk-spin"></span>
        <span class="btn-label">
          &#128269;</span>
      </button>
    </div>
    <div id="lk-results"
      style="display:none">
      <div class="divider">
        <span>Результаты</span></div>
      <div id="lk-info"
        style="font-size:.8rem;
        color:var(--muted);
        margin-bottom:.5rem"></div>
      <div id="lk-status"
        style="margin-bottom:.8rem"></div>
      <textarea id="lk-output"
        class="list-area" readonly
        style="min-height:200px;
        background:var(--bg)"></textarea>
      <div style="display:flex;
        gap:.5rem;margin-top:.5rem">
        <button class="btn btn-save"
          style="flex:1"
          onclick="copyLookup(event)">
          &#128203; Копировать</button>
      </div>
      <p class="hint">
        Скопируйте и вставьте
        в список обхода нужного
        протокола.</p>
    </div>
  </div>
</div>
</div>
<div class="dns-panel">
  <button class="dns-toggle"
    onclick="toggleDns()">
    &#128268; DNS (DoT/DoH)</button>
  <div class="dns-grid" id="dns-grid">
    <div class="dns-label">Canonical DNS state</div>
    <div class="dns-state unavailable" id="dns-state">DNS_UNAVAILABLE</div>
    <div class="netfilter-status degraded" id="netfilter-state">Netfilter: NETFILTER_DEGRADED</div>
    <div class="dns-label">Canonical DNS state legend</div>
    <div class="dns-legend">
      <span class="dnssec">DNSSEC_OK</span>
      <span class="no-dnssec">DNS_OK_NO_DNSSEC</span>
      <span class="tunnel">TUNNEL_DNS</span>
      <span class="unavailable">DNS_UNAVAILABLE</span>
    </div>
    <div class="dns-label">DoT</div>
    {% for p in dns_dot_ports %}
    <div class="dns-port checking"
      id="dp-{{ p }}">{{ p }}</div>
    {% endfor %}
    <div class="dns-label">DoH</div>
    {% for p in dns_doh_ports %}
    <div class="dns-port checking"
      id="dp-{{ p }}">{{ p }}</div>
    {% endfor %}
    <div class="dns-label" id="pin-label"
      style="display:none">
      Закреплённые адреса серверов</div>
    <div class="pin-box" id="pin-box"></div>
  </div>
</div>
<div class="dns-panel">
  <button class="dns-toggle"
    onclick="toggleVer()">
    &#128230; Версии</button>
  <div class="ver-grid" id="ver-grid">
    <div class="dns-label">
      Протокол &mdash; Версия</div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-xray">xray</div>
      <button class="btn upd-btn"
        id="ub-xray"
        onclick="runUpd('xray','xray')">
        &#8681; Обновить</button>
    </div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-hysteria">hysteria</div>
      <button class="btn upd-btn"
        id="ub-hysteria"
        onclick="runUpd('hysteria','hysteria')">
        &#8681; Обновить</button>
    </div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-shadowsocks">ss</div>
      <button class="btn upd-btn"
        id="ub-shadowsocks"
        onclick="runUpd('opkg','shadowsocks')">
        &#8681; Обновить</button>
    </div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-trojan">trojan</div>
      <button class="btn upd-btn"
        id="ub-trojan"
        onclick="runUpd('opkg','trojan')">
        &#8681; Обновить</button>
    </div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-tor">tor</div>
      <button class="btn upd-btn"
        id="ub-tor"
        onclick="runUpd('opkg','tor')">
        &#8681; Обновить</button>
    </div>
    <div class="ver-item">
      <div class="dns-port checking"
        id="ver-dnsmasq">dnsmasq</div>
      <button class="btn upd-btn"
        id="ub-dnsmasq"
        onclick="runUpd('opkg','dnsmasq')">
        &#8681; Обновить</button>
    </div>
    <div class="upd-all-row" id="upd-all-row">
      <button class="btn upd-btn"
        id="ub-all"
        onclick="runUpd('all','all')">
        &#8681; Обновить всё</button>
    </div>
    <div class="upd-out" id="upd-out"></div>
  </div>
</div>
<script>
/* Файл отдаётся роутером на каждый запрос страницы, поэтому русский
   текст пишется напрямую (страница в UTF-8), а не \uXXXX-кодами:
   так короче и не тратится время на разбор escape-последовательностей.
   Повторяющиеся операции вынесены в g/each/setCell. */
function g(i){return document.getElementById(i)}
function each(a,f){for(var i=0;i<a.length;i++)f(a[i])}
/* Переключение вкладок без перезагрузки страницы: все вкладки уже
   отрисованы в DOM. Прежний вариант (location.href) заставлял роутер
   на каждый клик заново читать все списки обхода, считать записи и
   формировать 30 КБ HTML. Теперь запрос к роутеру не уходит вовсе,
   а адрес правится через history — ссылка остаётся рабочей. */
function go(id){
  var i,el,tabs=document.querySelectorAll('.tab-content'),
  btns=document.querySelectorAll('.tab-btn');
  for(i=0;i<tabs.length;i++)
    tabs[i].classList.remove('active');
  for(i=0;i<btns.length;i++)
    btns[i].classList.remove('active');
  el=g('tab-'+id);
  if(!el){location.href='/?tab='+id;return}
  el.classList.add('active');
  el=g('btn-'+id);
  if(el)el.classList.add('active');
  if(window.history&&history.replaceState)
    history.replaceState(null,'','/?tab='+id);
  window.scrollTo(0,0)}
function jget(u,cb){fetch(u).then(function(r){
  return r.json()}).then(cb).catch(function(){})}
/* Экранирование перед вставкой в innerHTML: значения приходят из
   /api/lookup и содержат пользовательский ввод (домен из поля поиска).
   Без этого строка вида "<img src=x onerror=...>.com" выполнялась
   как HTML — подтверждённый XSS. */
function esc(v){
  return String(v==null?'':v)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;')}
function setCell(el,cls,txt){
  if(!el)return;el.className='dns-port '+cls;
  el.textContent=txt}

each(['ss','tr','vl','to','hy','bt'],function(id){
  var ta=g('ta-'+id),cnt=g('cnt-'+id);
  if(!ta||!cnt)return;
  function u(){cnt.textContent='Стр: '+
    ta.value.split('\n').length}
  ta.addEventListener('input',u);u()});

function btnLock(f){
  var b=f.querySelector('.btn');
  if(!b||b.classList.contains('loading'))
    return false;
  b.classList.add('loading');
  b.disabled=true;return true}

var _poll=null,_ld=0;
function pollUpdate(){
  jget('/api/update-status',function(d){
    var bar=g('update-bar'),
    now=Math.floor(Date.now()/1000);
    function stop(){if(_poll){
      clearInterval(_poll);_poll=null}}
    if(d.status==='running'){
      var e=now-(d.ts||now);if(e<0)e=0;
      bar.className='running';
      bar.textContent='\u23F3 Обновление… '+e+'с';
      bar.style.display='block';
      if(!_poll)_poll=setInterval(pollUpdate,2000);
    }else if(d.status==='done'){
      if(d.ts>_ld){_ld=d.ts;
        bar.className='done';
        bar.textContent='\u2705 Готово';
        bar.style.display='block';
        setTimeout(function(){
          bar.style.display='none'},8000)}
      stop();
    }else if(d.status==='error'&&d.ts&&
        (now-d.ts)<120){
      bar.className='error';
      bar.textContent='\u274C '+(d.message||'');
      bar.style.display='block';stop();
    }else{stop()}})}
pollUpdate();

/* Доступность серверов обхода: плашка показывается, пока проблема не
   устранена. Проверка выполняется в unblock_dnsmasq.sh по событиям
   (загрузка, WAN, изменение конфигурации или tunnel), панель лишь
   отображает её результат. */
function pollPin(){
  jget('/api/pin-status',function(d){
    var b=g('pin-bar');
    if(!b||!d)return;
    if(d.kind==='warn'&&d.message){
      b.className='warn';
      b.textContent=d.message;
    }else if(d.kind==='ok'&&d.message){
      b.className='ok';
      b.textContent=d.message;
      setTimeout(function(){
        b.className='';b.style.display='none'},15000);
    }else{
      b.className='';b.style.display='none';
    }
  })}
pollPin();
setInterval(pollPin,60000);

var DNS_PORTS={{ dns_ports|tojson }};
var _dO=false;
function toggleDns(){
  var el=g('dns-grid');_dO=!_dO;
  el.className=_dO?'dns-grid open':'dns-grid';
  if(_dO)fetchDns()}
function dnsStateClass(state){
  return state==='DNSSEC_OK'?'dnssec':
    (state==='DNS_OK_NO_DNSSEC'?'no-dnssec':
    (state==='TUNNEL_DNS'?'tunnel':'unavailable'))}
function setDnsState(id,state){
  var el=g(id);if(!el)return;
  el.className='dns-state '+dnsStateClass(state);
  el.textContent=state;
}
function setNetfilterState(state){
  var el=g('netfilter-state');if(!el)return;
  el.className='netfilter-status '+
    (state==='NETFILTER_OK'?'ok':'degraded');
  el.textContent='Netfilter: '+state;
}
function fetchDns(){
  setDnsState('dns-state','DNS_UNAVAILABLE');
  setNetfilterState('NETFILTER_DEGRADED');
  each(DNS_PORTS,function(p){
    setCell(g('dp-'+p),'checking',p+'…')});
  jget('/api/dns-status',function(d){
    var dnsState=d.dns_state||'DNS_UNAVAILABLE';
    setDnsState('dns-state',dnsState);
    setNetfilterState(d.netfilter_state||'NETFILTER_DEGRADED');
    each(['dot','doh'],function(t){
      if(!d[t])return;
      each(Object.keys(d[t]),function(p){
        var info=d[t][p],
            ok=typeof info==='boolean'?info:!!info.ok,
            state=typeof info==='object'?(info.state||''):'',
            cls=!ok?'unavailable':dnsStateClass(dnsState),
            label=!ok?' \u2717 DNS':
              (dnsState==='DNSSEC_OK'?' \u2713 DNSSEC':
              (dnsState==='DNS_OK_NO_DNSSEC'?' \u2248 DNS':
              (dnsState==='TUNNEL_DNS'?' \u2197 TUNNEL DNS':' \u2717 DNS')));
        setCell(g('dp-'+p),cls,p+label);
        if(g('dp-'+p)&&typeof info==='object')
          g('dp-'+p).title=state+'; '+
            (info.detail||'')})});
    /* Пин показывается, только если адрес сервера задан доменом:
       при заданном IP закреплять нечего и блок остаётся скрытым. */
    var pb=g('pin-box'),pl=g('pin-label'),
        pin=d.pinned||[];
    if(pb&&pl){
      if(pin.length){
        var t='';
        each(pin,function(x){
          t+=esc(x.host)+' \u2192 '+esc(x.ip)+'\n'});
        pb.textContent=t.replace(/\n$/,'');
        pb.className='pin-box on';
        pl.style.display='';
      }else{
        pb.className='pin-box';
        pl.style.display='none';
      }}})}

var VER_NAMES=['xray','hysteria','shadowsocks',
  'trojan','tor','dnsmasq'];
var _vO=false;
/* ── Обновление протоколов ───────────────────────────────────────
   Скрипт работает минутами, поэтому запрос лишь стартует его,
   а прогресс подтягивается опросом /api/proto-update-status. */
var _updTimer=null;
/* Показ/скрытие кнопки обновления конкретного протокола. */
function updBtnShow(name,on){
  var b=g('ub-'+name);
  if(b)b.className='btn upd-btn'+(on?' on':'')}
/* Блокировка всех кнопок на время работы обновления. */
function updBtns(off){
  each(VER_NAMES.concat(['all']),
    function(a){var b=g('ub-'+a);
      if(b)b.disabled=off})}
function updShow(txt){
  var o=g('upd-out');if(!o)return;
  o.className='upd-out on';
  /* Вывод скрипта попадает в DOM — экранируем. */
  o.textContent=txt}
function updPoll(){
  fetch('/api/proto-update-status',
    {credentials:'same-origin'})
  .then(function(r){return r.json()})
  .then(function(d){
    var log=d.log||'';
    var head=d.status==='running'
      ? 'Выполняется…'
      : (d.status==='done'
         ? 'Готово' : 'Ошибка: '+(d.message||''));
    updShow(head+(log?'\n\n'+log:''));
    if(d.status==='running')return;
    clearInterval(_updTimer);_updTimer=null;
    updBtns(false);
    /* Версии могли измениться — перечитываем. */
    fetchVer()})
  .catch(function(){})}
function runUpd(action,label){
  if(_updTimer)return;
  if(!confirm('Запустить обновление: '
    +(label||action)
    +'?\nСервисы будут перезапущены.'))return;
  updBtns(true);
  updShow('Запуск…');
  var b=new FormData();
  b.append('action',action);
  b.append('csrf_token',
    document.querySelector(
      'input[name=csrf_token]').value);
  fetch('/update/run',
    {method:'POST',body:b,
     credentials:'same-origin'})
  .then(function(r){return r.json()
    .then(function(j){return {ok:r.ok,j:j}})})
  .then(function(res){
    if(!res.ok||!res.j.ok){
      updShow('Ошибка: '
        +(res.j.error||'неизвестная'));
      updBtns(false);return}
    _updTimer=setInterval(updPoll,2000);
    updPoll()})
  .catch(function(e){
    updShow('Ошибка сети: '+e);
    updBtns(false)})}
function toggleVer(){
  var el=g('ver-grid');_vO=!_vO;
  el.className=_vO?'ver-grid open':'ver-grid';
  if(_vO)fetchVer()}
function fetchVer(){
  each(VER_NAMES,function(n){
    setCell(g('ver-'+n),'checking',n+'…')});
  jget('/api/protocol-versions',function(d){
    if(!d.versions)return;
    var u={},src={},gh=d.github_only||{},any=false;
    if(d.updates)each(d.updates,function(x){
      u[x.name]=x.available;src[x.name]=x.source});
    each(Object.keys(d.versions),function(n){
      /* github_only — справочная версия для протоколов, которые
         обновляются только через opkg. Заполняется, лишь если на
         GitHub появилась сборка под архитектуру роутера. */
      var v=d.versions[n],nv=u[n],
      /* Источник показывается рядом с версией: пользователь видит,
         откуда придёт обновление — с GitHub или из репозитория
         Entware. Для xray и hysteria выбирается более свежая. */
      s=src[n]?' ('+src[n]+')':'';
      if(nv){
        setCell(g('ver-'+n),'fail',n+': '+v+' \u2192 '+nv+s);
        /* Кнопка появляется только у того протокола, для которого
           обновление действительно найдено. */
        updBtnShow(n,true);any=true;
      }else if(gh[n]&&gh[n]!==v){
        /* Обновление доступно на GitHub, но ставится только из opkg. */
        setCell(g('ver-'+n),'ok',
          n+': '+v+' (GitHub: '+gh[n]+')');
        updBtnShow(n,false);
      }else{
        setCell(g('ver-'+n),'ok',n+': '+v);
        updBtnShow(n,false);
      }});
    /* «Обновить всё» имеет смысл лишь когда есть что обновлять. */
    var ar=g('upd-all-row');
    if(ar)ar.className=any?'upd-all-row on':'upd-all-row'})}

function lkSet(v){g('lk-query').value=v;doLookup()}
function doLookup(){
  var q=g('lk-query').value.trim();
  if(!q)return;
  var sp=g('lk-spin');
  sp.style.display='inline-block';
  var fd=new FormData();fd.append('query',q);
  fetch('/api/lookup',{method:'POST',body:fd})
  .then(function(r){return r.json()})
  .then(function(d){
    sp.style.display='none';
    g('lk-results').style.display='block';
    var dn=d.domains||[],ips=d.ips||[],
    cid=d.cidrs||[],inl=d.in_lists||{},
    miss=d.missing||[],fnd=d.found||[],
    cov=d.covered||{};
    g('lk-info').textContent='Сайты: '+dn.length+
      ' | IP: '+ips.length+
      ' | CIDR: '+cid.length;
    var h='<div style="font-size:.8rem">';
    if(fnd.length){
      h+='<div style="color:var(--green);'+
        'margin-bottom:.3rem">\u2705 В списках: '+
        fnd.length+'</div>';
      each(Object.keys(inl),function(k){
        h+='<span style="color:var(--green);'+
          'font-size:.72rem">  '+esc(k)+'.txt: '+
          esc(inl[k].join(', '))+'</span><br>'});
      var ck=Object.keys(cov);
      if(ck.length){
        h+='<div style="color:var(--accent);'+
          'font-size:.72rem;margin-top:.2rem">'+
          '\u2139\uFE0F Покрыты:</div>';
        each(ck,function(k){
          h+='<span style="color:var(--accent);'+
            'font-size:.72rem">  '+esc(k)+' \u2192 '+
            esc(cov[k])+'</span><br>'})}}
    if(miss.length)
      h+='<div style="color:var(--orange);'+
        'margin-top:.3rem">\u26A0\uFE0F Нет в '+
        'списках: '+miss.length+'</div>';
    if(!fnd.length&&!miss.length)
      h+='<span style="color:var(--muted)">'+
        'Нет данных</span>';
    g('lk-status').innerHTML=h+'</div>';
    function sortItems(a){
      var ok=[],no=[];
      each(a,function(v){
        (miss.indexOf(v)>=0?no:ok).push(v)});
      return ok.concat(no)}
    function mark(v){
      if(cov[v])return v+' #\u2705 '+cov[v];
      return v+(miss.indexOf(v)>=0?
        ' #\u26A0\uFE0F':' #\u2705')}
    var lines=[];
    function push(arr,title){
      if(!arr.length)return;
      if(lines.length)lines.push('');
      lines.push('#'+title);
      each(arr,function(v){lines.push(mark(v))})}
    var d1=sortItems(dn);
    if(d1.length){lines.push('#'+q);
      each(d1,function(v){lines.push(mark(v))})}
    push(sortItems(ips),q+' IP');
    push(sortItems(cid),q+' CIDR');
    g('lk-output').value=lines.join('\n');
  }).catch(function(e){
    sp.style.display='none';
    alert('\u274C '+e)})}

function copyLookup(ev){
  var ta=g('lk-output');
  ta.select();
  ta.setSelectionRange(0,ta.value.length);
  try{
    document.execCommand('copy');
    var b=(ev||window.event).target,
    old=b.textContent;
    b.textContent='\u2705 Скопировано';
    setTimeout(function(){
      b.textContent=old},2000)
  }catch(e){}}

g('lk-query').addEventListener('keypress',
  function(e){if(e.key==='Enter')doLookup()});
</script></body></html>'''


def _render(active='ss'):
    contents, lc = {}, {}
    ld, ipsets = {}, {}
    km = {
        'ss': 'shadowsocks',
        'tr': 'trojan',
        'vl': 'vless',
        'to': 'tor',
        'hy': 'hysteria'}
    for k in ('ss', 'tr', 'vl',
              'to', 'hy'):
        fk = km[k]
        t = read_file_text(
            BYPASS_FILES[fk])
        contents[k] = t
        d, ip, cidr = _count_entries(t)
        lc[k] = d + ip + cidr
        ld[k] = _format_details(
            d, ip, cidr)
        ipsets[k] = BYPASS_IPSETS[fk]
    bt = read_file_text(BOT_BYPASS_FILE)
    contents['bt'] = bt
    d, ip, cidr = _count_entries(bt)
    lc['bt'] = d + ip + cidr
    ld['bt'] = _format_details(
        d, ip, cidr)
    ipsets['bt'] = BYPASS_IPSETS['bot']
    return render_template_string(
        PAGE_TEMPLATE,
        active=active,
        contents=contents,
        list_counts=lc,
        list_details=ld,
        ipsets=ipsets,
        dns_dot_ports=DNS_PORTS_DOT,
        dns_doh_ports=DNS_PORTS_DOH,
        dns_ports=DNS_PORTS_DOT + DNS_PORTS_DOH,
        svc_enabled=get_services_enabled(),
        csrf_token=generate_csrf())


def _read_proto_update():
    """Статус фонового обновления протоколов."""
    try:
        with open(PROTO_UPD_STATUS, 'r') as f:
            d = json.load(f)
    except Exception:
        return {'status': 'idle', 'ts': 0,
                'message': '', 'log': ''}
    # Процесс мог быть убит, не успев записать финальный статус.
    if d.get('status') == 'running':
        age = time.time() - d.get('ts', 0)
        if age > PROTO_UPD_TIMEOUT and not _lock_is_live(PROTO_LAUNCH_LOCK):
            d['status'] = 'error'
            d['message'] = 'Таймаут'
    d['log'] = _tail_file(PROTO_UPD_LOG)
    return d


def _tail_file(path, limit=4000):
    try:
        with open(path, 'r') as f:
            return f.read()[-limit:]
    except Exception:
        return ''


def start_proto_update(action):
    """Запускает update_protocols.sh в фоне.

    Скрипт работает минутами, поэтому HTTP-запрос его не ждёт:
    панель опрашивает /api/proto-update-status.
    """
    if action not in ('xray', 'hysteria', 'github',
                      'opkg', 'all'):
        raise ValueError('action')

    st = _read_proto_update()
    if st.get('status') == 'running':
        age = int(time.time()
                  - st.get('ts', 0))
        if age < PROTO_UPD_TIMEOUT and _lock_is_live(PROTO_LAUNCH_LOCK):
            raise RuntimeError(
                f'Обновление уже идёт ({age}с)')
        # Status can be left at running if the worker was killed. A dead
        # owner is recoverable; the atomic lock is the source of truth.

    sc = config.paths.get(
        'update_protocols',
        '/opt/bin/update_protocols.sh')
    if not os.path.exists(sc):
        raise FileNotFoundError(sc)
    if not _acquire_launcher_lock(PROTO_LAUNCH_LOCK):
        raise RuntimeError('Обновление уже запускается')

    try:
        with open(PROTO_UPD_STATUS, 'w') as f:
            json.dump({
                'status': 'running',
                'ts': int(time.time()),
                'action': action,
                'message': 'Запуск...'}, f)
    except Exception:
        pass

    # Обёртка пишет финальный статус по коду возврата скрипта,
    # а не по наличию значков в выводе.
    lines = [
        '#!/bin/sh',
        'SC=' + shlex.quote(sc),
        'ACT=' + shlex.quote(action),
        'LOG=' + shlex.quote(PROTO_UPD_LOG),
        'ST=' + shlex.quote(PROTO_UPD_STATUS),
        'LAUNCH_LOCK=' + shlex.quote(PROTO_LAUNCH_LOCK),
        "trap 'rm -rf \"$LAUNCH_LOCK\" 2>/dev/null || true' EXIT INT TERM HUP",
        'printf \'%s\\n\' "$$" > "$LAUNCH_LOCK/pid"',
        'awk \'{print $22}\' "/proc/$$/stat" 2>/dev/null > "$LAUNCH_LOCK/start" || true',
        ': > "$LOG"',
        '"$SC" "$ACT" >> "$LOG" 2>&1',
        'RC=$?',
        'TS=$(date +%s)',
        'if [ "$RC" -eq 0 ]; then',
        '    S=done; M="Готово"',
        'else',
        '    S=error; M="Код возврата $RC"',
        'fi',
        'TMP="$ST.tmp"',
        'printf \'{"status":"%s","ts":%s,'
        '"action":"%s","message":"%s"}\\n\' '
        '"$S" "$TS" "$ACT" "$M" > "$TMP"',
        'mv -f "$TMP" "$ST"',
        'exit "$RC"',
    ]
    with open(PROTO_UPD_WRAPPER, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    os.chmod(PROTO_UPD_WRAPPER, 0o755)

    try:
        subprocess.Popen(
            ['/bin/sh', PROTO_UPD_WRAPPER],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except Exception:
        _release_launcher_lock(PROTO_LAUNCH_LOCK)
        raise


@app.route('/api/proto-update-status')
def api_proto_update_status():
    return jsonify(_read_proto_update())


@app.route('/update/run', methods=['POST'])
def route_update_run():
    # Изменяющее состояние действие: CSRF обязателен, доступ уже
    # ограничен LAN и Basic-авторизацией.
    _check_csrf()
    action = (request.form.get('action')
              or '').strip()
    try:
        start_proto_update(action)
    except ValueError:
        return jsonify({
            'ok': False,
            'error': 'Неизвестное действие'}), 400
    except FileNotFoundError:
        return jsonify({
            'ok': False,
            'error': 'Скрипт обновления не найден'}), 500
    except RuntimeError as e:
        return jsonify({
            'ok': False, 'error': str(e)}), 409
    except Exception as e:
        logging.error('proto update: %s', e)
        return jsonify({
            'ok': False,
            'error': 'Не удалось запустить'}), 500
    return jsonify({'ok': True})


@app.route('/api/update-status')
def api_update_status():
    return jsonify(_read_update_status())


@app.route('/api/dns-status')
def api_dns_status():
    return jsonify(check_dns_ports())


# Состояние доступности серверов обхода. Пишется unblock_dnsmasq.sh при
# проверке закреплённых адресов. Telegram с роутера часто заблокирован,
# поэтому панель — основной канал уведомления.
PIN_STATUS_FILE = _GS.get(
    'pin_status_file', '/tmp/keenzoo_pin_status.json')


@app.route('/api/pin-status')
def api_pin_status():
    try:
        if not os.path.exists(PIN_STATUS_FILE):
            return jsonify({'kind': 'none', 'ts': 0, 'message': ''})
        with open(PIN_STATUS_FILE, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return jsonify({'kind': 'none', 'ts': 0, 'message': ''})
        return jsonify(data)
    except (json.JSONDecodeError, IOError, ValueError):
        return jsonify({'kind': 'none', 'ts': 0, 'message': ''})


def _start_updates_check_async(script):
    if not _acquire_launcher_lock(UPDATES_CHECK_LOCK):
        return False
    cmd = (
        shlex.quote(script)
        + ' >/dev/null 2>&1; rc=$?; rm -rf '
        + shlex.quote(UPDATES_CHECK_LOCK)
        + '; exit "$rc"')
    cmd = (
        "printf '%s\\n' \"$$\" > "
        + shlex.quote(UPDATES_CHECK_LOCK + '/pid')
        + "; awk '{print $22}' \"/proc/$$/stat\" > "
        + shlex.quote(UPDATES_CHECK_LOCK + '/start')
        + ' 2>/dev/null || true; '
        + cmd)
    try:
        subprocess.Popen(
            ['/bin/sh', '-c', cmd],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        return True
    except Exception:
        _release_launcher_lock(UPDATES_CHECK_LOCK)
        return False


@app.route('/api/protocol-versions')
def api_protocol_versions():
    sf = config.paths.get(
        'updates_status',
        '/tmp/updates_status.json')
    if not os.path.exists(sf):
        cs = config.paths.get(
            'check_updates',
            '/opt/bin/check_updates.sh')
        if os.path.exists(cs):
            _start_updates_check_async(cs)
    if os.path.exists(sf):
        try:
            with open(sf, 'r') as f:
                return jsonify(
                    json.load(f))
        except Exception:
            pass
    return jsonify({
        'ts': 0, 'has_updates': False,
        'versions': {}, 'updates': []})


@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    query = (request.form.get('query')
             or '').strip()
    if not query:
        return jsonify({
            'error': 'Пустой запрос'})
    return jsonify(
        _lookup_resource(query))


@app.route('/')
def index():
    active = request.args.get(
        'tab', 'ss')
    if active not in (
            'ss', 'tr', 'vl',
            'to', 'hy', 'bt', 'lk'):
        active = 'ss'
    return _render(active)


@app.route('/key/ss', methods=['POST'])
def key_ss():
    _check_csrf()
    key = (request.form.get('key')
           or '').strip()
    if not key:
        flash('\u274c Ключ SS', 'err')
        return redirect(
            url_for('index') + '?tab=ss')
    try:
        shadowsocks_config(key)
        restart_service('shadowsocks')
        flash('\u2705 SS: ключ', 'ok')
    except Exception as e:
        log_error(f'[w]ss: {e}')
        flash(f'\u274c SS — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=ss')


@app.route('/key/tr', methods=['POST'])
def key_tr():
    _check_csrf()
    key = (request.form.get('key')
           or '').strip()
    if not key:
        flash('\u274c Ключ TR', 'err')
        return redirect(
            url_for('index') + '?tab=tr')
    try:
        trojan_config(key)
        restart_service('trojan')
        flash('\u2705 Trojan: ключ', 'ok')
    except Exception as e:
        log_error(f'[w]tr: {e}')
        flash(f'\u274c TR — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=tr')


@app.route('/key/vl', methods=['POST'])
def key_vl():
    _check_csrf()
    key = (request.form.get('key')
           or '').strip()
    if not key:
        flash('\u274c Ключ VL', 'err')
        return redirect(
            url_for('index') + '?tab=vl')
    try:
        vless_config(key)
        restart_service('vless')
        flash('\u2705 VLESS: ключ', 'ok')
    except Exception as e:
        log_error(f'[w]vl: {e}')
        flash(f'\u274c VL — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=vl')


@app.route('/key/to', methods=['POST'])
def key_to():
    _check_csrf()
    o = (request.form.get(
        'obfs4_bridges') or '').strip()
    w = (request.form.get(
        'webtunnel_bridges') or '').strip()
    if not o and not w:
        flash('\u274c Мост', 'err')
        return redirect(
            url_for('index') + '?tab=to')
    parts = [p for p in [o, w] if p]
    try:
        tor_config('\n'.join(parts))
        restart_service('tor')
        flash('\u2705 Tor: мосты', 'ok')
    except Exception as e:
        log_error(f'[w]to: {e}')
        flash(f'\u274c Tor — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=to')


@app.route('/key/hy', methods=['POST'])
def key_hy():
    _check_csrf()
    key = (request.form.get('key')
           or '').strip()
    if not key:
        flash('\u274c Ключ HY', 'err')
        return redirect(
            url_for('index') + '?tab=hy')
    try:
        hysteria_config(key)
        restart_service('hysteria')
        flash('\u2705 Hysteria: ключ',
              'ok')
    except Exception as e:
        log_error(f'[w]hy: {e}')
        flash(f'\u274c HY — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=hy')


@app.route('/config/ss', methods=['POST'])
def config_ss():
    _check_csrf()
    data = (request.form.get(
        'config_data') or '').strip()
    if not data:
        flash('\u274c Конфиг', 'err')
        return redirect(
            url_for('index') + '?tab=ss')
    try:
        apply_direct_config(
            'shadowsocks', data)
        restart_service('shadowsocks')
        flash('\u2705 SS: конфиг', 'ok')
    except Exception as e:
        log_error(f'[w]ss cfg: {e}')
        flash(f'\u274c SS — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=ss')


@app.route('/config/tr', methods=['POST'])
def config_tr():
    _check_csrf()
    data = (request.form.get(
        'config_data') or '').strip()
    if not data:
        flash('\u274c Конфиг', 'err')
        return redirect(
            url_for('index') + '?tab=tr')
    try:
        apply_direct_config(
            'trojan', data)
        restart_service('trojan')
        flash('\u2705 Trojan: конфиг',
              'ok')
    except Exception as e:
        log_error(f'[w]tr cfg: {e}')
        flash(f'\u274c TR — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=tr')


@app.route('/config/vl', methods=['POST'])
def config_vl():
    _check_csrf()
    data = (request.form.get(
        'config_data') or '').strip()
    if not data:
        flash('\u274c Конфиг', 'err')
        return redirect(
            url_for('index') + '?tab=vl')
    try:
        apply_direct_config(
            'vless', data)
        restart_service('vless')
        flash('\u2705 VLESS: конфиг',
              'ok')
    except Exception as e:
        log_error(f'[w]vl cfg: {e}')
        flash(f'\u274c VL — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=vl')


@app.route('/config/hy', methods=['POST'])
def config_hy():
    _check_csrf()
    data = (request.form.get(
        'config_data') or '').strip()
    if not data:
        flash('\u274c Конфиг', 'err')
        return redirect(
            url_for('index') + '?tab=hy')
    try:
        apply_direct_config(
            'hysteria', data)
        restart_service('hysteria')
        flash('\u2705 Hysteria: конфиг',
              'ok')
    except Exception as e:
        log_error(f'[w]hy cfg: {e}')
        flash(f'\u274c HY — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + '?tab=hy')


def _save_list_route(
        lk, tab, filepath=None,
        skip_global_dedup=False):
    _check_csrf()
    content = (request.form.get(
        'content') or '').strip()
    if filepath is None:
        filepath = BYPASS_FILES[lk]
    try:
        result = parse_and_save(
            filepath, content,
            skip_global_dedup=(
                skip_global_dedup))
        # Обновляем ТОЛЬКО затронутый набор: полный цикл резолвит
        # сотни доменов всех протоколов и занимает десятки секунд,
        # хотя изменился один список.
        apply_unblock_async(
            config.ipset_names.get(lk, ''))
        s = _format_details(
            result['domains'],
            result['ips'],
            result['cidr'])
        msg = f'\u2705 {lk}.txt: {s}'
        if result.get('cidr_report'):
            msg += '\n' + '\n'.join(
                result['cidr_report'])
        if result['duplicates']:
            msg += '\n' + '\n'.join(
                result['duplicates'])
        if result['errors']:
            msg += '\n' + '\n'.join(
                result['errors'])
        flash(msg, 'ok')
    except Exception as e:
        log_error(f'[w]{lk}: {e}')
        flash(f'\u274c {lk} — '
              f'{html.escape(str(e))}',
              'err')
    return redirect(
        url_for('index') + f'?tab={tab}')


@app.route('/toggle/<tab>', methods=['POST'])
def toggle_service(tab):
    _check_csrf()
    sn = TAB_TO_SERVICE.get(tab)
    if not sn:
        flash('\u274c Неизвестный протокол', 'err')
        return redirect(url_for('index'))

    want = request.form.get('enabled') == '1'
    try:
        set_service_enabled(sn, want)
        flash(
            ('\u2705 ' + sn + ' включён'
             if want else
             '\u26a0\ufe0f ' + sn + ' отключён'),
            'ok')
    except Exception as e:
        log_error(f'[w]toggle {sn}: {e}')
        flash(f'\u274c {sn} — {html.escape(str(e))}', 'err')
    return redirect(
        url_for('index') + '?tab=' + tab)


@app.route('/list/ss', methods=['POST'])
def list_ss():
    return _save_list_route(
        'shadowsocks', 'ss')


@app.route('/list/tr', methods=['POST'])
def list_tr():
    return _save_list_route(
        'trojan', 'tr')


@app.route('/list/vl', methods=['POST'])
def list_vl():
    return _save_list_route(
        'vless', 'vl')


@app.route('/list/to', methods=['POST'])
def list_to():
    return _save_list_route(
        'tor', 'to')


@app.route('/list/hy', methods=['POST'])
def list_hy():
    return _save_list_route(
        'hysteria', 'hy')


@app.route('/list/bt', methods=['POST'])
def list_bt():
    return _save_list_route(
        'bot', 'bt',
        filepath=BOT_BYPASS_FILE,
        skip_global_dedup=True)


if __name__ == '__main__':
    app.config['MAX_CONTENT_LENGTH'] = (
        MAX_CONTENT_LENGTH)
    rotate_log()

    # Создаём listening socket до применения INPUT-правил. На Keenetic
    # netfilter может ждать общий lock обновления списков десятки секунд;
    # прежний порядок вызывал ложный "start failed": Flask-процесс уже жил,
    # но до app.run не доходил, потому что S99generator убивал его по таймауту.
    # make_server также превращает bind-ошибку в явный traceback в
    # generator.log, вместо неоднозначного Flask banner.
    try:
        server = make_server(
            '0.0.0.0', LISTEN_PORT, app, threaded=True)
    except Exception as exc:
        sys.stderr.write(
            f"[!] generator listener {LISTEN_PORT} failed: "
            f"{type(exc).__name__}: {exc}\n")
        sys.stderr.flush()
        raise

    print(
        f"\n  http://{LAN_IP}"
        f":{LISTEN_PORT}\n"
        f"  listener: 0.0.0.0:{LISTEN_PORT}\n")

    def _apply_panel_firewall():
        try:
            setup_firewall(LISTEN_PORT)
        except Exception as exc:
            # Flask still enforces LAN + Basic auth. Keep the error visible;
            # the next netfilter hook will retry the firewall transaction.
            logging.error(
                'panel firewall apply failed: %s: %s',
                type(exc).__name__, exc)

    threading.Thread(
        target=_apply_panel_firewall,
        name='panel-firewall',
        daemon=True).start()
    server.serve_forever()

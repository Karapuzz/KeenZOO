#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/opt/etc/bot/generator.py
"""

import os
import stat
import sys
import json
import ipaddress
import logging
import shutil
import shlex
import subprocess
import signal
import time
import hashlib
import hmac
import html
import re
import glob
import threading
import tempfile
import fcntl
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from contextlib import contextmanager
from functools import wraps
from typing import Dict, Tuple
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

# Единственное определение лимита: раньше было две константы (2 МиБ при
# импорте и 1 МиБ в __main__), и фактический предел зависел от способа
# запуска. 2 МиБ достаточно для правки крупных списков текстом и всё ещё
# ограничивает разбор форм на память-ограниченном роутере.
MAX_CONTENT_LENGTH = 2 * 1024 * 1024

app = Flask(__name__)
# Bound input size before parsing forms/JSON on memory-constrained routers.
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

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
            # dns4.2.21 (A3 M6): чтение без TOCTOU — O_NOFOLLOW не идёт
            # по symlink, тип и права проверяются по fstat открытого fd,
            # а не по повторному stat пути.
            fd = os.open(SECRET_FILE, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise OSError('secret path is not a regular file')
                with os.fdopen(fd, 'r', encoding='utf-8') as secret:
                    fd = None
                    key = secret.read(4096).strip()
            finally:
                if fd is not None:
                    os.close(fd)
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


@app.after_request
def _security_headers(response):
    # dns4.2.27 (внешний аудит, G-05): защита от встраивания панели в
    # чужой фрейм (кликджекинг из LAN) и от MIME-сниффинга. Хук
    # применяется ко ВСЕМ ответам, включая отказные 403/404.
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault(
        'Content-Security-Policy', "frame-ancestors 'none'")
    return response


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
        token.encode('utf-8'), expected.encode('utf-8'))


LAN_IP = _GS.get('listen_ip', getattr(config, 'routerip', '192.168.1.1'))
LISTEN_PORT = int(_GS.get('listen_port', 8080))
UNBLOCK_TIMEOUT = int(_GS.get('unblock_timeout', 300))

# Панель обслуживает только внутренние сети. Публичные адреса и любые
# внешние подключения отклоняются до аутентификации.
# Учёт неудачных входов: {ip: (число_неудач, заблокирован_до)}.
# Хранится в памяти процесса — перезапуск панели сбрасывает счётчики,
# что приемлемо: панель доступна только из LAN.
_auth_fails: Dict[str, Tuple[int, float]] = {}
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
    config, 'dns_snapshot_max_age', 21600))  # was 90000=25h (dns4.2.21)

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
                lines = deque(f, maxlen=50)
            with open(GENERATOR_LOG, 'w',
                      encoding='utf-8') as f:
                f.writelines(lines)
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
        _auth_fails.pop(client, None)
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
        # dns4.2.23 (аудит A5 #2): прежний список содержал значение
        # заголовка «хост» из самого запроса — величину, управляемую
        # атакующим: при DNS-rebinding (evil.example -> IP роутера)
        # браузер присылает совпадающие хост и origin, и проверка
        # сравнивала атакующее значение само с собой. Теперь —
        # статический белый список имён
        # (конфигурируется в bot_config) плюс любой IP роутера из
        # внутренних подсетей (гостевой бридж, второй LAN, VPN-адрес
        # прошивки отличаются от LAN_IP). Второй эшелон (скрытый
        # CSRF-токен) остаётся на месте.
        allowed_names = {'localhost', '127.0.0.1', LAN_IP} | set(
            getattr(config, 'router_hostnames', []))

        def _port_ok(parsed):
            # Браузер не пишет порт в Origin для стандартных значений
            # (80/443), поэтому отсутствующий порт принимается наравне
            # с портом панели; иной явный порт — другой сервис.
            # dns4.2.24 (аудит A6 N1): свойство .port бросает ValueError
            # ЛЕНИВО — для мусорных значений вида ':abc', ':99999',
            # ':-1'. Обращение обязано быть под защитой: неперехваченное
            # исключение давало 500 + разрастание лога на флеш-памяти
            # роутера.
            try:
                port = parsed.port
            except ValueError:
                return False
            return port in (None, LISTEN_PORT)

        def _same_origin(value):
            if not value:
                return False
            try:
                parsed = urlparse(value)
            except Exception:
                return False
            if parsed.scheme not in ('http', 'https'):
                return False
            host = parsed.hostname or ''
            if not _port_ok(parsed):
                return False
            if host in allowed_names:
                return True
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                return False
            return any(addr in s for s in ALLOWED_SUBNETS)

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


def _run_command(args, timeout=30, env=None, check=False, label='command',
                 expected_rcs=(0,)):
    """Run a bounded command with one error/reporting policy.

    The wrapper deliberately keeps argv execution (no shell=True), truncates
    captured diagnostics for flash-backed logs, and turns timeout/OS errors
    into a normal CompletedProcess-like result unless the caller requests
    ``check``. This keeps BusyBox/Entware failures visible without allowing a
    hung child to hang the web worker forever.

    ``expected_rcs`` lists return codes that are a normal semantic answer,
    not an error (e.g. rc=1 for iptables -D/-C when a rule is absent).
    Such codes are not logged and never raise under ``check``; only codes
    OUTSIDE the list are treated as failures.
    """
    try:
        # Spool stdout/stderr rather than holding arbitrarily large command
        # output in Python RAM. Only bounded diagnostics/data are read back.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(list(args), stdout=out, stderr=err,
                                    stdin=subprocess.DEVNULL, env=env,
                                    start_new_session=True)
            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Give ash EXIT traps a chance to restore state; then ensure
                # grandchildren cannot continue modifying rules after rollback.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            size = out.tell()
            out.seek(0)
            stdout = out.read(1024 * 1024).decode('utf-8', 'replace') if size <= 1024 * 1024 else ''
            err.seek(max(0, err.tell() - 4000))
            stderr = err.read(4000).decode('utf-8', 'replace')
            rc = proc.returncode
            if timed_out:
                rc, stderr = 124, 'timeout'
            elif size > 1024 * 1024:
                rc, stderr = 125, 'command output exceeds 1 MiB'
            result = subprocess.CompletedProcess(args, rc, stdout, stderr)
    except OSError as err:
        log_error(f'[!] {label}: {err}')
        result = subprocess.CompletedProcess(
            args=args, returncode=127, stdout='', stderr=str(err))

    result.stdout = result.stdout or ''
    if len(result.stdout) > 1024 * 1024:
        result.stdout = ''
        result.stderr = 'command output exceeds 1 MiB'
        result.returncode = 125
    result.stderr = (result.stderr or '')[-4000:]
    if result.returncode not in expected_rcs:
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


def _ipt(*args, expected_rcs=(0,)):
    """Bounded iptables call using the common subprocess policy."""
    return _run_command(
        [IPTABLES, '-w'] + list(args),
        timeout=15,
        label='iptables ' + ' '.join(str(a) for a in args),
        expected_rcs=expected_rcs)


# Межпроцессный lock setup_firewall: иначе две одновременно запущенные
# панели проходят check-then-act «-C → -I» вдвоём, обе видят rc=1 и обе
# вставляют правило — до следующего старта живут дубли ACCEPT.
_FW_LOCK_PATH = '/tmp/keenzoo_panel_fw.lock'


@contextmanager
def _firewall_lock():
    fd = os.open(_FW_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


# Владелец netfilter-правил порта панели (dns4.2.20, аудит A2 п.1.3):
# правила ставит/снимает только этот хук. Константа вынесена наверх,
# чтобы тесты могли подменить её на свой стаб.
PANEL_FW_HOOK = '/opt/etc/ndm/netfilter.d/100-redirect.sh'


def setup_firewall(port):
    """
    Ограничивает доступ к порту панели на уровне netfilter ЧЕРЕЗ
    ЕДИНСТВЕННОГО ВЛАДЕЛЬЦА правил — NDM-хук
    /opt/etc/ndm/netfilter.d/100-redirect.sh (секция filter,
    type=iptable table=filter).

    dns4.2.20: прежняя реализация сама редактировала правила (ACCEPT по
    исходным подсетям без -i и снятие -i-правил хука), а хук сносил её
    -s-правила как legacy и ставил свои -i-правила — взаимная перезапись
    на каждом старте панели и каждом событии NDM, при том что у панели
    нет snapshot/rollback: transient-сбой оставлял порт без DROP из WAN.
    Теперь панель только вызывает владельца: хук идемпотентно ставит
    -i lo/-i LAN ACCEPT + DROP со снапшотом таблицы и откатом при сбое.
    Flask-проверка remote_addr по ALLOWED_SUBNETS остаётся вторым слоем
    без изменений.
    """
    hook = PANEL_FW_HOOK
    with _firewall_lock():
        if not os.access(hook, os.X_OK):
            raise FileNotFoundError(f'netfilter hook not executable: {hook}')
        result = subprocess.run(
            [hook],
            env={**os.environ, 'type': 'iptable', 'table': 'filter'},
            capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        diagnostics = (result.stderr or result.stdout or '').strip()
        raise RuntimeError(
            f'netfilter hook rc={result.returncode}: {diagnostics[-300:]}')


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
    """Читает ENABLED= из init-скрипта. Нет файла/состояния — считаем выключенным."""
    sc = SERVICE_SCRIPTS.get(sn)
    if not sc or not os.path.exists(sc):
        return False
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
    return False


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
    for table in ('nat', 'filter'):
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


_update_thread_lock = threading.RLock()
_update_depth = threading.local()


@contextmanager
def shared_update_lock():
    if not _update_thread_lock.acquire(blocking=False):
        raise RuntimeError('Изменение уже выполняется; повторите позже')
    owner = False
    try:
        depth = getattr(_update_depth, 'value', 0)
        if not depth:
            if not _acquire_launcher_lock(LOCK_DIR):
                raise RuntimeError('DNS/ipset/netfilter заняты; повторите позже')
            owner = True
        _update_depth.value = depth + 1
        try:
            yield
        finally:
            _update_depth.value = depth
    finally:
        if owner:
            _release_launcher_lock(LOCK_DIR)
        _update_thread_lock.release()


def with_update_lock(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        with shared_update_lock():
            return func(*args, **kwargs)
    return wrapped


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
        # Частичное обновление запускается только по правке списка
        # (панель/бот): набора ЗАМЕНЯЮТСЯ новым содержимым, без merge
        # со старым, чтобы удалённые записи сразу уходили из ipset.
        # Плановые крон/WAN-прогоны REPLACE_SETS не получают и
        # сохраняют merge-защиту от «плохого» резолва.
        lines.append('export REPLACE_SETS=1')
    lines += [
        'STATUS_FILE="' + UPDATE_STATUS_FILE + '"',
        'TMP_STATUS="' + UPDATE_STATUS_FILE + '.wtmp"',
        'LOG_FILE="' + UPDATE_LOG_FILE + '"',
        # Баг 7 фикс: путь подставляется через shlex.quote — как уже
        # делается для LAUNCH_LOCK/ONLY_SETS выше. Путь пока внутренняя
        # константа, но экранирование дешевле доверия к источнику.
        'SCRIPT=' + shlex.quote(sp),
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
    routes = _run_command(
        ['ip', '-4', 'route', 'show', 'table', '100'],
        timeout=5, label='TPROXY local route')
    has_route = routes.returncode == 0 and bool(re.search(
        r'(?m)^local\s+(?:default|0\.0\.0\.0/0)\s+dev\s+lo(?:\s|$)',
        routes.stdout or ''))
    required = any(
        _service_ready(name)
        for name in ('vless', 'hysteria'))
    has_tproxy = 'TPROXY' in (rules.stdout or '')
    has_policy = bool(re.search(
        r'(?m)^.*(?:priority\s+1770|1770).*lookup\s+100',
        policy.stdout or ''))
    ok = rules.returncode == 0 and policy.returncode == 0 \
        and (not required or (has_tproxy and has_policy and has_route))
    return {
        'ok': ok,
        'state': 'ready' if ok else 'degraded',
        'tproxy_required': required,
        'tproxy_rules': has_tproxy,
        'policy_rule': has_policy,
        'local_route': has_route,
        'scope': 'rule-presence; not an end-to-end packet test',
    }


def read_dns_decision():
    from utils import v4_status
    if getattr(config, 'dns_policy_version', 4) == 4:
        current = v4_status()
        mode = current.get('mode', 'DNS_UNAVAILABLE')
        state = {'LOCAL_DNSSEC': 'DNSSEC_OK', 'TUNNEL_DNS': 'TUNNEL_DNS',
                 'EMERGENCY_DNS': 'DNS_OK_NO_DNSSEC'}.get(mode, 'DNS_UNAVAILABLE')
        metrics = current.get('metrics', {})
        secure = [str(p) for p, m in metrics.items() if m.get('rtt') is not None]
        return {'state': state, 'mode': mode, 'level': state,
                'epoch': current.get('epoch', 0), 'line_present': bool(current),
                'working_ports': ['40512'] if state != 'DNS_UNAVAILABLE' else [],
                'secure_ports': secure, 'insecure_ports': [],
                'policy': current}
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
    if state == 'TUNNEL_DNS' and fields.get('required') != '1':
        state = ''
    if state == 'TUNNEL_DNS' and fields.get('verified') != '1':
        state = ''
    if state == 'TUNNEL_DNS' \
            and fields.get('tunnel') not in ('xray', 'trojan', 'hysteria'):
        state = ''
    if fields.get('client') == 'staged':
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



# Short-lived observations are deliberately separate from the canonical owner
# decision. GET never probes DNS or applies config. At most one bounded batch
# runs per panel process, with three concurrent local dig children.
_dns_probe_guard = threading.Lock()
_dns_observation = {'status': 'idle', 'checked_at': 0, 'ports': {}}


def _dns_config_stamp():
    values = []
    for path in (config.paths.get('dnsmasq_conf', '/opt/etc/dnsmasq.conf'),
                 DNS_HEALTH_LOG):
        try:
            st = os.stat(path)
            values.append((st.st_ino, st.st_size, st.st_mtime_ns))
        except OSError:
            values.append(None)
    return tuple(values)


def _dns_probe_port(port):
    started = time.monotonic()
    result = _run_command(
        ['dig', '-4', '+dnssec', '+noall', '+comments', '+answer', '+stats',
         '+time=2', '+tries=2', '-q', DNS_HEALTH_DOMAIN, '-t', 'A',
         '@127.0.0.1', '-p', str(port)], timeout=6, label='DNS observation')
    text = result.stdout or ''
    code = re.search(r'status:\s*([A-Z0-9]+)', text)
    flags = re.search(r'flags:\s*([^;]+)', text)
    rcode = code.group(1) if code else None
    bits = flags.group(1).split() if flags else []
    addresses = []
    for addr in re.findall(r'(?m)^[^;\s]\S*\s+\d+\s+IN\s+A\s+(\S+)', text):
        try:
            addresses.append(str(ipaddress.IPv4Address(addr)))
        except ValueError:
            pass
    ok = result.returncode == 0 and rcode == 'NOERROR' and bool(addresses)
    if result.returncode in (125, 126, 127):
        state = 'probe-error'
    elif result.returncode in (9, 124):
        state = 'timeout'
    elif ok:
        state = 'dnssec-ok' if 'ad' in bits else 'dns-ok-no-dnssec'
    else:
        state = 'dns-failed'
    return {'ok': ok, 'state': state, 'rcode': rcode,
            'ad': 'ad' in bits, 'addresses': addresses[:16],
            'elapsed_ms': round((time.monotonic() - started) * 1000),
            'checked_at': int(time.time()), 'command_rc': result.returncode,
            'source': 'live-query', 'transport': 'IPv4 UDP to local listener'}


def _read_dns_observation():
    with _dns_probe_guard:
        data = dict(_dns_observation)
    checked = data.get('checked_at', 0)
    age = int(time.time()) - checked if checked else None
    data['age_seconds'] = age
    data['stale'] = (age is None or age < 0 or age > 60
                     or data.get('config_stamp') != _dns_config_stamp())
    return data


def _start_dns_probe():
    global _dns_observation
    with _dns_probe_guard:
        if _dns_observation.get('status') == 'running':
            return False
        stamp = _dns_config_stamp()
        age = time.time() - _dns_observation.get('checked_at', 0)
        if (0 <= age < 15 and _dns_observation.get('status') == 'done'
                and _dns_observation.get('config_stamp') == stamp):
            return False
        _dns_observation = {'status': 'running', 'checked_at': 0, 'ports': {}}

    def worker():
        global _dns_observation
        try:
            ports = sorted({53} | {int(p) for p in DNS_PORTS_DOT + DNS_PORTS_DOH
                                   if str(p).isdigit() and 1 <= int(p) <= 65535})
            if len(ports) > 17:
                raise ValueError('too many configured DNS ports')
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix='dns-probe') as pool:
                results = dict(zip(map(str, ports), pool.map(_dns_probe_port, ports)))
            data = {'status': 'done', 'checked_at': int(time.time()),
                    'domain': DNS_HEALTH_DOMAIN, 'ports': results,
                    'config_stamp': stamp}
            if stamp != _dns_config_stamp():
                data = {'status': 'error', 'checked_at': 0, 'ports': {},
                        'message': 'Конфигурация DNS изменялась; повторите проверку'}
        except Exception:
            logging.exception('DNS observation failed')
            data = {'status': 'error', 'checked_at': 0, 'ports': {},
                    'message': 'Не удалось выполнить DNS-проверку'}
        with _dns_probe_guard:
            _dns_observation = data
    try:
        threading.Thread(target=worker, daemon=True, name='dns-observation').start()
    except Exception:
        with _dns_probe_guard:
            _dns_observation = {'status': 'error', 'checked_at': 0, 'ports': {}}
        raise
    return True


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
    epoch = decision.get('epoch', 0)
    res['snapshot'] = {
        'epoch': epoch,
        'age_seconds': int(time.time()) - epoch if epoch else None,
        'is_live_measurement': False,
    }
    for kind in ('dot', 'doh'):
        for info in res[kind].values():
            info.update(source='snapshot', checked_at=epoch)
    observation = _read_dns_observation()
    observation.pop('config_stamp', None)
    res['observation'] = observation
    res['client_plane'] = dict(observation.get('ports', {}).get('53', {
        'state': 'not-measured', 'ok': None, 'checked_at': 0}))
    res['client_plane']['stale'] = observation['stale']
    res['decision'] = decision
    res['policy_v4'] = decision.get('policy', {})
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
    try:
        ipaddress.IPv4Network(entry, strict=False)
        return '/' in entry
    except ValueError:
        return False


def _validate_ip(entry):
    try:
        ipaddress.IPv4Address(entry)
        return True
    except ValueError:
        return False


# dns4.2.23 (аудит A5 #1), dns4.2.24 (A6 N5): таблица зарезервированных
# сетей. ПРАВИТЬ СИНХРОННО с awk-реализациями is_public_ipv4/
# is_public_cidr/is_public_range в unblock_ipset.sh и unblock_dnsmasq.sh —
# shell остаётся исполнителем
# последней мили; панель отсекает те же записи заранее, чтобы сохранённый
# список совпадал с фактически применённым (раньше приватный адрес
# сохранялся, но тихо отбрасывался при наполнении ipset).
_RESERVED_NETS = (
    ('0.0.0.0', 8), ('10.0.0.0', 8), ('100.64.0.0', 10),
    ('127.0.0.0', 8), ('169.254.0.0', 16), ('172.16.0.0', 12),
    ('192.0.0.0', 24), ('192.0.2.0', 24), ('192.88.99.0', 24),
    ('192.168.0.0', 16), ('192.175.48.0', 24), ('198.18.0.0', 15),
    ('198.51.100.0', 24), ('203.0.113.0', 24),
    # 224.0.0.0/3: shell-таблицы отсекают весь хвост 224—255 (и
    # multicast, и reserved 240/4) одной записью — держим так же.
    ('224.0.0.0', 3),
)


def _is_public_v4(addr):
    """True, только если адрес/сеть пройдёт public-фильтр shell-слоя."""
    net, _, plen = addr.partition('/')
    try:
        octets = [int(x) for x in net.split('.')]
        plen = 32 if not plen else int(plen)
    except ValueError:
        return False
    if len(octets) != 4 or not 0 <= plen <= 32:
        return False
    value = ((octets[0] << 24) | (octets[1] << 16)
             | (octets[2] << 8) | octets[3])
    # dns4.2.24 (аудит A6 N2): сравнивать надо АДРЕС СЕТИ, как это
    # делает awk-слой (first = int(v/block)*block в is_public_cidr):
    # ненормализованный ввод вида 1.163.38.40/7 раньше проходил панель
    # по адресу узла, тогда как shell честно отбрасывал сеть 0.0.0.0/7.
    value &= ~((1 << (32 - plen)) - 1) & 0xFFFFFFFF
    end = value | ((1 << (32 - plen)) - 1)
    for net_ip, pref in _RESERVED_NETS:
        o = [int(x) for x in net_ip.split('.')]
        start = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3])
        last = start | ((1 << (32 - pref)) - 1)
        # Пересечение диапазонов: даже частичное попадание в
        # зарезервированную сеть отбрасывается — как в shell.
        if value <= last and start <= end:
            return False
    return True


def _validate_entry(ce):
    if '/' in ce:
        if not _validate_cidr(ce):
            return None
        return ('cidr', ce) if _is_public_v4(ce) else None
    if _validate_ip(ce):
        return ('ip', ce) if _is_public_v4(ce) else None
    if re.fullmatch(r'[0-9.]+', ce):
        return None
    host = ce[2:] if ce.startswith('*.') else ce
    if not host or len(host) > 253:
        return None
    labels = host.split('.')
    # Фактический исполнитель списка — shell-валидатор (is_domain_core в
    # unblock_ipset.sh:351, такой же в unblock_dnsmasq.sh:891): минимум
    # две метки и TLD не полностью числовой. Однословная запись (youtube)
    # или «домен» с цифровым TLD раньше молча игнорировались при резолве.
    if len(labels) < 2:
        return None
    if labels[-1].isdigit():
        return None
    if all(1 <= len(label) <= 63 and re.fullmatch(
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?', label)
           for label in labels):
        return ('domain', ce)
    return None


def _rejection_reason(ce):
    # dns4.2.24 (аудит A6 N3): панель с dns4.2.23 отклоняет приватные и
    # зарезервированные адреса ДО записи в файл (иначе счётчик «принято»
    # расходился с фактически применённым), но голое «⚠️» не объясняло
    # причину. Отличаем непубличный, но синтаксически корректный адрес
    # от синтаксической ошибки — только для текста ошибки, логика
    # отбора не меняется.
    if '/' in ce:
        if _validate_cidr(ce) and not _is_public_v4(ce):
            return 'приватная/зарезервированная сеть, в обход не попадает'
    elif _validate_ip(ce) and not _is_public_v4(ce):
        return 'приватный/зарезервированный адрес, в обход не попадает'
    return ''


def read_file_text(fp):
    if not os.path.exists(fp):
        return ''
    with open(fp, 'r',
              encoding='utf-8') as f:
        return f.read().rstrip('\n\r')


def _atomic_write_text(filepath, text):
    directory = os.path.dirname(filepath)
    os.makedirs(directory, exist_ok=True)
    mode = 0o644
    try:
        mode = os.stat(filepath).st_mode & 0o777
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(filepath) + '.',
                               suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, filepath)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
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
                # См. parse_and_save: именованная секция без записей —
                # пользовательская аннотация, а не мусор.
                if ce or cc:
                    secs.append((cc, ce))
                    cc = None
                    ce = []
                continue
            if s.startswith('#'):
                if ce or cc:
                    secs.append((cc, ce))
                    ce = []
                cc = s[1:].strip()
            else:
                ce.append(s)
    if ce or cc:
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
                if c:
                    # Регистронезависимость как у seen-ключей
                    # parse_and_save: KEYWORD.example.com в trojan.txt
                    # должен закрывать keyword.example.com в vless.txt.
                    key = c.lower()
                    if key not in gm:
                        gm[key] = {
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
    # dns4.2.21 (аудит A3 M4): collapse_addresses на тысячах CIDR съедает
    # CPU MIPS-роутера в Flask-воркере. При большом списке свёртку
    # пропускаем целиком: ДАННЫЕ НЕ ОБРЕЗАЮТСЯ, секции возвращаются как
    # есть, а панель показывает отметку. Обрезание списка (вариант
    # внешнего отчёта) сознательно отклонено как потеря данных.
    if len(an) > 2000:
        return sections, [
            ('\U0001f4e6 CIDR: %d адресов — свёртка пропущена (>2000) '
             'для экономии CPU, список сохранён полностью') % len(an)]
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
    moves = []
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
        if sr > 0:
            moves.append((comment, sr))
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
    # Переносы между секциями показываем явно: пользователь должен
    # видеть, откуда адреса ушли в объединённые сети (заголовок секции
    # при этом остаётся в файле — его сохраняет parse_and_save).
    for moved_from, moved_count in moves[:6]:
        rep.append(
            f"\U0001f4e6 {moved_count} адрес. из "
            + (f"«{moved_from}»"
               if moved_from
               else 'блока без названия')
            + ' объединены в общие сети')
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


@with_update_lock
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
            # Пустой блок закрываем независимо от числа записей: заголовок
            # «осиротевшей» секции (все её адреса ушла CIDR-оптимизация)
            # обязан пережить пересохранение, иначе теряется аннотация.
            if ce or cc:
                secs.append((cc, ce))
                cc = None
                ce = []
            continue
        if s.startswith('#'):
            if ce or cc:
                secs.append((cc, ce))
                ce = []
            cc = s[1:].strip()
        else:
            cl = _clean_entry(s)
            if not cl:
                continue
            r = _validate_entry(cl)
            if r is None:
                # dns4.2.24 (A6 N3): подпись причины отклонения.
                _why = _rejection_reason(cl)
                errors.append(
                    f"\u26a0\ufe0f {cl}"
                    + (f" — {_why}" if _why else ""))
                continue
            key = cl.lower()
            if key in seen:
                c = seen[key]
                dups.append(
                    f"\u26a0\ufe0f {cl}"
                    + (f" (#{c})"
                       if c else ""))
                continue
            if key in gs:
                info = gs[key]
                dups.append(
                    f"\u26a0\ufe0f {cl}"
                    f" ({info['file']}.txt"
                    + (f", #{info['comment']}"
                       if info['comment']
                       else "")
                    + ")")
                continue
            seen[key] = cc
            if r[0] == 'domain':
                # Регистр доменов значения не имеет, а shell при
                # резолве приводит к нижнему — сохраняем нормализованно,
                # чтобы дедупликация не зависела от регистра ввода.
                core, _, tail = s.partition('#')
                s = core.strip().lower() + (
                    ' # ' + tail.strip() if tail else '')
            ce.append(s)
    if ce or cc:
        secs.append((cc, ce))
    del seen, gs
    secs, cr = _optimize_networks(secs)
    out = []
    # Порядок секций — пользовательский: сохраняем как введён.
    # Раньше именованные секции пересортировывались по алфавиту при
    # каждом сохранении, что ломало группировку и diff'ы. Сортировкой
    # записей внутри секции (_sort_key) порядок секций не затрагивается.
    cd = ci = cc2 = 0
    first_block = True
    for comment, entries in secs:
        if comment is None and not entries:
            continue
        if not first_block:
            out.append('')
        first_block = False
        if comment is not None:
            # Заголовок секции сохраняем, даже если CIDR-оптимизация
            # увела все её адреса: комментарий — пользовательская
            # аннотация («что это за ресурс и почему он тут»).
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
                    ['curl', '-s', '--fail', '--max-filesize', '1048576',
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
                ['curl', '-s', '--fail', '--max-filesize', '1048576',
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
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#10151e">
<meta name="csrf-token" content="{{ csrf_token }}">
<title>KeenZOO — панель управления</title>
<script>try{var savedTheme=localStorage.getItem("keenzoo-theme");if(savedTheme==="light"||savedTheme==="dark")document.documentElement.dataset.theme=savedTheme;}catch(e){}</script>
<style>
:root{color-scheme:dark;--txt:#e9edf5;--muted:#a0acc0;--accent:#7de0c3;--accent2:#97b6ff;--green:#7de0b1;--red:#ff98a6;--yellow:#f0cc83;--orange:#f0bc85;--blue:#97b6ff;--page:#10151e;--surface:#181f2b;--gl:#202938;--gl2:#283449;--brd:#344055;--bg:#111923;--shd:0 8px 32px #00000012;--font-text:'Segoe UI',system-ui,-apple-system,Roboto,'Helvetica Neue',Arial,sans-serif;--font-head:'Segoe UI',system-ui,-apple-system,Roboto,'Helvetica Neue',Arial,sans-serif;--font-mono:ui-monospace,'SF Mono','Cascadia Mono',Consolas,'Liberation Mono',monospace;--font-proto:ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif}
:root[data-theme=light]{color-scheme:light;--txt:#18283a;--muted:#536479;--accent:#096e59;--accent2:#345eb0;--green:#167348;--red:#b92c43;--yellow:#845900;--orange:#8f4c0e;--blue:#345eb0;--page:#f1f4f8;--surface:#fff;--gl:#f4f7fa;--gl2:#e7edf4;--brd:#ccd6e2;--bg:#f8fafc;--shd:0 8px 32px #172f4b08}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--txt);font:15.5px/1.62 var(--font-text);padding:0 32px 36px;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}button,input,textarea,select{font:inherit}button{cursor:pointer}button:disabled{opacity:.55;cursor:wait}button,a,input,textarea,select{-webkit-tap-highlight-color:transparent}a{color:var(--accent)}:focus-visible{outline:3px solid var(--accent2);outline-offset:4px}h1,h2,h3,p{margin:0}button,input,select{min-height:44px}textarea,input,select{max-width:100%;min-width:0}button{touch-action:manipulation}button,code,.hint,.msg,.dns-port,.dns-state,.netfilter-status{overflow-wrap:anywhere}svg{display:block}textarea{resize:vertical}input,textarea{scroll-margin-top:120px}button{transition:border-color .15s}
.app-header{max-width:1440px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:100px;border-bottom:1px solid var(--brd)}.brand{display:flex;align-items:center;gap:12px}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border:1px solid var(--accent);border-radius:14px;color:var(--accent);background:var(--gl)}.brand-name{font-family:var(--font-head);font-size:21px;font-weight:760;letter-spacing:-.6px}.brand-sub{font-size:12px;color:var(--muted)}.header-tools{display:flex;align-items:center;gap:16px}.environment{font-size:12px;color:var(--muted);padding:7px 12px;border:1px solid var(--brd);border-radius:99px}.theme-toggle{display:flex;gap:8px;align-items:center;border:1px solid var(--brd);border-radius:12px;padding:8px 14px;color:var(--txt);background:var(--surface)}.theme-toggle:hover{background:var(--gl2)}.skip-link{position:absolute;top:-100px;left:16px;z-index:30;background:var(--surface);padding:12px}.skip-link:focus{top:10px}
.page-intro{max-width:1440px;margin:32px auto 24px;display:flex;align-items:flex-end;justify-content:space-between;gap:24px}.eyebrow{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:var(--accent);margin-bottom:8px}h1{font-family:var(--font-head);font-size:clamp(27px,2.6vw,36px);font-weight:760;letter-spacing:-.8px;line-height:1.18}.page-intro p{color:var(--muted);margin-top:10px;font-size:13px;line-height:1.6}.intro-note{color:var(--muted);font-size:11.5px;line-height:1.65;max-width:240px;text-align:right}.shell{max-width:1440px;display:grid;grid-template-columns:220px minmax(0,1fr);gap:28px;margin:auto;align-items:start}.tabs{position:sticky;top:20px;min-width:0;display:flex;flex-direction:column;gap:5px;padding:8px 0}.nav-label{font-size:10px;font-weight:750;letter-spacing:1.5px;color:var(--muted);padding:14px 14px 8px;text-transform:uppercase}.tab-btn{display:flex;align-items:center;gap:11px;border:1px solid transparent;border-radius:12px;background:transparent;color:var(--muted);padding:11px 13px;text-align:left;width:100%;font-family:var(--font-proto);font-size:13.5px;font-weight:600;letter-spacing:.03em;min-height:48px}.tab-btn:hover{background:var(--gl);color:var(--txt)}.tab-btn.active{color:var(--accent);background:var(--gl);border-color:var(--brd);font-weight:650}.nav-icon{display:inline-grid;place-items:center;flex:0 0 28px;height:28px;border:1px solid var(--brd);border-radius:8px;font:600 11px var(--font-mono)}.tab-btn.active .nav-icon{background:var(--accent);color:var(--page);border-color:var(--accent)}.nav-count{margin-left:auto;font:11px var(--font-mono);color:var(--muted)}.nav-footer{color:var(--muted);font-size:11px;line-height:1.7;padding:22px 14px;border-top:1px solid var(--brd);margin-top:16px}.card{min-width:0;background:var(--surface);border:1px solid var(--brd);border-radius:20px;padding:28px;box-shadow:var(--shd)}.tab-content{display:none;min-width:0}.tab-content.active{display:block}.panel-heading{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:8px 20px;margin-bottom:24px}.panel-heading h2{font-family:var(--font-head);font-size:24px;letter-spacing:-.5px;font-weight:740;line-height:1.25}.panel-heading p{font-size:12.5px;color:var(--muted);margin-top:6px;line-height:1.6}.section-tag{flex-shrink:0;color:var(--muted);font:11px var(--font-mono);letter-spacing:.04em;border:1px solid var(--brd);border-radius:8px;padding:6px 9px}#tab-ss .panel-heading h2,#tab-tr .panel-heading h2,#tab-vl .panel-heading h2,#tab-to .panel-heading h2,#tab-hy .panel-heading h2{font-family:var(--font-proto);font-weight:800;text-transform:uppercase;letter-spacing:.06em;overflow-wrap:anywhere;min-width:0}
.protocol-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.15fr);gap:28px}.setup-column,.list-column{min-width:0}.list-column{border-left:1px solid var(--brd);padding-left:28px}.list-column>.divider{margin-top:0}.draft-indicator{display:none;margin-top:12px;color:var(--orange);font-size:12px}.draft-indicator.visible{display:block}.section-title{font-size:14px;font-weight:600}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:7px}textarea,input[type=text],select{display:block;width:100%;padding:12px 14px;color:var(--txt);background:var(--bg);border:1px solid var(--brd);border-radius:11px;font-family:var(--font-text);font-size:16px;line-height:1.5}textarea{font-family:var(--font-mono);font-size:14px}textarea:focus,input:focus,select:focus{border-color:var(--accent)}textarea::placeholder,input::placeholder{color:var(--muted);opacity:.7}.key-area{min-height:106px}.list-area{min-height:350px;line-height:1.7;tab-size:2}.hint{font-size:11.5px;color:var(--muted);line-height:1.65;margin:8px 0 14px}.hint code{background:var(--gl2);border-radius:4px;padding:2px 5px;font-size:11px}.divider{border-top:1px solid var(--brd);margin:24px 0 16px;padding-top:16px;line-height:1.6}.divider span{font-size:12px;color:var(--muted);font-weight:600}.counter{color:var(--muted);font:11px/1.8 ui-monospace,monospace;text-align:right;margin-top:6px}.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:44px;padding:11px 16px;border-radius:10px;border:1px solid var(--brd);background:var(--gl);color:var(--txt);font-size:13px;font-weight:650;line-height:1.5}.btn:hover{background:var(--gl2);border-color:var(--muted)}.btn-key,.btn-save{background:var(--accent);color:var(--page);border-color:var(--accent)}.btn-key:hover,.btn-save:hover{background:var(--accent);filter:brightness(.93);border-color:var(--accent)}.btn-save,.btn-cfg{margin-top:8px}.btn-cfg{color:var(--orange)}.btn.loading .btn-label{opacity:.7}.spinner-ring{display:none;width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}.btn.loading .spinner-ring{display:inline-block}@keyframes spin{to{transform:rotate(360deg)}}
.svc-row{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:14px 16px;background:var(--gl);border:1px solid var(--brd);border-radius:12px;margin-bottom:8px}.svc-name{font-family:var(--font-proto);font-size:13px;font-weight:700;letter-spacing:.04em;overflow-wrap:anywhere}.svc-name.on{color:var(--green)}.svc-name.off{color:var(--muted)}.switch{position:relative;display:inline-block;flex:0 0 50px;width:50px;height:44px;margin:0}.switch input{position:absolute;inset:0;width:100%;height:100%;opacity:0;margin:0;cursor:pointer;z-index:1}.slider{position:absolute;inset:9px 0;border:1px solid var(--brd);border-radius:24px;background:var(--bg)}.slider:before{content:'';position:absolute;left:3px;top:3px;width:18px;height:18px;border-radius:50%;background:var(--muted);transition:transform .18s}.switch input:checked+.slider{background:var(--accent);border-color:var(--accent)}.switch input:checked+.slider:before{transform:translateX(23px);background:var(--page)}.switch input:focus-visible+.slider{outline:3px solid var(--accent2);outline-offset:4px}.service-note{font-size:11px;color:var(--muted);margin:0 0 22px}
.msg,#update-bar,#pin-bar{max-width:1440px;margin:12px auto;padding:13px 18px;border:1px solid var(--brd);border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:var(--surface)}.msg-ok,#update-bar.done,#pin-bar.ok{border-left:3px solid var(--green);color:var(--green)}.msg-err,#update-bar.error,#pin-bar.warn{border-left:3px solid var(--red);color:var(--red)}#update-bar,#pin-bar{display:none}#update-bar.running,#update-bar.done,#update-bar.error,#pin-bar.ok,#pin-bar.warn{display:block}#update-bar.running{color:var(--accent)}.info-box{background:transparent;border:1px solid var(--brd);border-left:2px solid var(--brd);border-radius:10px;padding:13px 16px;font-size:12.5px;line-height:1.75;color:var(--muted);opacity:.92;margin-bottom:22px}.info-box b{color:var(--txt)}.lk-presets{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 18px}.lk-presets button{border:1px solid var(--brd);border-radius:99px;background:var(--surface);padding:8px 16px;color:var(--muted);font-family:var(--font-proto);font-size:12.5px;font-weight:600;letter-spacing:.04em}.lk-presets button:hover{border-color:var(--accent);color:var(--accent)}#lk-status{overflow-wrap:anywhere}#lk-output{min-height:260px!important}
.dns-panel{min-width:0}.dns-toggle{display:none}.dns-grid,.ver-grid{display:none;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.dns-grid.open,.ver-grid.open{display:grid}.dns-label{grid-column:1/-1;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin:16px 0 2px}.dns-port,.dns-state,.netfilter-status{padding:14px;border:1px solid var(--brd);border-radius:11px;background:var(--bg);font:12px/1.7 var(--font-mono);min-width:0}.dns-state,.netfilter-status{grid-column:1/-1}.dnssec,.dns-port.ok,.netfilter-status.ok{color:var(--green)}.no-dnssec{color:var(--yellow)}.tunnel{color:var(--blue)}.unavailable,.dns-port.fail{color:var(--red)}.checking{color:var(--muted)}.netfilter-status.degraded{color:var(--orange)}.dns-grid>.hint,#dns-v4-state{grid-column:1/-1;margin:0;overflow-wrap:anywhere;font-size:12px}#dns-v4-state{background:var(--gl);border:1px solid var(--brd);border-radius:10px;padding:14px!important;font-family:var(--font-mono)}.dns-grid>.btn{grid-column:span 2}.dns-legend{display:flex;flex-wrap:wrap;gap:8px;grid-column:1/-1;font:10px/1.6 var(--font-mono)}.dns-legend span{border:1px solid var(--brd);border-radius:6px;padding:5px 8px;overflow-wrap:anywhere}.pin-box{display:none;grid-column:1/-1;white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--brd);border-radius:10px;padding:14px;color:var(--muted);font:12px/1.8 var(--font-mono)}.pin-box.on{display:block}.ver-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.ver-item{min-width:0;padding:16px;background:var(--bg);border:1px solid var(--brd);border-radius:12px}.ver-item .dns-port{border:0;padding:0;min-height:55px;font-size:13px}.upd-btn{display:none;color:var(--accent)}.upd-btn.on,.upd-all-row.on{display:block}.upd-all-row{display:none;grid-column:1/-1}.upd-all-row .upd-btn{display:block}.upd-out{display:none;grid-column:1/-1;white-space:pre-wrap;overflow:auto;max-height:400px;overflow-wrap:anywhere;background:var(--bg);padding:18px;border:1px solid var(--brd);border-radius:12px;font:12px/1.8 var(--font-mono)}.upd-out.on{display:block}.panel-actions{display:flex;gap:12px;margin-bottom:20px}.panel-actions .btn{width:auto}.app-footer{max-width:1440px;margin:26px auto 0;display:flex;justify-content:space-between;gap:16px;color:var(--muted);font-size:11px}.app-footer span{overflow-wrap:anywhere}
@media(min-width:1600px){body{padding-left:48px;padding-right:48px}}
@media(max-width:1150px){.protocol-layout{grid-template-columns:minmax(0,1fr)}.list-column{border-left:0;padding-left:0;border-top:1px solid var(--brd);padding-top:24px}.list-column>.divider{border:0;padding:0}.shell{grid-template-columns:190px minmax(0,1fr);gap:20px}.card{padding:24px}.ver-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:900px){body{padding:0 20px 28px}.app-header{min-height:84px}.shell{display:block}.tabs{position:relative;top:0;display:flex;flex-direction:row;overflow-x:auto;gap:7px;padding:0 0 14px;margin-bottom:6px;scrollbar-width:thin;scroll-padding-inline:5px}.nav-label,.nav-footer,.nav-count{display:none}.tab-btn{flex:0 0 auto;width:auto;white-space:nowrap;padding:8px 12px;min-height:46px;border-color:var(--brd);background:var(--surface)}.nav-icon{flex-basis:24px;width:24px;height:24px;font-size:10px}.page-intro{margin:24px auto 20px}.intro-note{display:none}.card{padding:24px}.protocol-layout{grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:22px}.list-column{border-top:0;border-left:1px solid var(--brd);padding:0 0 0 22px}.list-column>.divider{padding-top:0}.environment{display:none}}
@media(max-width:640px){body{padding:0 14px 24px;padding-bottom:max(24px,env(safe-area-inset-bottom))}.app-header{min-height:78px}.brand-name{font-size:19px}.brand-sub{font-size:10px}.brand-mark{width:36px;height:36px;border-radius:11px}.theme-toggle{padding:8px 10px;font-size:12px}.header-tools{gap:6px}.page-intro{margin:22px auto 18px}.page-intro p{font-size:12px}.card{padding:18px;border-radius:15px}.panel-heading{gap:6px 10px;margin-bottom:20px}.panel-heading h2{font-size:21px}#tab-ss .panel-heading h2,#tab-tr .panel-heading h2,#tab-vl .panel-heading h2,#tab-to .panel-heading h2,#tab-hy .panel-heading h2{font-size:19px;letter-spacing:.05em}.section-tag{font-size:10px;padding:5px 7px}.protocol-layout{grid-template-columns:minmax(0,1fr);gap:24px}.list-column{border:0;border-top:1px solid var(--brd);padding:20px 0 0}.list-area{min-height:280px}textarea{font-size:16px}.dns-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.dns-state,.netfilter-status,.dns-grid>.btn{grid-column:1/-1}.ver-grid{grid-template-columns:minmax(0,1fr)}.info-box{padding:12px;font-size:12px}.app-footer{flex-direction:column;gap:4px}.svc-row{padding:10px 12px}.panel-actions .btn{width:100%}.nav-icon{display:none}.tabs{margin-right:-2px}.tab-btn{font-size:13px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}

</style></head><body>

<a class="skip-link" href="#main-content">К настройкам</a>
<header class="app-header">
  <div class="brand"><span class="brand-mark" aria-hidden="true"><svg width="23" height="23" viewBox="0 0 24 24" fill="none"><path d="M5 4v16M19 4l-9 8 9 8M10 12H5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span><div><div class="brand-name">KeenZOO</div><div class="brand-sub">Сеть под вашим контролем</div></div></div>
  <div class="header-tools"><span class="environment">IPv4 · локальная панель</span><button type="button" class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" aria-label="Переключить цветовую тему"><span aria-hidden="true">◐</span><span id="theme-label">Светлая тема</span></button></div>
</header>
<section class="page-intro"><div><div class="eyebrow">Панель управления</div><h1>Подключения и маршруты</h1><p>Настройте протоколы, управляйте списками и проверяйте DNS.</p></div><div class="intro-note">Изменения применяются<br>только после вашего действия.</div></section>

<div id="update-bar" role="status" aria-live="polite"></div>
<div id="pin-bar" role="status" aria-live="polite"></div>
{% with msgs = get_flashed_messages(
  with_categories=true) %}
{% if msgs %}{% for cat, msg in msgs %}
<div role="status" class="msg {{ 'msg-ok'
  if cat=='ok' else 'msg-err' }}">
  {{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<div class="shell">
<nav class="tabs" role="tablist" aria-label="Разделы панели" aria-orientation="vertical">
<div class="nav-label" role="presentation">Подключения</div>
{% for tid,label,icon in [('ss','Shadowsocks','SS'),('tr','Trojan','TR'),('vl','VLESS','VL'),('to','Tor','TO'),('hy','Hysteria','HY'),('bt','Трафик роутера','RT'),('lk','Поиск адресов','↗'),('dn','DNS и сеть','◎'),('up','Обновления','↑')] %}
{% if tid=='bt' %}<div class="nav-label" role="presentation">Инструменты</div>{% endif %}
<button type="button" id="btn-{{ tid }}" class="tab-btn {% if active==tid %}active{% endif %}" role="tab" aria-selected="{{ 'true' if active==tid else 'false' }}" aria-controls="tab-{{ tid }}" tabindex="{{ '0' if active==tid else '-1' }}" onclick="go('{{ tid }}')"><span class="nav-icon" aria-hidden="true">{{ icon }}</span><span>{{ label }}</span>{% if tid in list_counts %}<span class="nav-count" title="Записей в списке">{{ list_counts[tid] }}</span>{% endif %}</button>
{% endfor %}
<div class="nav-footer" role="presentation">KeenZOO UI 6<br>Без внешних шрифтов и CDN</div>
</nav>
<main class="card" id="main-content" tabindex="-1">
  {% for tid, tname, fkey in [
    ('ss','Shadowsocks','shadowsocks'),
    ('tr','Trojan','trojan'),
    ('vl','VLESS','vless'),
    ('to','Tor','tor'),
    ('hy','Hysteria','hysteria')] %}
  <div id="tab-{{ tid }}"
    class="tab-content
    {% if active==tid %}active{% endif %}" role="tabpanel" aria-labelledby="btn-{{ tid }}" tabindex="0">
    <div class="panel-heading"><div><h2>{{ tname }}</h2><p>Подключение и правила выборочного обхода</p></div><span class="section-tag">{{ fkey }}.txt</span></div>
    <div class="protocol-layout"><section class="setup-column" aria-label="Настройки подключения">
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
          {{ 'разрешён' if svc_enabled[tid]
            else 'отключён' }}</span>
        <label class="switch">
          <input type="checkbox" role="switch" aria-label="Включить {{ tname }} в конфигурации"
            {% if svc_enabled[tid] %}checked{% endif %}
            onchange="document.getElementById(
              'tgl-{{ tid }}').submit()">
          <span class="slider"></span>
        </label>
      </div>
    </form>
    <p class="service-note">Переключатель отражает настройку автозапуска, а не проверку соединения.</p>
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
         obfs4</div>
      <label for="obfs4_bridges">Мосты obfs4 (по одному)</label>
      <textarea name="obfs4_bridges" id="obfs4_bridges" spellcheck="false"
        class="key-area"
        placeholder="obfs4 ..."></textarea>
      <div style="font-size:.88rem;
        color:var(--accent);
        font-weight:600;
        margin:.6rem 0 .4rem">
         Webtunnel</div>
      <label for="webtunnel_bridges">Мосты Webtunnel (по одному)</label>
      <textarea name="webtunnel_bridges" id="webtunnel_bridges" spellcheck="false"
        class="key-area"
        placeholder="webtunnel ..."></textarea>
      <button type="submit"
        class="btn btn-key">
        <span class="spinner-ring"></span>
        <span class="btn-label">
           Применить</span>
      </button>
    </form>
    {% else %}
    <form method="post"
      action="{{ url_for('key_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label for="key-{{ tid }}">Ссылка подключения {{ tname }}</label>
      <input type="text" name="key" id="key-{{ tid }}" autocomplete="off" autocapitalize="none" spellcheck="false"
        placeholder="{{ {'ss':'ss://…','tr':'trojan://…','vl':'vless://…','hy':'hysteria2://…'}[tid] }}">
      <p class="hint">
        Вставьте ссылку подключения. После применения сервис будет перезапущен.</p>
      <button type="submit"
        class="btn btn-key">
        <span class="spinner-ring"></span>
        <span class="btn-label">
           Применить ключ</span>
      </button>
    </form>
    <div class="divider">
      <span>
        или JSON-конфиг</span></div>
    <form method="post"
      action="{{ url_for('config_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label for="config-{{ tid }}">JSON-конфигурация</label>
      <textarea name="config_data" id="config-{{ tid }}" spellcheck="false" autocapitalize="none"
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
           Применить конфиг</span>
      </button>
    </form>
    {% endif %}
    </section><section class="list-column" aria-label="Список обхода">
    <div class="divider">
      <span>
        {{ fkey }}.txt &mdash;
        {{ list_details[tid] }}</span>
    </div>
    <form method="post"
      action="{{ url_for('list_'+tid) }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label for="ta-{{ tid }}">Домены, IP и сети · {{ ipsets[tid] }}</label>
      <textarea name="content" spellcheck="false" autocapitalize="none"
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
           Сохранить</span>
      </button>
    </form>
    </section></div>
  </div>
  {% endfor %}
  <div id="tab-bt" class="tab-content
    {% if active=='bt' %}active{% endif %}" role="tabpanel" aria-labelledby="btn-bt" tabindex="0"><div class="panel-heading"><div><h2>Трафик роутера</h2><p>Отдельный маршрут для TCP-соединений самого роутера</p></div></div>
    <div class="info-box">
       <b>Обход роутера</b><br>
      Только TCP OUTPUT для доменов/IP из bot.txt.<br>
      DNS и UDP клиентов этим выбором не изменяются.<br>
      Не добавляйте IP своего VPS в список.</div>
    <form method="post" action="{{ url_for('route_router_protocol') }}"
      onsubmit="return btnLock(this)">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <label for="router-protocol">Протокол TCP для bot.txt</label>
      <select id="router-protocol" name="protocol">
        {% for key, item in router_protocols.items() %}
        <option value="{{ key }}" {% if router_protocol==key %}selected{% endif %}>
          {{ item[1] }}</option>
        {% endfor %}
      </select>
      <p class="hint">Сначала настройте и включите протокол. Выбор сохраняется
        после перезагрузки. При отключённом протоколе перехват снимается
        (прямое соединение, без автоматической смены протокола).
        Для доменного сервера Trojan необходим актуальный pin в hosts.</p>
      <button type="submit" class="btn btn-save">
        <span class="spinner-ring"></span>
        <span class="btn-label">Применить протокол</span>
      </button>
    </form>
    <div class="divider">
      <span> bot.txt &mdash;
        {{ list_details.bt }}</span></div>
    <form method="post"
      action="{{ url_for('list_bt') }}"
      onsubmit="return btnLock(this)">
      <input type="hidden"
        name="csrf_token"
        value="{{ csrf_token }}">
      <label for="ta-bt">Домены, IP и сети · {{ ipsets.bt }}</label>
      <textarea name="content" spellcheck="false" autocapitalize="none"
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
           Сохранить</span>
      </button>
    </form>
  </div>
  <div id="tab-lk" class="tab-content
    {% if active=='lk' %}active{% endif %}" role="tabpanel" aria-labelledby="btn-lk" tabindex="0"><div class="panel-heading"><div><h2>Поиск адресов</h2><p>Найдите домены, IP и сети для ваших списков</p></div></div>
    <div class="info-box">
       <b>Поиск IP и CIDR</b><br>
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
      <input type="text" id="lk-query" aria-label="Домен, IP или автономная система" autocapitalize="none" spellcheck="false"
        placeholder="Сайт, IP, AS32934">
      <button class="btn btn-key"
        style="width:auto;padding:0 1.2rem"
        aria-label="Найти адреса" onclick="doLookup()">
        <span class="spinner-ring"
          id="lk-spin"></span>
        <span class="btn-label">Найти</span>
      </button>
    </div>
    <div id="lk-results"
      style="display:none">
      <div class="divider">
        <span>Результаты</span></div>
      <div id="lk-info" role="status" aria-live="polite"
        style="font-size:.8rem;
        color:var(--muted);
        margin-bottom:.5rem"></div>
      <div id="lk-status"
        style="margin-bottom:.8rem"></div>
      <textarea id="lk-output" aria-label="Результаты поиска"
        class="list-area" readonly
        style="min-height:200px;
        background:var(--bg)"></textarea>
      <div style="display:flex;
        gap:.5rem;margin-top:.5rem">
        <button class="btn btn-save"
          style="flex:1"
          id="copy-lookup" onclick="copyLookup(event)">
           Копировать</button>
      </div>
      <p class="hint" id="copy-note" role="status" aria-live="polite"></p>
      <p class="hint">
        Скопируйте и вставьте
        в список обхода нужного
        протокола.</p>
    </div>
  </div>
<div id="tab-dn" class="tab-content {% if active=='dn' %}active{% endif %}" role="tabpanel" aria-labelledby="btn-dn" tabindex="0"><div class="panel-heading"><div><h2>DNS и сеть</h2><p>Состояние DNSSEC, туннелей и правил перехвата</p></div></div><div class="info-box">Открытие вкладки читает сохранённое состояние. <b>«Проверить без изменений»</b> запускает измерения, <b>«Пересобрать DNS»</b> меняет конфигурацию после подтверждения.</div>
  <div class="dns-grid open" id="dns-grid">
    <div class="dns-label">Последнее решение DNS v4 (GET не запускает проверку)</div>
    <div id="dns-refresh-note" role="status" aria-live="polite" class="hint"></div>
    <div class="dns-state" id="dns-state">Ещё не прочитано</div>
    <div id="dns-snapshot-age" class="hint"></div>
    <div id="dns-client-state" class="hint">Порт 53: ещё не проверен</div>
    <div class="netfilter-status" id="netfilter-state">Netfilter: ещё не проверен</div>
    <button type="button" class="btn" onclick="fetchDns()">Проверить без изменений</button>
    <button type="button" class="btn" onclick="applyDns()">Пересобрать DNS</button>
    <div class="dns-label">Легенда последнего DNS-решения</div>
    <div class="dns-legend">
      <span class="dnssec">DNSSEC_OK</span>
      <span class="no-dnssec">EMERGENCY_DNS / без DNSSEC</span>
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
<div id="tab-up" class="tab-content {% if active=='up' %}active{% endif %}" role="tabpanel" aria-labelledby="btn-up" tabindex="0"><div class="panel-heading"><div><h2>Обновления</h2><p>Версии компонентов и управляемое обновление</p></div></div><div class="info-box">Проверка версий запускается вручную. Обновление может перезапустить сервисы и временно прервать соединения.</div><div class="panel-actions"><button type="button" class="btn btn-key" onclick="fetchVer()">Проверить версии</button></div>
  <div class="ver-grid open" id="ver-grid">
    <div id="versions-refresh-note" role="status" aria-live="polite" class="hint" style="grid-column:1/-1">Проверка ещё не запускалась. Нажмите «Проверить версии».</div>
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
</main>
</div>
<footer class="app-footer"><span>KeenZOO · UI 6</span><span>Настройки и ключи хранятся на роутере</span></footer>
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
function go(id,keepScroll){
  var el=g('tab-'+id);if(!el)return;
  each(document.querySelectorAll('.tab-content'),function(p){p.classList.toggle('active',p===el)});
  each(document.querySelectorAll('.tab-btn'),function(b){var on=b.id==='btn-'+id;b.classList.toggle('active',on);b.setAttribute('aria-selected',on?'true':'false');b.tabIndex=on?0:-1});
  if(window.history&&history.replaceState)history.replaceState(null,'','/?tab='+id);
  document.title='KeenZOO — '+g('btn-'+id).querySelectorAll('span')[1].textContent;
  if(window.matchMedia('(max-width:900px)').matches){var nav=document.querySelector('.tabs'),button=g('btn-'+id);nav.scrollLeft=button.offsetLeft-nav.clientWidth/2+button.offsetWidth/2;}
  if(id==='dn')pollDns();
  if(!keepScroll)window.scrollTo(0,0);
}
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
    }else if(d.status==='defer'){
      /* Отложено из-за временной недоступности DNS: повтор по крону через
         сутки, поэтому причина показывается без окна свежести — она
         исчезнет при следующем переходе в running/done/error. */
      bar.className='error';
      bar.textContent='\u23F3 Отложено: '+(d.message||'');
      bar.style.display='block';stop();
    }else if((d.status==='error'||d.status==='rollback_failed')&&d.ts&&
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
(function(){var el=document.createElement('div');el.id='dns-v4-state';el.style.cssText='padding:8px;overflow-wrap:anywhere';var box=g('dns-grid');if(box)box.appendChild(el);})();
var _dO=false;
function toggleDns(){
  var el=g('dns-grid');_dO=!_dO;
  el.className=_dO?'dns-grid open':'dns-grid';
  if(_dO)pollDns()}
function dnsStateClass(state){
  return state==='DNSSEC_OK'?'dnssec':
    ((state==='DNS_OK_NO_DNSSEC'||state==='EMERGENCY_DNS')?'no-dnssec':
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
function startCheck(url,done,fail){
  var b=new FormData();b.append('csrf_token',
    document.querySelector('input[name=csrf_token]').value);
  fetch(url,{method:'POST',body:b,credentials:'same-origin'})
  .then(function(r){return r.json().then(function(d){
    if(!r.ok||!d.ok)throw new Error(d.error||'HTTP '+r.status);
    done(d)})}).catch(fail)}
var _dnsPolling=false, _dnsApplying=false;
function fetchDns(){
  if(_dnsPolling||_dnsApplying)return;
  _dnsPolling=true;
  g('dns-refresh-note').textContent='Проверка локальных DNS-портов без изменения настроек…';
  each(DNS_PORTS,function(p){setCell(g('dp-'+p),'checking',p+'…')});
  startCheck('/api/dns-probe',function(){pollDnsProbe();},function(e){
    _dnsPolling=false;g('dns-refresh-note').textContent=String(e)})}
function pollDnsProbe(){
  fetch('/api/dns-probe',{credentials:'same-origin'})
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){
    if(d.status==='running'){setTimeout(pollDnsProbe,2000);return}
    _dnsPolling=false;pollDns();
  }).catch(function(e){_dnsPolling=false;g('dns-refresh-note').textContent='Ошибка: '+e})}
function applyDns(){
  if(_dnsPolling||_dnsApplying)return;
  if(!confirm('Пересобрать DNS-конфигурацию? При изменении настроек dnsmasq будет перезапущен.'))return;
  _dnsApplying=true;
  g('dns-refresh-note').textContent='Применение DNS…';
  startCheck('/api/dns-refresh',function(){pollDnsApply();},function(e){
    _dnsApplying=false;g('dns-refresh-note').textContent=String(e)})}
function pollDnsApply(){
  fetch('/api/dns-refresh-status',{credentials:'same-origin'})
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){
    if(d.status==='running'){setTimeout(pollDnsApply,2000);return}
    _dnsApplying=false;
    if(d.status==='error'){
      g('dns-refresh-note').textContent='Применение не завершено: '+(d.message||'');
      return}
    fetchDns();
  }).catch(function(e){_dnsApplying=false;g('dns-refresh-note').textContent='Ошибка: '+e})}
function pollDns(){
  fetch('/api/dns-status',{credentials:'same-origin'})
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){
    var dnsState=d.dns_state||'DNS_UNAVAILABLE', snap=d.snapshot||{}, live=d.observation||{};
    if(d.policy_v4&&d.policy_v4.version===4){var pv=d.policy_v4;var pn=g('dns-v4-state');if(pn)pn.textContent='Контроллер: '+pv.mode+' · Предпочтительный порт: '+(pv.preferred||'—')+' · Активный upstream: '+(pv.active?pv.active[0]+':'+pv.active[1]+' ('+(pv.active[2]?'TCP':'UDP')+')':'нет')+' · Туннель: '+(pv.tunnel||'не выбран')+(pv.health_mode==='hybrid'?' · Гибрид: контроль без подтверждений '+Math.round(pv.interval/60)+' мин; пул 11:00 / 23:00 (время роутера); возврат Primary '+Math.round(pv.recovery_interval/60)+' мин · Последнее подтверждение: '+(pv.last_evidence_epoch?new Date(pv.last_evidence_epoch*1000).toLocaleString():'нет')+' · Служебных проб: '+pv.health_query_count+' · Пассивных подтверждений: '+pv.passive_confirmations:'');}
    setDnsState('dns-state',dnsState);
    g('dns-snapshot-age').textContent=snap.epoch
      ? 'Решение от '+new Date(snap.epoch*1000).toLocaleString()+
        '; возраст '+snap.age_seconds+' с. Это не текущая проверка.'
      : 'Сохранённого решения нет';
    setNetfilterState(d.netfilter_state||'NETFILTER_DEGRADED');
    var port53=(live.ports||{})['53'];
    g('dns-client-state').textContent=port53
      ? 'Порт 53: '+port53.state+(port53.rcode?' / '+port53.rcode:'')+
        '; проверен '+new Date(port53.checked_at*1000).toLocaleTimeString()
      : 'Порт 53: ещё не проверен';
    g('dns-refresh-note').textContent=live.status==='error'
      ? live.message : (live.checked_at
        ? 'Измерения от '+new Date(live.checked_at*1000).toLocaleTimeString()+
          (live.stale?' — устарели, повторите проверку':' (без изменения конфигурации)')
        : 'Нет текущих измерений');
    each(DNS_PORTS,function(p){
      var info=(live.ports||{})[String(p)];
      if(!info){setCell(g('dp-'+p),'checking',p+' — не измерен');return}
      var cls=live.stale?'checking':(info.ok?(info.ad?'dnssec':'no-dnssec'):'unavailable');
      var label=info.rcode||info.state;
      setCell(g('dp-'+p),cls,p+' '+label+(live.stale?' (старое)':''));
      if(g('dp-'+p))g('dp-'+p).title='IPv4 local query; '+info.state+'; '+info.elapsed_ms+' ms';
    });
    var pb=g('pin-box'),pl=g('pin-label'),pin=d.pinned||[];
    if(pb&&pl){
      if(pin.length){
        var t='';each(pin,function(x){t+=x.host+' → '+x.ip+'\n'});
        pb.textContent=t.replace(/\n$/,'');pb.className='pin-box on';pl.style.display='';
      }else{pb.className='pin-box';pl.style.display='none'}
    }
  }).catch(function(e){g('dns-refresh-note').textContent='Ошибка чтения состояния: '+e})}

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
  if(_vO)pollVer()}
var _versionsPolling=false;
function fetchVer(){
  if(_versionsPolling)return;
  _versionsPolling=true;
  g('versions-refresh-note').textContent='Проверка версий…';
  startCheck('/api/protocol-versions/refresh',function(){pollVer()},function(e){
    _versionsPolling=false;g('versions-refresh-note').textContent=String(e)})}
function pollVer(){
  each(VER_NAMES,function(n){
    setCell(g('ver-'+n),'checking',n+'…')});
  fetch('/api/protocol-versions',{credentials:'same-origin'})
  .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
  .then(function(d){
    var job=d.check||{};
    if(job.status==='running'){setTimeout(pollVer,2000);return}
    _versionsPolling=false;
    g('versions-refresh-note').textContent=job.status==='error' ? job.message :
      (d.status==='partial' ? 'Не все источники доступны: '+(d.message||'DNS/WAN') :
       (d.stale ? 'Данные устарели; повторите проверку' : 'Версии проверены'));
    if(!d.versions)return;
    var u={},src={},gh=d.github_only||{},any=false;
    if(d.updates)each(d.updates,function(x){
      u[x.name]=x.available;src[x.name]=x.source});
    each(VER_NAMES,function(n){
      /* github_only — справочная версия для протоколов, которые
         обновляются только через opkg. Заполняется, лишь если на
         GitHub появилась сборка под архитектуру роутера. */
      var v=d.versions[n]||'N/A',nv=u[n],
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
        setCell(g('ver-'+n),v==='N/A'?'unavailable':'ok',n+': '+v);
        updBtnShow(n,false);
      }});
    /* «Обновить всё» имеет смысл лишь когда есть что обновлять. */
    var ar=g('upd-all-row');
    if(ar)ar.className=any?'upd-all-row on':'upd-all-row'
  }).catch(function(e){_versionsPolling=false;
    g('versions-refresh-note').textContent='Ошибка: '+e})}

function lkSet(v){g('lk-query').value=v;doLookup()}
function doLookup(){
  var q=g('lk-query').value.trim();
  if(!q)return;
  var sp=g('lk-spin');
  sp.style.display='inline-block';
  var fd=new FormData();fd.append('query',q);
  var cm=document.querySelector('meta[name=csrf-token]');
  if(cm)fd.append('csrf_token',cm.content);
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
  var ta=g('lk-output'),note=g('copy-note');
  function result(ok){note.textContent=ok?'Скопировано в буфер обмена':'Не удалось скопировать автоматически. Выделите текст и скопируйте вручную.'}
  function fallback(){ta.focus();ta.select();ta.setSelectionRange(0,ta.value.length);try{result(document.execCommand('copy'))}catch(e){result(false)}}
  if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(ta.value).then(function(){result(true)},fallback)}else fallback();
}

g('lk-query').addEventListener('keypress',
  function(e){if(e.key==='Enter')doLookup()});

/* UI 6: local-only appearance, keyboard navigation and unsaved input safety. */
function syncThemeLabel(){var light=document.documentElement.dataset.theme==='light';g('theme-label').textContent=light?'Тёмная тема':'Светлая тема';g('theme-toggle').setAttribute('aria-label',light?'Включить тёмную тему':'Включить светлую тему');document.querySelector('meta[name="theme-color"]').content=light?'#f1f4f8':'#10151e'}
function toggleTheme(){var theme=document.documentElement.dataset.theme==='light'?'dark':'light';document.documentElement.dataset.theme=theme;try{localStorage.setItem('keenzoo-theme',theme)}catch(e){}syncThemeLabel()}
syncThemeLabel();
var tabNav=document.querySelector('.tabs');
function navOrientation(){tabNav.setAttribute('aria-orientation',window.matchMedia('(max-width:900px)').matches?'horizontal':'vertical')}
navOrientation();window.addEventListener('resize',navOrientation);
tabNav.addEventListener('keydown',function(e){
  var btns=Array.prototype.slice.call(tabNav.querySelectorAll('[role=tab]')),i=btns.indexOf(document.activeElement);if(i<0)return;
  var horizontal=tabNav.getAttribute('aria-orientation')==='horizontal',next=horizontal?'ArrowRight':'ArrowDown',prev=horizontal?'ArrowLeft':'ArrowUp';
  if(e.key===next)i=(i+1)%btns.length;else if(e.key===prev)i=(i+btns.length-1)%btns.length;else if(e.key==='Home')i=0;else if(e.key==='End')i=btns.length-1;else return;
  e.preventDefault();go(btns[i].id.slice(4),true);btns[i].focus();
});
var draftForms=[],leavingBySubmit=false;
each(document.querySelectorAll('form'),function(form){
  var fields=Array.prototype.slice.call(form.querySelectorAll('textarea:not([readonly]),input[type=text],select'));if(!fields.length)return;
  var initial=fields.map(function(el){return el.value}),note=document.createElement('p');note.className='draft-indicator';note.setAttribute('role','status');note.textContent='Есть несохранённые изменения';form.appendChild(note);
  function changed(){var dirty=fields.some(function(el,i){return el.value!==initial[i]});form.dataset.dirty=dirty?'1':'0';note.classList.toggle('visible',dirty)}
  fields.forEach(function(el){el.addEventListener('input',changed);el.addEventListener('change',changed)});
  draftForms.push(form);
});
window.addEventListener('beforeunload',function(e){if(!leavingBySubmit&&draftForms.some(function(f){return f.dataset.dirty==='1'})){e.preventDefault();e.returnValue=''}});
each(document.querySelectorAll('form'),function(form){form.addEventListener('submit',function(e){
  if(draftForms.some(function(f){return f!==form&&f.dataset.dirty==='1'})&&!confirm('В других формах есть несохранённые изменения. Продолжить и потерять их?')){e.preventDefault();e.stopImmediatePropagation();return}
  leavingBySubmit=true;
},true)});
window.addEventListener('pageshow',function(){leavingBySubmit=false;each(document.querySelectorAll('.btn.loading'),function(b){b.classList.remove('loading');b.disabled=false})});
// No active DNS checks or package lookups on initial page load or tab navigation.
var initialTab=document.querySelector('.tab-btn.active');if(initialTab)go(initialTab.id.slice(4),true);

</script></body></html>'''


ROUTER_PROTOCOL_FILE = os.path.join(UNBLOCK_DIR, '.router_protocol')
ROUTER_PROTOCOLS = {
    'xray': ('vless', 'Xray / VLESS', 'localportvless'),
    'trojan': ('trojan', 'Trojan', 'localporttrojan'),
    'hysteria': ('hysteria', 'Hysteria2', 'localporthysteria'),
}


def get_router_protocol():
    try:
        with open(ROUTER_PROTOCOL_FILE, encoding='ascii') as f:
            value = f.read(32).strip()
    except FileNotFoundError:
        return 'xray'
    if value not in ROUTER_PROTOCOLS:
        raise ValueError('Некорректный .router_protocol; выберите протокол заново')
    return value


def set_router_protocol(value: str) -> None:
    if value not in ROUTER_PROTOCOLS:
        raise ValueError('Допустимы только xray, trojan, hysteria')
    service, _label, port_key = ROUTER_PROTOCOLS[value]
    with shared_update_lock():
        if os.path.exists(os.path.join(UNBLOCK_DIR, '.disabled')):
            raise RuntimeError('Проект отключён; сначала выполните установку')
        if not _read_enabled(service):
            raise RuntimeError('Сначала включите выбранный протокол')
        if not _proc_alive('xray' if value == 'xray' else value) or not _port_ready(
                _config_port(port_key), udp=False):
            raise RuntimeError('Выбранный протокол не слушает TCP-порт')
        existed = os.path.exists(ROUTER_PROTOCOL_FILE)
        old = read_file_text(ROUTER_PROTOCOL_FILE) if existed else ''
        script = config.paths['redirect_script']
        env = os.environ.copy()
        env.update(type='iptable', table='nat', KEENZOO_UPDATE_LOCK_HELD='1',
                   KEENZOO_LOCK_DIR=LOCK_DIR)
        _atomic_write_text(ROUTER_PROTOCOL_FILE, value + '\n')
        try:
            _run_command(['/bin/sh', script], timeout=90, env=env,
                         check=True, label='router TCP apply')
        except Exception:
            # Hook restores its iptables snapshot on error. Reconcile after
            # restoring the setting too (also covers a terminated hook).
            if existed:
                _atomic_write_text(ROUTER_PROTOCOL_FILE, old + '\n')
            else:
                os.unlink(ROUTER_PROTOCOL_FILE)
            rollback = _run_command(['/bin/sh', script], timeout=90, env=env,
                                    label='router TCP rollback')
            if rollback.returncode:
                raise RuntimeError('Не удалось применить И откатить netfilter; проверьте журнал') from None
            raise


@app.route('/router/protocol', methods=['POST'])
def route_router_protocol():
    _check_csrf()
    try:
        set_router_protocol((request.form.get('protocol') or '').strip())
    except ValueError as err:
        return jsonify(ok=False, error=str(err)), 400
    except (RuntimeError, OSError) as err:
        return jsonify(ok=False, error=str(err)), 409
    flash('TCP bot.txt: выбранный протокол применён. Новые соединения используют новый путь.', 'ok')
    return redirect(url_for('index') + '?tab=bt')


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
        router_protocol=(read_file_text(ROUTER_PROTOCOL_FILE).strip()
                         if os.path.exists(ROUTER_PROTOCOL_FILE) else 'xray'),
        router_protocols=ROUTER_PROTOCOLS,
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
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - limit))
            return f.read(limit).decode('utf-8', 'replace')
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


@app.route('/api/dns-probe', methods=['GET', 'POST'])
def api_dns_probe():
    if request.method == 'POST':
        _check_csrf()
        if _lock_is_live(_GS.get('lock_dir', '/tmp/unblock_update.lockdir')):
            return jsonify(ok=False, error='Выполняется применение DNS/списков'), 409
        try:
            started = _start_dns_probe()
        except (OSError, RuntimeError):
            return jsonify(ok=False, error='Не запущена DNS-проверка'), 500
        return jsonify(ok=True, started=started), 202
    data = _read_dns_observation()
    data.pop('config_stamp', None)
    return jsonify(data)


@app.route('/api/dns-refresh-status')
def api_dns_refresh_status():
    return jsonify(_read_refresh_job(DNS_REFRESH_STATUS, DNS_REFRESH_LOCK))


@app.route('/api/dns-status')
def api_dns_status():
    data = check_dns_ports()
    data['refresh'] = _read_refresh_job(DNS_REFRESH_STATUS, DNS_REFRESH_LOCK)
    return jsonify(data)


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


# Background checks have bounded runtime and a visible terminal result. Their
# shell children still own the normal update mutex; GET never starts work.
DNS_REFRESH_LOCK = '/tmp/keenzoo_dns_refresh.lockdir'
DNS_REFRESH_STATUS = '/tmp/keenzoo_dns_refresh.json'
VERSIONS_REFRESH_STATUS = '/tmp/keenzoo_versions_refresh.json'


def _read_refresh_job(path, lock):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError('invalid status')
        if data.get('status') == 'running' and not _lock_is_live(lock):
            data.update(status='error', message='Проверка прервана; запустите повторно')
        return data
    except (OSError, ValueError):
        return {'status': 'idle', 'ts': 0, 'message': ''}


def _start_refresh_job(script, lock, status_file, env=None, timeout=600):
    if not os.path.isfile(script) or not os.access(script, os.X_OK):
        raise FileNotFoundError(script)
    if not _acquire_launcher_lock(lock):
        return False

    def save(status, message='', rc=0):
        _atomic_write_text(status_file, json.dumps({
            'status': status, 'message': message, 'rc': rc,
            'ts': int(time.time())}, ensure_ascii=False))

    def worker():
        try:
            result = _run_command([script], timeout=timeout, env=env,
                                  label='background check')
            messages = {75: 'Другая операция заняла блокировку; повторите позже',
                        124: 'Превышено время проверки; проверьте DNS и WAN'}
            message = messages.get(result.returncode,
                                   'Проверка завершилась ошибкой; см. журнал DNS/обновлений')
            save('done' if result.returncode == 0 else 'error',
                 '' if result.returncode == 0 else message, result.returncode)
        except Exception:
            logging.exception('background check failed')
            try:
                save('error', 'Ошибка фоновой проверки', 1)
            except OSError:
                pass
        finally:
            _release_launcher_lock(lock)

    try:
        save('running')
        threading.Thread(target=worker, daemon=True, name='keenzoo-check').start()
    except Exception:
        _release_launcher_lock(lock)
        raise
    return True


@app.route('/api/dns-refresh', methods=['POST'])
def api_dns_refresh():
    _check_csrf()
    env = os.environ.copy()
    env['DNS_HEALTH_ONLY'] = '1'
    # Never inherit a parent's assertion that it owns the shell mutex.
    env.pop('KEENZOO_UPDATE_LOCK_HELD', None)
    try:
        started = _start_refresh_job(
            config.paths.get('unblock_dnsmasq', '/opt/bin/unblock_dnsmasq.sh'),
            DNS_REFRESH_LOCK, DNS_REFRESH_STATUS, env=env)
    except (OSError, RuntimeError):
        return jsonify(ok=False, error='Не удалось запустить DNS-проверку'), 500
    return jsonify(ok=True, started=started), 202


@app.route('/api/protocol-versions/refresh', methods=['POST'])
def api_versions_refresh():
    _check_csrf()
    try:
        started = _start_updates_check_async(config.paths.get(
            'check_updates', '/opt/bin/check_updates.sh'))
    except (OSError, RuntimeError):
        return jsonify(ok=False, error='Не удалось запустить проверку версий'), 500
    return jsonify(ok=True, started=started), 202


def _start_updates_check_async(script):
    return _start_refresh_job(script, UPDATES_CHECK_LOCK,
                              VERSIONS_REFRESH_STATUS, timeout=240)


@app.route('/api/protocol-versions')
def api_protocol_versions():
    data = {'ts': 0, 'has_updates': False, 'versions': {}, 'updates': []}
    try:
        with open(config.paths.get('updates_status', '/tmp/updates_status.json')) as f:
            cached = json.load(f)
        if isinstance(cached, dict):
            data.update(cached)
        age = time.time() - float(data.get('ts', 0))
        data['stale'] = not 0 <= age < 3600
    except (OSError, ValueError, TypeError):
        data['stale'] = True
    data['check'] = _read_refresh_job(VERSIONS_REFRESH_STATUS, UPDATES_CHECK_LOCK)
    return jsonify(data)


@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    # Маршрут делает внешние HTTP-запросы (CIDR-пресеты), поэтому,
    # как и все изменяющие POST, обязан проверять CSRF-токен.
    _check_csrf()
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
            'to', 'hy', 'bt', 'lk', 'dn', 'up'):
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

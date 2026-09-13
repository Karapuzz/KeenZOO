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
from urllib.parse import urlparse

from flask import (
    Flask, render_template_string,
    request, flash, redirect,
    url_for, abort, session, jsonify, Response,
)

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
    """
    Постоянный ключ подписи сессии. Хранится в файле, иначе при каждом
    перезапуске панели сессии (а с ними и CSRF-токены) обнулялись бы.
    Ошибки файловой системы не должны валить панель на старте: в худшем
    случае откатываемся на эфемерный ключ и пишем об этом в лог.
    """
    try:
        if os.path.exists(SECRET_FILE):
            with open(SECRET_FILE, 'r') as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key

        os.makedirs(
            os.path.dirname(SECRET_FILE) or '.',
            exist_ok=True)

        key = hashlib.sha256(os.urandom(64)).hexdigest()
        # Права выставляются в момент создания, до записи содержимого.
        fd = os.open(
            SECRET_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key)
        return key
    except OSError as err:
        sys.stderr.write(
            f"[!] Не удалось сохранить {SECRET_FILE}: {err}. "
            "Сессии будут сбрасываться при перезапуске панели.\n")
        return hashlib.sha256(os.urandom(64)).hexdigest()


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

DNS_PORTS_DOT = list(
    getattr(config, 'dnsovertls_ports',
            [40500, 40501, 40502, 40503]))
DNS_PORTS_DOH = list(
    getattr(config, 'dnsoverhttps_ports',
            [40508, 40509, 40510, 40511]))

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
    """Вызов iptables с ограничением по времени.

    -w заставляет iptables ждать освобождения xtables-блокировки:
    без ограничения параллельный вызов из ndm-хука мог подвесить
    поток панели навсегда. Истёкшее ожидание возвращается как обычная
    неудача (returncode 1), иначе TimeoutExpired обрушил бы запуск
    панели, которая вызывает setup_firewall при старте.
    """
    try:
        return subprocess.run(
            [IPTABLES, '-w'] + list(args),
            capture_output=True, text=True,
            timeout=15)
    except subprocess.TimeoutExpired:
        log_error(
            '[!] iptables не ответил за 15 с: '
            + ' '.join(str(a) for a in args))
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout='', stderr='timeout')


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
        subprocess.run(
            [sc, action],
            capture_output=True, text=True, timeout=30)
    except (subprocess.SubprocessError, OSError) as e:
        raise RuntimeError(f"{sn}: {e}")

    _reapply_netfilter()


def _reapply_netfilter():
    """
    Переприменяет правила перехвата. Хук сам пропускает протоколы,
    у которых ENABLED=no, и снимает их прежние правила.
    """
    hook = '/opt/etc/ndm/netfilter.d/100-redirect.sh'
    if not os.path.exists(hook):
        return
    for table in ('nat', 'mangle'):
        env = dict(os.environ,
                   type='iptable', table=table)
        try:
            subprocess.run(
                [hook], env=env, capture_output=True,
                text=True, timeout=60)
        except (subprocess.SubprocessError, OSError):
            pass


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
        r = subprocess.run(
            [sc, 'restart'],
            capture_output=True,
            text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f'{sn}: перезапуск не завершился за 30 с')
    if r.returncode != 0:
        err = (r.stderr.strip()
               or r.stdout.strip())
        raise RuntimeError(f"{sn}: {err}")


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


def _build_wrapper(sp, only_sets=''):
    # only_sets — частичное обновление: обрабатывается лишь указанный
    # набор ipset. Правка одной записи в списке раньше запускала полный
    # цикл по всем доменам всех протоколов (сотни DNS-запросов).
    lines = [
        '#!/bin/sh',
        'export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin',]
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
        if age < UNBLOCK_TIMEOUT:
            raise RuntimeError(
                f"Уже ({int(age)}с).")
        _write_update_status('idle', 'stale')
        try:
            pf = os.path.join(
                LOCK_DIR, 'pid')
            if os.path.exists(pf):
                with open(pf, 'r') as f:
                    op = int(
                        f.read().strip())
                try:
                    os.kill(op, 0)
                except OSError:
                    import shutil
                    shutil.rmtree(
                        LOCK_DIR,
                        ignore_errors=True)
        except Exception:
            pass
    _write_update_status(
        'running', 'starting')
    with open(WRAPPER_SCRIPT, 'w') as f:
        f.write(_build_wrapper(sc, only_sets))
    os.chmod(WRAPPER_SCRIPT, 0o755)
    subprocess.Popen(
        ['/bin/sh', WRAPPER_SCRIPT],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)


def _test_dns_port(port):
    try:
        r = subprocess.run(
            ['dig', '+short',
             '+timeout=2', '+tries=1',
             'google.com', '@localhost',
             '-p', str(port)],
            capture_output=True,
            text=True, timeout=5)
        return bool(re.search(
            r'\d+\.\d+\.\d+\.\d+',
            r.stdout))
    except Exception:
        return False


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
                if inside and line:
                    parts = line.split()
                    if len(parts) >= 2:
                        out.append({
                            'ip': parts[0],
                            'host': parts[1]})
    except OSError:
        pass
    return out


def check_dns_ports():
    res = {'dot': {}, 'doh': {}}
    for p in DNS_PORTS_DOT:
        res['dot'][str(p)] = (
            _test_dns_port(p))
    for p in DNS_PORTS_DOH:
        res['doh'][str(p)] = (
            _test_dns_port(p))
    res['pinned'] = read_pinned_hosts()
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
                r = subprocess.run(
                    ['curl', '-s',
                     '--max-time', '10',
                     cidr_url],
                    capture_output=True,
                    text=True, timeout=15)
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
                r = subprocess.run(
                    ['dig', '+short',
                     domain, '@localhost'],
                    capture_output=True,
                    text=True, timeout=10)
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
            r = subprocess.run(
                ['curl', '-s',
                 '--max-time', '15',
                 'https://stat.ripe.net'
                 '/data/announced-prefixes'
                 '/data.json'
                 f'?resource={asn}'],
                capture_output=True,
                text=True, timeout=20)
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
            r = subprocess.run(
                ['dig', '+short', '--', q,
                 '@localhost'],
                capture_output=True,
                text=True, timeout=10)
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
            r = subprocess.run(
                ['dig', '+short', 'CNAME',
                 '--', q, '@localhost'],
                capture_output=True,
                text=True, timeout=10)
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
.dns-port.ok{color:var(--green);
  border-color:rgba(61,220,151,.4)}
.dns-port.fail{color:var(--red);
  border-color:rgba(255,107,122,.4)}
.dns-port.checking{color:var(--muted)}
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
    <div class="dns-label">DoT</div>
    {% for p in [40500,40501,40502,40503] %}
    <div class="dns-port checking"
      id="dp-{{ p }}">{{ p }}</div>
    {% endfor %}
    <div class="dns-label">DoH</div>
    {% for p in [40508,40509,40510,40511] %}
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
   устранена. Проверка выполняется в unblock_dnsmasq.sh (крон, подъём
   WAN, смена ключа), панель лишь отображает её результат. */
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

var DNS_PORTS=[40500,40501,40502,40503,
  40508,40509,40510,40511];
var _dO=false;
function toggleDns(){
  var el=g('dns-grid');_dO=!_dO;
  el.className=_dO?'dns-grid open':'dns-grid';
  if(_dO)fetchDns()}
function fetchDns(){
  each(DNS_PORTS,function(p){
    setCell(g('dp-'+p),'checking',p+'…')});
  jget('/api/dns-status',function(d){
    each(['dot','doh'],function(t){
      if(!d[t])return;
      each(Object.keys(d[t]),function(p){
        var ok=d[t][p];
        setCell(g('dp-'+p),ok?'ok':'fail',
          p+(ok?' \u2713':' \u2717'))})});
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
        if age > PROTO_UPD_TIMEOUT:
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
    if action not in ('xray', 'hysteria',
                      'opkg', 'all'):
        raise ValueError('action')

    st = _read_proto_update()
    if st.get('status') == 'running':
        age = int(time.time()
                  - st.get('ts', 0))
        raise RuntimeError(
            f'Обновление уже идёт ({age}с)')

    sc = config.paths.get(
        'update_protocols',
        '/opt/bin/update_protocols.sh')
    if not os.path.exists(sc):
        raise FileNotFoundError(sc)

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

    subprocess.Popen(
        ['/bin/sh', PROTO_UPD_WRAPPER],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)


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
            try:
                subprocess.run(
                    [cs], timeout=60)
            except Exception:
                pass
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
    setup_firewall(LISTEN_PORT)

    # Слушаем на всех интерфейсах: у роутера несколько внутренних адресов
    # (основная сеть, гостевая, отдельный бридж для 5 ГГц, VPN-сервер
    # прошивки). При host=LAN_IP панель отвечала только по 192.168.1.1,
    # и Wi-Fi-клиенты из другой подсети получали отказ соединения.
    # Доступ извне при этом закрыт двумя рубежами: правило DROP в INPUT
    # (setup_firewall) и проверка подсети в security_checks().
    print(
        f"\n  http://{LAN_IP}"
        f":{LISTEN_PORT}\n")
    app.run(
        host='0.0.0.0',
        port=LISTEN_PORT,
        debug=False,
        threaded=True,
        use_reloader=False)

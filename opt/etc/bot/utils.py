# -*- coding: utf-8 -*-
import os
import signal
import time
import subprocess
import json
import re
import tarfile
import requests
import urllib3
import gc
import tempfile
import shutil
from urllib.parse import (
    urlparse, parse_qs, unquote)
import base64
import bot_config as config


def signal_handler(sig, frame):
    log_error(
        f"Бот остановлен сигналом "
        f"{signal.Signals(sig).name}")
    raise SystemExit


# ---------------------------------------------------------------------------
# Ротация логов. Пороги настраиваются через опциональные атрибуты
# bot_config (LOG_MAX_SIZE_BYTES / LOG_KEEP_LINES) — если их нет,
# используются прежние значения по умолчанию (полная совместимость).
# Без ротации лог-файлы на Entware (часто ограниченный объём флеш/USB)
# могли бы расти неограниченно и занять всё свободное место.
# ---------------------------------------------------------------------------

_LOG_MAX_SIZE_BYTES = getattr(config, 'LOG_MAX_SIZE_BYTES', 524288)
_LOG_KEEP_LINES = getattr(config, 'LOG_KEEP_LINES', 50)


def clean_log(log_file, max_size=None, keep_lines=None):
    """
    Ограничивает размер лог-файла: при превышении max_size байт
    оставляет только последние keep_lines строк.
    """
    max_size = (
        _LOG_MAX_SIZE_BYTES if max_size is None else max_size)
    keep_lines = (
        _LOG_KEEP_LINES if keep_lines is None else keep_lines)

    if not os.path.exists(log_file):
        open(log_file, 'a').close()
        return
    try:
        if os.path.getsize(log_file) > max_size:
            with open(log_file, 'r', encoding='utf-8',
                      errors='replace') as f:
                lines = f.readlines()
            with open(log_file, 'w', encoding='utf-8') as f:
                f.writelines(lines[-keep_lines:])
    except OSError:
        pass


def log_error(message):
    log_file = config.paths["error_log"]
    try:
        clean_log(log_file)
        with open(log_file, "a",
                  encoding='utf-8') as fl:
            fl.write(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
                f" - {message}\n")
    except Exception:
        pass


def download_script():
    subprocess.run(
        ["curl", "-s", "-o",
         config.paths["script_sh"],
         f"{config.bot_url}/script.sh"])
    os.chmod(
        config.paths["script_sh"], 0o0755)


def load_bypass_list(filepath):
    if not os.path.exists(filepath):
        return set()
    result = set()
    with open(filepath, 'r',
              encoding='utf-8') as f:
        for line in f:
            line = line.split('#')[0].strip()
            if line:
                result.add(line)
    return result


def save_bypass_list(filepath, sites):
    try:
        with open(filepath, 'w',
                  encoding='utf-8') as f:
            f.write('\n'.join(sorted(sites)))
    except Exception as e:
        log_error(
            f"Ошибка сохранения: {str(e)}")
        raise


def check_restart(bot):
    chat_id_path = config.paths[
        "chat_id_path"]
    if os.path.exists(chat_id_path):
        with open(chat_id_path, 'r') as f:
            chat_id = int(f.read().strip())
        try:
            bot.send_message(
                chat_id,
                '✅ Бот перезапущен')
        except Exception as e:
            log_error(
                f"Перезапуск: {str(e)}")
        os.remove(chat_id_path)


# ---------------------------------------------------------------------------
# Preflight-проверки бинарниками (best-effort: если бинарник не найден,
# проверка пропускается с записью в лог, а не блокирует запись конфига —
# это важно, чтобы не сломать деплой на роутерах, где xray/tor ещё не
# установлены на момент первой генерации конфига).
# ---------------------------------------------------------------------------

def _find_binary(binary_name, fallback_paths):
    """Ищет бинарник через PATH, затем по типовым путям Entware."""
    found = shutil.which(binary_name)
    if found:
        return found
    for path in fallback_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


def _preflight_xray(tmp_path):
    """
    Проверка конфига через xray -test.

    Формат передаётся ЯВНО через '-format json', а не через
    автоопределение по расширению файла (default 'auto' у Xray
    определяет формат по расширению, а временный файл создаётся
    tempfile.mkstemp со случайным суффиксом и может не совпадать
    с реальным расширением — при опоре на автоопределение это
    давало бы false negative на абсолютно корректных конфигах).
    Поддержаны оба синтаксиса CLI: старый 'xray -test' и новый
    'xray run -test'.
    """
    binary = _find_binary(
        'xray', ['/opt/sbin/xray', '/opt/bin/xray'])
    if not binary:
        log_error(
            "Preflight: xray не найден, проверка конфига пропущена")
        return

    last_err = ''
    for cmd in (
            [binary, 'run', '-test',
             '-format', 'json', '-config', tmp_path],
            [binary, '-test',
             '-format', 'json', '-config', tmp_path]):
        try:
            res = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=15)
        except subprocess.TimeoutExpired:
            last_err = 'timeout при проверке конфига'
            continue
        if res.returncode == 0:
            return
        last_err = (res.stderr or res.stdout or '').strip()

    raise ValueError(f"Xray validation failed: {last_err}")


def _preflight_tor(tmp_path):
    """Проверка torrc через 'tor --verify-config -f <файл>'."""
    binary = _find_binary(
        'tor', ['/opt/sbin/tor', '/opt/bin/tor'])
    if not binary:
        log_error(
            "Preflight: tor не найден, проверка конфига пропущена")
        return

    try:
        res = subprocess.run(
            [binary, '--verify-config', '-f', tmp_path],
            capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise ValueError("Tor validation timeout")

    if res.returncode != 0:
        err = (res.stderr or res.stdout or '').strip()
        raise ValueError(f"Tor validation failed: {err}")


def _cleanup_stale_tmp_files(directory, basename, max_age_seconds=3600):
    """
    Удаляет "осиротевшие" временные файлы конфигурации, оставшиеся
    от прерванных (например, из-за отключения питания роутера)
    предыдущих запусков write_config. Без этой очистки такие файлы
    накапливались бы бесконечно и могли занять всё место на
    накопителе Entware. Возраст 1 час гарантированно превышает время
    любой нормальной записи (доли секунды), поэтому риска удалить
    "живой" временный файл конкурентного процесса нет.
    """
    pattern_prefix = f".{basename}.tmp_"
    try:
        now = time.time()
        for name in os.listdir(directory):
            if not name.startswith(pattern_prefix):
                continue
            full = os.path.join(directory, name)
            try:
                if now - os.path.getmtime(full) > max_age_seconds:
                    os.remove(full)
            except OSError:
                pass
    except OSError:
        pass


class ConfigWriter:
    @staticmethod
    def write_config(file_path,
                     config_data,
                     format='json'):
        """
        Атомарная запись конфигурации:
        0) удаляются "осиротевшие" временные файлы от прошлых
           прерванных записей (защита от накопления мусора на диске);
        1) содержимое пишется во временный файл в той же директории
           (нужно для атомарности os.replace на той же ФС), причём
           временный файл получает то же расширение, что и целевой
           файл (доп. защита на случай, если бинарник определяет
           формат по расширению);
        2) выполняется best-effort preflight-проверка (xray -test для
           vless_config, tor --verify-config для tor_config);
        3) только при успехе временный файл заменяет боевой путь.

        Права временного файла наследуются от уже существующего
        конфига (если есть), иначе ставятся в 0600 — конфиги содержат
        пароли/UUID/reality-ключи и не должны быть читаемы всем.
        Установка прав выполняется ПОСЛЕ передачи fd в os.fdopen()
        (через os.chmod по пути, а не os.fchmod по дескриптору) и
        обёрнута в отдельный try/except: на файловых системах без
        полноценной поддержки POSIX-прав (exFAT/NTFS — частый случай
        для внешних USB-накопителей Entware) chmod может завершиться
        ошибкой — это не должно ни прерывать запись конфига, ни
        приводить к утечке файлового дескриптора.

        Все ошибки (включая невалидный JSON на входе, ошибки создания
        каталога и preflight) логируются через log_error перед
        повторным raise.
        """
        directory = os.path.dirname(file_path) or '.'
        tmp_path = None

        try:
            os.makedirs(directory, exist_ok=True)
            _cleanup_stale_tmp_files(
                directory, os.path.basename(file_path))

            if format == 'json':
                content = json.dumps(
                    json.loads(config_data),
                    ensure_ascii=False, indent=2)
            else:
                content = config_data

            _, ext = os.path.splitext(file_path)
            fd, tmp_path = tempfile.mkstemp(
                dir=directory,
                prefix=f".{os.path.basename(file_path)}.tmp_",
                suffix=ext)

            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                try:
                    if os.path.exists(file_path):
                        mode = os.stat(file_path).st_mode & 0o777
                    else:
                        mode = 0o600
                    os.chmod(tmp_path, mode)
                except OSError as chmod_err:
                    log_error(
                        f"Preflight: chmod пропущен для "
                        f"{tmp_path}: {chmod_err}")

                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            real_path = os.path.realpath(file_path)
            if real_path == os.path.realpath(
                    config.paths.get('vless_config', '')):
                _preflight_xray(tmp_path)
            elif real_path == os.path.realpath(
                    config.paths.get('tor_config', '')):
                _preflight_tor(tmp_path)

            os.replace(tmp_path, file_path)

        except Exception as e:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            log_error(
                f"Failed to write config to {file_path}: {e}")
            raise


def notify_on_error():
    def decorator(func):
        def wrapper(key, bot=None,
                    chat_id=None,
                    *args, **kwargs):
            try:
                return func(
                    key, bot, chat_id,
                    *args, **kwargs)
            except Exception as e:
                if bot and chat_id:
                    if func.__name__ == (
                            "tor_config"):
                        bot.send_message(
                            chat_id,
                            f"❌ Tor: "
                            f"{str(e)}")
                    else:
                        protocol = (
                            func.__name__
                            .split('_')[1]
                            .capitalize())
                        bot.send_message(
                            chat_id,
                            f"❌ "
                            f"{protocol}: "
                            f"{str(e)}")
                raise
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# IPv4-only проверка. На роутере Keenetic IPv6 отключён на уровне системы,
# а dnsmasq/ipset в проекте работают только в режиме family inet (IPv4).
# Явный IPv6-адрес сервера в ссылке привёл бы к конфигу, который либо не
# подключится (нет IPv6-стека), либо не попадёт в анблок-списки — поэтому
# такой адрес отклоняется на этапе парсинга с понятной ошибкой.
# ---------------------------------------------------------------------------

def _is_ipv6_literal(host):
    """
    Надёжный маркер IPv6 в этом контексте — наличие ':' в host,
    т.к. ни домены, ни IPv4-адреса символ ':' не содержат (host
    на этом этапе уже отделён от порта вызывающим кодом).
    """
    return bool(host) and ':' in host


def _reject_ipv6_host(host, context="адрес сервера"):
    if _is_ipv6_literal(host):
        raise ValueError(
            f"IPv6 не поддерживается (IPv6 отключён на "
            f"роутере): {context}")


@notify_on_error()
def parse_vless_key(key, bot=None,
                    chat_id=None):
    if not key.startswith('vless://'):
        raise ValueError("vless://")
    url = key[6:]
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if (not parsed_url.hostname
            or not parsed_url.username):
        raise ValueError("Нет адреса/ID")
    _reject_ipv6_host(parsed_url.hostname)
    port = parsed_url.port or 443
    if not (1 <= port <= 65535):
        raise ValueError(f"Порт: {port}")
    transport = params.get(
        'type', ['tcp'])[0]
    raw_path = params.get(
        'path', ['/'])[0]
    raw_host = params.get(
        'host', [''])[0]
    return {
        'address': parsed_url.hostname,
        'port': port,
        'id': parsed_url.username,
        'encryption': params.get(
            'encryption', ['none'])[0],
        'flow': params.get(
            'flow', [''])[0],
        'security': params.get(
            'security', [''])[0],
        'pbk': params.get(
            'pbk', [''])[0],
        'fp': params.get(
            'fp', [''])[0],
        'sni': params.get(
            'sni', [''])[0],
        'sid': params.get(
            'sid', [''])[0],
        'spx': params.get(
            'spx', ['/'])[0],
        'transport': transport,
        'serviceName': params.get(
            'serviceName', [''])[0],
        'ws_path': raw_path,
        'ws_host': raw_host,
        'xhttp_mode': params.get(
            'mode', ['auto'])[0],
        'xhttp_path': raw_path,
        'xhttp_host': raw_host,
    }


@notify_on_error()
def parse_trojan_key(key, bot=None,
                     chat_id=None):
    if not key.startswith('trojan://'):
        raise ValueError("trojan://")
    parsed_url = urlparse(key)
    params = parse_qs(
        parsed_url.query,
        keep_blank_values=True)
    pw = (unquote(parsed_url.username)
          if parsed_url.username else "")
    if not pw:
        raise ValueError("Нет пароля")
    port = parsed_url.port
    if port is None:
        raise ValueError("Нет порта")
    if not (1 <= port <= 65535):
        raise ValueError(f"Порт: {port}")
    netloc = parsed_url.netloc
    if '@' in netloc:
        hp = netloc.rsplit('@', 1)[-1]
    else:
        hp = netloc
    if hp.startswith('['):
        be = hp.find(']')
        if be == -1:
            raise ValueError("IPv6")
        host = hp[1:be]
    else:
        host = hp.rsplit(':', 1)[0]
    if not host:
        raise ValueError("Нет адреса")
    _reject_ipv6_host(host)
    sni_raw = params.get('sni', [''])[0]
    sni = (unquote(sni_raw)
           if sni_raw else '')
    path_raw = params.get(
        'path', ['/'])[0]
    path = (unquote(path_raw)
            if path_raw else '/')
    result = {
        'pw': pw, 'host': host,
        'port': port, 'sni': sni,
        'fp': params.get('fp', [''])[0],
        'alpn': params.get(
            'alpn', [''])[0],
        'type': params.get(
            'type', ['tcp'])[0],
        'security': params.get(
            'security', ['tls'])[0],
        'path': path,
        'host_header': params.get(
            'host', [''])[0],
        'allowInsecure': params.get(
            'allowInsecure', ['0'])[0],
        'serviceName': params.get(
            'serviceName', [''])[0],
    }
    if not result['sni']:
        result['sni'] = result['host']
    result['ws_enabled'] = (
        'true' if result['type'] == 'ws'
        else 'false')
    result['verify'] = (
        'false'
        if result['allowInsecure'] == '1'
        else 'true')
    return result


@notify_on_error()
def parse_shadowsocks_key(key, bot=None,
                          chat_id=None):
    if not key.startswith('ss://'):
        raise ValueError("ss://")

    def dec_b64(v):
        v = unquote(v.strip())
        v += '=' * ((4 - len(v) % 4) % 4)
        return base64.urlsafe_b64decode(
            v.encode('utf-8')).decode('utf-8')

    raw = key[5:].split('#', 1)[0]

    if '@' in raw:
        userinfo, server_part = raw.rsplit('@', 1)
        decoded = dec_b64(userinfo)
        if ':' not in decoded:
            raise ValueError("method:password")
        method, password = decoded.split(':', 1)
    else:
        decoded = dec_b64(raw)
        if '@' not in decoded:
            raise ValueError("server")
        userinfo, server_part = decoded.rsplit('@', 1)
        if ':' not in userinfo:
            raise ValueError("method:password")
        method, password = userinfo.split(':', 1)

    server_part = server_part.split('?', 1)[0].split('/', 1)[0]
    if server_part.startswith('['):
        end = server_part.find(']')
        if end < 0:
            raise ValueError("IPv6")
        server = server_part[1:end]
        port = server_part[end + 2:]
    else:
        if ':' not in server_part:
            raise ValueError("Порт")
        server, port = server_part.rsplit(':', 1)

    _reject_ipv6_host(server)

    if (not server or not port.isdigit()
            or not method or not password):
        raise ValueError("Некорректный")
    pn = int(port)
    if not (1 <= pn <= 65535):
        raise ValueError(f"Порт: {port}")
    return {
        'server': server, 'port': pn,
        'password': password,
        'method': method,
    }

@notify_on_error()
def parse_hysteria_key(key, bot=None,
                       chat_id=None):
    kc = key.split('#')[0].strip()
    if kc.startswith('hy2://'):
        up = kc[6:]
    elif kc.startswith('hysteria2://'):
        up = kc[12:]
    else:
        raise ValueError("hy2://")
    pu = urlparse('http://' + up)
    params = parse_qs(pu.query)
    auth = (unquote(pu.username)
            if pu.username else "")
    if not auth:
        raise ValueError("Нет пароля")
    server = pu.hostname
    if not server:
        raise ValueError("Нет адреса")
    _reject_ipv6_host(server)
    port = pu.port
    if not port:
        raise ValueError("Нет порта")
    if not (1 <= port <= 65535):
        raise ValueError(f"Порт: {port}")
    sni = params.get('sni', [''])[0]
    if not sni:
        sni = server
    ins = params.get('insecure', ['0'])[0]
    insecure = (
        'true' if str(ins).lower() in ('1', 'true', 'yes') else 'false')
    alpn_raw = params.get('alpn', [''])[0]
    if alpn_raw:
        ap = [p.strip()
              for p in alpn_raw.split(',')
              if p.strip()]
        alpn = ', '.join(
            f'"{p}"' for p in ap)
    else:
        alpn = ''
    ot = params.get('obfs', [''])[0]
    op = params.get('obfs-password', [''])[0]
    return {
        'server': server, 'port': port,
        'auth': auth, 'sni': sni,
        'insecure': insecure, 'alpn': alpn,
        'obfs_type': ot,
        'obfs_password': op,
    }


def _cleanup_empty_fields(obj):
    rif = {'flow'}
    ts = {
        'grpcSettings', 'wsSettings',
        'tcpSettings', 'httpSettings',
        'quicSettings', 'xhttpSettings',
    }
    ss = {'realitySettings', 'tlsSettings'}
    if isinstance(obj, dict):
        cn = obj.get('network', '')
        cs = obj.get('security', '')
        kr = []
        for k, v in obj.items():
            if k in rif and v == '':
                kr.append(k)
            elif (k in ts
                  and isinstance(v, dict)):
                exp = cn + 'Settings'
                if k != exp:
                    kr.append(k)
                elif not v:
                    kr.append(k)
            elif (k in ss
                  and isinstance(v, dict)):
                exs = cs + 'Settings'
                if k != exs:
                    kr.append(k)
                elif not v:
                    kr.append(k)
            elif isinstance(v, (dict, list)):
                _cleanup_empty_fields(v)
        obfs = obj.get('obfs')
        if (isinstance(obfs, dict)
                and not obfs.get('type')):
            kr.append('obfs')
        alpn = obj.get('alpn')
        if isinstance(alpn, list):
            if (not alpn
                    or (len(alpn) == 1
                        and alpn[0] == '')):
                kr.append('alpn')
        for k in kr:
            if k in obj:
                del obj[k]
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _cleanup_empty_fields(item)



_JSON_RAW_KEYS = {
    'insecure', 'alpn', 'ws_enabled',
    'verify', 'localportvless',
    'localporttrojan', 'localportsh',
    'localporthysteria',
}


def _tpl_value(key, value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if key in _JSON_RAW_KEYS:
        return str(value)
    return json.dumps(
        str(value), ensure_ascii=False)[1:-1]


def _ensure_xray_tproxy(parsed):
    if not isinstance(parsed, dict):
        return parsed

    port = int(config.localportvless)
    inbounds = parsed.setdefault('inbounds', [])

    # Удалить старый UDP TPROXY-дубль.
    inbounds[:] = [
        ib for ib in inbounds
        if ib.get('tag') != 'vless-udp-tproxy'
    ]

    base = None
    for ib in inbounds:
        if (ib.get('protocol') == 'dokodemo-door'
                and int(ib.get('port', 0)) == port):
            base = ib
            break

    if base is None:
        base = {
            'port': port,
            # IPv6 отключён на роутере Keenetic — слушаем только IPv4,
            # чтобы избежать ошибки bind при попытке открыть AF_INET6.
            'listen': '0.0.0.0',
            'protocol': 'dokodemo-door',
            'settings': {
                'network': 'tcp',
                'followRedirect': True,
            },
            'sniffing': {
                'enabled': True,
                'destOverride': ['http', 'tls'],
            },
        }
        inbounds.insert(0, base)

    base['port'] = port
    base.setdefault('listen', '0.0.0.0')
    base['protocol'] = 'dokodemo-door'
    base.setdefault('settings', {})
    base['settings']['network'] = 'tcp'
    base['settings']['followRedirect'] = True
    base.setdefault('streamSettings', {})
    base['streamSettings'].setdefault('sockopt', {})
    base['streamSettings']['sockopt']['tproxy'] = 'redirect'

    udp = json.loads(json.dumps(base))
    udp['tag'] = 'vless-udp-tproxy'
    udp['settings']['network'] = 'udp'
    udp.setdefault('streamSettings', {})
    udp['streamSettings'].setdefault('sockopt', {})
    udp['streamSettings']['sockopt']['tproxy'] = 'tproxy'
    inbounds.append(udp)

    return parsed


def _ensure_hysteria_tproxy(parsed):
    if not isinstance(parsed, dict):
        return parsed
    port = int(config.localporthysteria)
    parsed.setdefault('tcpRedirect', {})['listen'] = (
        f'0.0.0.0:{port}')
    parsed.setdefault('udpTProxy', {})['listen'] = (
        f'0.0.0.0:{port}')
    return parsed


def generate_config(key, template_file,
                    config_path,
                    replacements,
                    parse_func,
                    bot=None, chat_id=None):
    params = parse_func(key, bot, chat_id)

    with open(
            os.path.join(
                config.paths["templates_dir"],
                template_file),
            'r', encoding='utf-8') as f:
        template = f.read()

    cd = template

    for rk, rv in replacements.items():
        cd = cd.replace(
            "{{" + rk + "}}",
            _tpl_value(rk, rv))

    for pk, pv in params.items():
        cd = cd.replace(
            "{{" + pk + "}}",
            _tpl_value(pk, pv))

    if template_file.endswith('.json'):
        parsed = json.loads(cd)

        if template_file == 'vless_template.json':
            parsed = _ensure_xray_tproxy(parsed)
        elif template_file == 'hysteria_template.json':
            parsed = _ensure_hysteria_tproxy(parsed)

        _cleanup_empty_fields(parsed)
        cd = json.dumps(
            parsed,
            ensure_ascii=False,
            indent=2)

    ConfigWriter.write_config(
        config_path, cd)

def vless_config(key, bot=None,
                 chat_id=None):
    generate_config(
        key=key,
        template_file="vless_template.json",
        config_path=config.paths[
            "vless_config"],
        replacements={
            "localportvless":
                config.localportvless},
        parse_func=parse_vless_key,
        bot=bot, chat_id=chat_id)


def trojan_config(key, bot=None,
                  chat_id=None):
    generate_config(
        key=key,
        template_file=(
            "trojan_template.json"),
        config_path=config.paths[
            "trojan_config"],
        replacements={
            "localporttrojan":
                config.localporttrojan},
        parse_func=parse_trojan_key,
        bot=bot, chat_id=chat_id)


def shadowsocks_config(key, bot=None,
                       chat_id=None):
    generate_config(
        key=key,
        template_file=(
            "shadowsocks_template.json"),
        config_path=config.paths[
            "shadowsocks_config"],
        replacements={
            "localportsh":
                config.localportsh},
        parse_func=parse_shadowsocks_key,
        bot=bot, chat_id=chat_id)


def hysteria_config(key, bot=None,
                    chat_id=None):
    os.makedirs(
        config.paths.get(
            "hysteria_dir",
            "/opt/etc/hysteria"),
        exist_ok=True)
    generate_config(
        key=key,
        template_file=(
            "hysteria_template.json"),
        config_path=config.paths[
            "hysteria_config"],
        replacements={
            "localporthysteria":
                config.localporthysteria},
        parse_func=parse_hysteria_key,
        bot=bot, chat_id=chat_id)
def _convert_singbox_vless(sb):
    """sing-box vless → xray."""
    server = sb.get('server', '')
    port = sb.get('server_port', 443)
    uuid = sb.get('uuid', '')
    flow = sb.get('flow', '')
    if not server:
        raise ValueError("Нет server")
    if not uuid:
        raise ValueError("Нет uuid")
    tls = sb.get('tls', {})
    sni = tls.get('server_name', server)
    reality = tls.get('reality', {})
    utls = tls.get('utls', {})
    security = 'none'
    if reality.get('enabled'):
        security = 'reality'
    elif tls.get('enabled'):
        security = 'tls'
    fp = utls.get(
        'fingerprint',
        tls.get('fingerprint', 'chrome'))
    transport = sb.get('transport', {})
    network = transport.get('type', 'tcp')
    stream = {
        "network": network,
        "security": security,
    }
    if security == 'reality':
        stream["realitySettings"] = {
            "publicKey": reality.get(
                'public_key', ''),
            "fingerprint": fp,
            "serverName": sni,
            "shortId": reality.get(
                'short_id', ''),
            "spiderX": "/",
        }
    elif security == 'tls':
        stream["tlsSettings"] = {
            "serverName": sni,
            "allowInsecure": False,
        }
    if network == 'grpc':
        stream["grpcSettings"] = {
            "serviceName":
                transport.get(
                    'service_name', ''),
        }
    elif network == 'ws':
        stream["wsSettings"] = {
            "path": transport.get(
                'path', '/'),
            "headers": {
                "Host": transport.get(
                    'headers', {}).get(
                    'Host', ''),
            },
        }
    user = {
        "id": uuid,
        "encryption": "none",
        "level": 0,
    }
    if flow:
        user["flow"] = flow
    xray = {
        "log": {
            "access": "",
            "error": "",
            "loglevel": "none",
        },
        "inbounds": [{
            "port":
                config.localportvless,
            # IPv6 отключён на роутере — слушаем только IPv4.
            "listen": "0.0.0.0",
            "protocol": "dokodemo-door",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": True,
            },
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http", "tls"],
            },
        }],
        "outbounds": [
            {
                "tag": "vless-reality",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server,
                        "port": port,
                        "users": [user],
                    }],
                },
                "streamSettings": stream,
            },
            {
                "tag": "direct",
                "protocol": "freedom",
            },
        ],
        "routing": {
            "domainStrategy":
                "IPIfNonMatch",
            "rules": [{
                "type": "field",
                "port": "0-65535",
                "outboundTag":
                    "vless-reality",
                "enabled": True,
            }],
        },
    }
    return xray


def _convert_xray_hysteria(xc):
    """xray hysteria → нативный hy2."""
    outbounds = xc.get('outbounds', [])
    ho = None
    for ob in outbounds:
        pr = ob.get('protocol', '')
        if pr in ('hysteria', 'hysteria2'):
            ho = ob
            break
    if not ho:
        raise ValueError("Нет outbound hy")
    settings = ho.get('settings', {})
    stream = ho.get('streamSettings', {})
    tls_s = stream.get('tlsSettings', {})
    hy_s = stream.get(
        'hysteriaSettings', {})
    address = settings.get(
        'address',
        settings.get('server', ''))
    port = settings.get('port', 443)
    if not address:
        vn = settings.get('vnext', [])
        if vn:
            address = vn[0].get(
                'address', '')
            port = vn[0].get('port', 443)
    if not address:
        raise ValueError("Нет адреса")
    auth = hy_s.get(
        'auth',
        hy_s.get(
            'auth_str',
            settings.get('auth', '')))
    if not auth:
        vn = settings.get('vnext', [])
        if vn:
            users = vn[0].get('users', [])
            if users:
                auth = users[0].get(
                    'id',
                    users[0].get(
                        'password', ''))
    if not auth:
        raise ValueError("Нет auth")
    sni = tls_s.get(
        'serverName',
        tls_s.get('sni', address))
    alpn = tls_s.get('alpn', [])
    if isinstance(alpn, str):
        alpn = [alpn]
    insecure = tls_s.get(
        'allowInsecure',
        tls_s.get('insecure', False))
    native = {
        "server": f"{address}:{port}",
        "auth": auth,
        "tls": {
            "sni": sni,
            "insecure": insecure,
        },
        "quic": {
            "initStreamReceiveWindow":
                8388608,
            "maxStreamReceiveWindow":
                8388608,
            "initConnReceiveWindow":
                20971520,
            "maxConnReceiveWindow":
                20971520,
        },
        "tcpRedirect": {
            "listen": (
                f"0.0.0.0:"
                f"{config.localporthysteria}")
        }
    }
    if alpn:
        native['tls']['alpn'] = alpn
    fm = stream.get('finalmask', {})
    qp = fm.get('quicParams', {})
    cg = qp.get('congestion', '')
    if cg:
        native['quic']['congestion'] = cg
    return native


def _convert_singbox_hysteria(sb):
    """sing-box hysteria2 → нативный hy2."""
    server = sb.get('server', '')
    port = sb.get('server_port', 443)
    password = sb.get('password', '')
    if not server:
        raise ValueError("Нет server")
    if not password:
        raise ValueError("Нет password")
    tls = sb.get('tls', {})
    sni = tls.get(
        'server_name',
        tls.get('sni', server))
    insecure = tls.get(
        'insecure', False)
    alpn = tls.get('alpn', [])
    if isinstance(alpn, str):
        alpn = [alpn]
    native = {
        "server": f"{server}:{port}",
        "auth": password,
        "tls": {
            "sni": sni,
            "insecure": insecure,
        },
        "quic": {
            "initStreamReceiveWindow":
                8388608,
            "maxStreamReceiveWindow":
                8388608,
            "initConnReceiveWindow":
                20971520,
            "maxConnReceiveWindow":
                20971520,
        },
        "tcpRedirect": {
            "listen": (
                f"0.0.0.0:"
                f"{config.localporthysteria}")
        }
    }
    if alpn:
        native['tls']['alpn'] = alpn
    return native


def apply_direct_config(protocol,
                        config_data,
                        bot=None,
                        chat_id=None):
    """
    JSON конфиг напрямую.
    xray, sing-box, нативный.
    """
    cp = {
        'vless': config.paths[
            "vless_config"],
        'shadowsocks': config.paths[
            "shadowsocks_config"],
        'trojan': config.paths[
            "trojan_config"],
        'hysteria': config.paths[
            "hysteria_config"],
    }
    cdir = {
        'vless': config.paths.get(
            "xray_dir", "/opt/etc/xray"),
        'trojan': config.paths.get(
            "trojan_dir",
            "/opt/etc/trojan"),
        'hysteria': config.paths.get(
            "hysteria_dir",
            "/opt/etc/hysteria"),
    }
    if protocol not in cp:
        raise ValueError(
            f"Неизвестный: {protocol}")
    filepath = cp[protocol]
    dp = cdir.get(protocol)
    if dp:
        os.makedirs(dp, exist_ok=True)
    data = config_data.strip()
    if not data:
        raise ValueError("Пустой конфиг")
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON: {e}")

    if protocol == 'vless':
        if 'outbounds' in parsed:
            # xray формат
            parsed['inbounds'] = [{
                "port":
                    config.localportvless,
                # IPv6 отключён на роутере — слушаем только IPv4.
                "listen": "0.0.0.0",
                "protocol":
                    "dokodemo-door",
                "settings": {
                    "network": "tcp,udp",
                    "followRedirect":
                        True},
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http", "tls"]}
            }]
            parsed.pop('dns', None)
            rt = parsed.get('routing', {})
            rules = rt.get('rules', [])
            cr = [r for r in rules
                  if 'domain' not in r]
            if cr:
                parsed['routing'][
                    'rules'] = cr
            elif 'routing' in parsed:
                del parsed['routing']
        elif (parsed.get('type') == 'vless'
              or ('server' in parsed
                  and 'uuid' in parsed)):
            # sing-box формат
            parsed = (
                _convert_singbox_vless(
                    parsed))
        else:
            raise ValueError(
                "Нет outbounds "
                "или server/uuid")

    elif protocol == 'shadowsocks':
        if 'server' not in parsed:
            raise ValueError("Нет server")
        parsed['local_port'] = (
            config.localportsh)

    elif protocol == 'trojan':
        if (not parsed.get('remote_addr')
                or 'remote_port' not in parsed
                or not parsed.get('password')):
            raise ValueError(
                "Нет remote_addr/remote_port/password")
        parsed['local_port'] = (
            config.localporttrojan)

    elif protocol == 'hysteria':
        if ('server' in parsed
                and 'auth' in parsed):
            # Нативный формат
            pass
        elif ('server' in parsed
              and 'password' in parsed):
            # sing-box формат
            parsed = (
                _convert_singbox_hysteria(
                    parsed))
        elif 'outbounds' in parsed:
            # xray формат
            parsed = (
                _convert_xray_hysteria(
                    parsed))
        else:
            raise ValueError(
                "Нет server/auth, "
                "server/password "
                "или outbounds")
        parsed.setdefault('tcpRedirect', {})['listen'] = (
            f"0.0.0.0:{config.localporthysteria}")

    if protocol == 'vless':
        parsed = _ensure_xray_tproxy(parsed)
    elif protocol == 'hysteria':
        parsed = _ensure_hysteria_tproxy(parsed)

    ConfigWriter.write_config(
        filepath,
        json.dumps(parsed, ensure_ascii=False))


@notify_on_error()
def tor_config(bridges, bot=None,
               chat_id=None):
    bl = bridges.strip().split('\n')
    vt = {"obfs4", "webtunnel"}

    # IPv4 + порт. IPv6 не поддерживается, т.к. отключён на роутере
    # Keenetic (аналогично dnsmasq/ipset, работающим только в family inet).
    ipp = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$")

    urp = re.compile(
        r"^https?://[^\s/$.?#].\S*$")

    for line in bl:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if parts and parts[0].lower() == "bridge":
            parts = parts[1:]
        if not parts:
            raise ValueError(
                f"Мост: '{line}'")
        tt = (parts[0]
              if parts[0] in vt
              else None)
        if tt:
            if len(parts) < 2:
                raise ValueError(
                    f"IP: '{line}'")
            bd = parts[1]
        else:
            bd = parts[0]
        if tt == "webtunnel":
            if not ipp.match(bd):
                raise ValueError(
                    f"IP:порт: '{line}'")
            # url= может быть пустым
            # в некоторых мостах
            url_match = next(
                (p[4:]
                 for p in parts
                 if p.startswith("url=")),
                None)
            if url_match is None:
                raise ValueError(
                    f"Нет url=: '{line}'")
            # Проверять URL только если
            # он не пустой
            if (url_match
                    and not urp.match(
                        url_match)):
                raise ValueError(
                    f"URL: '{line}'")
        else:
            if not ipp.match(bd):
                raise ValueError(
                    f"IP:порт: '{line}'")

    with open(
            os.path.join(
                config.paths[
                    "templates_dir"],
                "tor_template.torrc"),
            'r', encoding='utf-8') as f:
        cdata = f.read()
        cdata = cdata.replace(
            "{{localporttor}}",
            str(config.localporttor))
        cdata = cdata.replace(
            "{{dnsporttor}}",
            str(config.dnsporttor))
        bo = bridges.strip()
        transports = ["obfs4", "webtunnel"]
        found = False
        for t in transports:
            if t in bo:
                bo = "\n".join(
                    line if line.startswith("Bridge ")
                    else (line.replace(
                        t,
                        f"Bridge {t}", 1)
                    if line.startswith(t)
                    else line)
                    for line in
                    bo.splitlines())
                cdata = cdata.replace(
                    f"#ClientTransport"
                    f"Plugin {t}",
                    f"ClientTransport"
                    f"Plugin {t}", 1)
                found = True
        cdata = cdata.replace(
            "{{bridges}}",
            bo if found else "")
    ConfigWriter.write_config(
        config.paths["tor_config"],
        cdata, format='text')



def send_archive(bot, chat_id,
                 file_path, caption):
    f = None
    try:
        f = open(file_path, "rb")
        bot.send_document(
            chat_id, f, caption=caption)
    except (requests.exceptions.ReadTimeout,
            requests.exceptions
            .ConnectionError,
            urllib3.exceptions
            .MaxRetryError):
        bot.send_message(
            chat_id, "❌ Ошибка отправки")
        return False
    finally:
        if f:
            try:
                f.close()
            except Exception:
                pass
            del f
            gc.collect()
    return True


def split_and_send_archive(
        bot, chat_id, archive_path,
        max_size, backup_state,
        progress_msg_id):
    sp = f"{archive_path}_part_"
    try:
        subprocess.run(
            ["split", "-b", str(max_size),
             archive_path, sp],
            check=True)
        pf = sorted([
            f for f in os.listdir(
                os.path.dirname(
                    archive_path))
            if f.startswith(
                os.path.basename(sp))])
        for part_file in pf:
            pp = os.path.join(
                os.path.dirname(
                    archive_path),
                part_file)
            if not send_archive(
                    bot, chat_id, pp,
                    f"⏳ ({part_file})"):
                return False
        bot.edit_message_text(
            f"✅ Разбит:\n"
            f"{', '.join(backup_state.get_selected_types())}",
            chat_id, progress_msg_id)
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Split: {str(e)}")
        bot.edit_message_text(
            "❌ Разбиение",
            chat_id, progress_msg_id)
        return False


def create_backup_with_params(
        bot, chat_id, backup_state,
        selected_drive, progress_msg_id):
    archive_path = None
    args = [config.paths["script_bu"]]
    ms = (config.backup_settings
          .get("MAX_SIZE_MB")
          * 1024 * 1024)
    params = {
        "LOG_FILE":
            config.backup_settings[
                "LOG_FILE"],
        "SELECTED_DRIVE":
            selected_drive["path"],
        "BACKUP_STARTUP_CONFIG": str(
            backup_state
            .startup_config).lower(),
        "BACKUP_FIRMWARE": str(
            backup_state
            .firmware).lower(),
        "BACKUP_ENTWARE": str(
            backup_state
            .entware).lower(),
        "BACKUP_CUSTOM_FILES": str(
            backup_state
            .custom_files).lower(),
    }
    args.extend(
        [f"{k}={v}"
         for k, v in params.items()])
    if (backup_state.custom_files
            and 'CUSTOM_BACKUP_PATHS'
            in config.backup_settings):
        args.append(
            f"CUSTOM_BACKUP_PATHS="
            f"{config.backup_settings['CUSTOM_BACKUP_PATHS']}")
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, bufsize=1,
        universal_newlines=True)
    final_result = None
    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("type") == (
                        "progress"):
                    bot.edit_message_text(
                        f"⏳ "
                        f"{data['message']}",
                        chat_id,
                        progress_msg_id)
                elif "status" in data:
                    final_result = data
            except json.JSONDecodeError:
                continue
        process.wait()
        if (final_result
                and final_result["status"]
                == "success"):
            archive_path = (
                final_result[
                    "archive_path"])
            if not os.path.exists(
                    archive_path):
                bot.edit_message_text(
                    "❌ Не найден",
                    chat_id,
                    progress_msg_id)
                return
            asz = os.path.getsize(
                archive_path)
            if asz <= ms:
                bot.edit_message_text(
                    "✅ Отправляю...",
                    chat_id,
                    progress_msg_id)
                cap = (
                    f"✅ Бэкап:\n"
                    f"{', '.join(backup_state.get_selected_types())}")
                if send_archive(
                        bot, chat_id,
                        archive_path,
                        cap):
                    bot.edit_message_text(
                        "✅ Завершен",
                        chat_id,
                        progress_msg_id)
            else:
                bot.edit_message_text(
                    "❕ Разбиваю...",
                    chat_id,
                    progress_msg_id)
                split_and_send_archive(
                    bot, chat_id,
                    archive_path,
                    ms, backup_state,
                    progress_msg_id)
        elif final_result:
            bot.edit_message_text(
                f"❌ "
                f"{final_result.get('message', '?')}",
                chat_id,
                progress_msg_id)
        else:
            bot.edit_message_text(
                "❌ Без результата",
                chat_id,
                progress_msg_id)
    finally:
        if (archive_path
                and os.path.exists(
                    archive_path)
                and backup_state
                .delete_archive):
            try:
                os.remove(archive_path)
            except Exception as e:
                log_error(
                    f"Del: {str(e)}")
        if (archive_path
                and os.path.exists(
                    os.path.dirname(
                        archive_path))):
            dp = os.path.dirname(
                archive_path)
            bn = os.path.basename(
                archive_path)
            for pf in [
                    f for f
                    in os.listdir(dp)
                    if f.startswith(
                        f"{bn}_part_")]:
                try:
                    os.remove(
                        os.path.join(
                            dp, pf))
                except Exception as e:
                    log_error(
                        f"Part: {str(e)}")


def get_available_drives():
    drives = []
    curr = None
    cm = None
    try:
        mo = subprocess.check_output(
            ["ndmc", "-c", "show media"],
            text=True,
            stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError,
            Exception):
        return []
    for rl in mo.splitlines():
        s = rl.strip()
        if s.startswith("manufacturer:"):
            cm = s.split(":", 1)[1].strip()
        elif s.startswith("uuid:"):
            if curr:
                drives.append(curr)
            uuid = (
                s.split(":", 1)[1].strip())
            curr = {
                'uuid': uuid,
                'path': f"/tmp/mnt/{uuid}"}
        elif (s.startswith("label:")
              and curr is not None):
            curr['label'] = (
                s.split(":", 1)[1].strip())
        elif (s.startswith("fstype:")
              and curr is not None):
            ft = (
                s.split(":", 1)[1].strip())
            if ft == "swap":
                curr = None
            else:
                curr['fstype'] = ft
        elif (s.startswith("free:")
              and curr is not None):
            val = (
                s.split(":", 1)[1].strip())
            try:
                sg = round(
                    int(val)
                    / (1024*1024*1024), 1)
            except Exception:
                sg = None
            curr['size'] = sg
            if curr.get('label'):
                curr['display_name'] = (
                    curr['label'])
            elif cm:
                curr['display_name'] = cm
            else:
                curr['display_name'] = (
                    "Unknown")
    if curr:
        drives.append(curr)
    return drives
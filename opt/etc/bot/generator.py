#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/opt/etc/bot/generator.py
"""

import os
import sys
import json
import ipaddress
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

import bot_config as config
from utils import (
    shadowsocks_config,
    trojan_config,
    vless_config,
    tor_config,
    hysteria_config,
    apply_direct_config,
    log_error,
)

app = Flask(__name__)

SECRET_FILE = '/opt/etc/bot/.secret_key'


def _load_or_create_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r') as f:
            return f.read().strip()
    key = hashlib.sha256(
        os.urandom(64)).hexdigest()
    with open(SECRET_FILE, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(key)
    return key


app.secret_key = _load_or_create_secret()
app.jinja_env.autoescape = True


def generate_csrf():
    token = session.get('csrf_token')

    if isinstance(token, str) and len(token) >= 32:
        return token

    token = hmac.new(
        app.secret_key.encode(),
        os.urandom(32),
        hashlib.sha256).hexdigest()

    session['csrf_token'] = token
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


LAN_IP = os.getenv(
    'LAN_IP', '192.168.1.1')
LISTEN_PORT = int(
    os.getenv('LISTEN_PORT', '8080'))
MAX_CONTENT_LENGTH = 1 * 1024 * 1024
UNBLOCK_TIMEOUT = int(os.getenv(
    'UNBLOCK_UPDATE_TIMEOUT', '300'))

ALLOWED_SUBNETS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fd00::/8'),
]

GENERATOR_LOG = '/opt/etc/bot/generator.log'
UNBLOCK_DIR = '/opt/etc/unblock'
LOCK_DIR = '/tmp/unblock_update.lockdir'
UPDATE_STATUS_FILE = (
    '/tmp/unblock_update_status.json')
UPDATE_LOG_FILE = (
    '/tmp/unblock_update.log')
WRAPPER_SCRIPT = (
    '/tmp/unblock_update_wrapper.sh')

DNS_PORTS_DOT = [
    40500, 40501, 40502, 40503]
DNS_PORTS_DOH = [
    40508, 40509, 40510, 40511]

SERVICE_SCRIPTS = {
    'shadowsocks':
        '/opt/etc/init.d/S65shadowsocks',
    'trojan':
        '/opt/etc/init.d/S22trojan',
    'vless':
        '/opt/etc/init.d/S24xray',
    'tor':
        '/opt/etc/init.d/S35tor',
    'hysteria':
        '/opt/etc/init.d/S23hysteria',
}

BYPASS_FILES = {
    'shadowsocks': os.path.join(
        UNBLOCK_DIR, 'shadowsocks.txt'),
    'trojan': os.path.join(
        UNBLOCK_DIR, 'trojan.txt'),
    'vless': os.path.join(
        UNBLOCK_DIR, 'vless.txt'),
    'tor': os.path.join(
        UNBLOCK_DIR, 'tor.txt'),
    'hysteria': os.path.join(
        UNBLOCK_DIR, 'hysteria.txt'),
}

BOT_BYPASS_FILE = os.path.join(
    UNBLOCK_DIR, 'bot.txt')

BYPASS_IPSETS = {
    'shadowsocks': 'unblocksh',
    'tor':         'unblocktor',
    'vless':       'unblockvless',
    'trojan':      'unblocktroj',
    'hysteria':    'unblockhysteria',
    'bot':         'unblockrouter',
}

MAX_LIST_LINES = 5000


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
    pass


def _is_local_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(
        addr in s for s in ALLOWED_SUBNETS)


@app.before_request
def security_checks():
    # Не доверяем X-Forwarded-For / X-Real-IP.
    client_ip = request.remote_addr or ''

    if not _is_local_ip(client_ip):
        return ('⛔ Запрещено.', 403)

    web_user = getattr(config, 'web_username', 'admin')
    web_pass = getattr(config, 'web_password', '')
    auth = request.authorization

    if (not web_pass
            or not auth
            or not hmac.compare_digest(
                str(auth.username), str(web_user))
            or not hmac.compare_digest(
                str(auth.password), str(web_pass))):
        return Response(
            'Authentication required',
            401,
            {'WWW-Authenticate':
             'Basic realm="Keenetic bypass panel"'})

    if request.method == 'POST':
        allowed_hosts = {
            f'{LAN_IP}:{LISTEN_PORT}',
            f'localhost:{LISTEN_PORT}',
            f'127.0.0.1:{LISTEN_PORT}',
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


def setup_firewall(port):
    wan = ['eth0', 'ppp0', 'ppp1', 'wan0']
    lan = ['br0', 'br1', 'wlan0', 'wlan1']
    for i in wan:
        while True:
            r = subprocess.run(
                ['iptables', '-D', 'INPUT',
                 '-p', 'tcp', '--dport',
                 str(port), '-i', i,
                 '-j', 'ACCEPT'],
                capture_output=True,
                text=True)
            if r.returncode != 0:
                break
    for i in lan:
        if subprocess.run(
            ['iptables', '-C', 'INPUT',
             '-p', 'tcp', '--dport',
             str(port), '-i', i,
             '-j', 'ACCEPT'],
            capture_output=True,
            text=True).returncode != 0:
            subprocess.run(
                ['iptables', '-I', 'INPUT',
                 '-p', 'tcp', '--dport',
                 str(port), '-i', i,
                 '-j', 'ACCEPT'],
                capture_output=True,
                text=True)
    if subprocess.run(
        ['iptables', '-C', 'INPUT',
         '-p', 'tcp', '--dport',
         str(port), '-j', 'DROP'],
        capture_output=True,
        text=True).returncode != 0:
        subprocess.run(
            ['iptables', '-A', 'INPUT',
             '-p', 'tcp', '--dport',
             str(port), '-j', 'DROP'],
            capture_output=True,
            text=True)


def _check_csrf():
    token = request.form.get(
        'csrf_token', '')
    if not validate_csrf(token):
        abort(403)


def restart_service(sn):
    sc = SERVICE_SCRIPTS.get(sn)
    if not sc:
        raise ValueError(f"?: {sn}")
    if not os.path.exists(sc):
        raise FileNotFoundError(f"!: {sc}")
    os.chmod(sc, 0o755)
    r = subprocess.run(
        [sc, 'restart'],
        capture_output=True,
        text=True, timeout=30)
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


def _build_wrapper(sp):
    lines = [
        '#!/bin/sh',
        'export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin',
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


def apply_unblock_async():
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
        f.write(_build_wrapper(sc))
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


def check_dns_ports():
    res = {'dot': {}, 'doh': {}}
    for p in DNS_PORTS_DOT:
        res['dot'][str(p)] = (
            _test_dns_port(p))
    for p in DNS_PORTS_DOH:
        res['doh'][str(p)] = (
            _test_dns_port(p))
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
        results['domains'] = [q]
        try:
            r = subprocess.run(
                ['dig', '+short', q,
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
                 q, '@localhost'],
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
        cidr_found = False
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
                cidr_found = True
                break
            elif check_net == net:
                # Точное совпадение
                found_anywhere.add(cidr_str)
                results['in_lists']. \
                    setdefault(fname, []) \
                    .append(cidr_str)
                cidr_found = True
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
:root{--bg:#0f1117;--card:#1a1d27;
  --border:#2d3148;--accent:#6c5ce7;
  --green:#00b894;--red:#d63031;
  --text:#dfe6e9;--muted:#636e8a;
  --input-bg:#13151d;--divider:#2a2e42;
  --orange:#e17055}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,
  sans-serif;background:var(--bg);
  color:var(--text);min-height:100vh;
  display:flex;flex-direction:column;
  align-items:center;padding:1.5rem 1rem}
h1{font-size:1.5rem;margin-bottom:1rem;
  background:linear-gradient(135deg,
  var(--accent),var(--green));
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent}
.tabs{display:flex;gap:3px;
  margin-bottom:-1px;flex-wrap:wrap;
  justify-content:center}
.tab-btn{padding:.5rem 1rem;
  border:1px solid var(--border);
  border-bottom:none;
  border-radius:8px 8px 0 0;
  background:var(--card);
  color:var(--muted);cursor:pointer;
  font-size:.82rem;transition:.2s}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--accent);
  border-color:var(--accent);
  background:var(--bg);font-weight:600}
.card{width:100%;max-width:720px;
  background:var(--card);
  border:1px solid var(--border);
  border-radius:0 12px 12px 12px;
  padding:1.5rem}
.tab-content{display:none}
.tab-content.active{display:block}
label{display:block;font-size:.8rem;
  color:var(--muted);margin-bottom:.3rem}
textarea,input[type=text]{width:100%;
  padding:.6rem .8rem;
  background:var(--input-bg);
  border:1px solid var(--border);
  border-radius:8px;color:var(--text);
  font-size:.85rem;
  font-family:'Consolas',monospace;
  resize:vertical;
  transition:border-color .2s}
textarea:focus,input:focus{outline:none;
  border-color:var(--accent)}
.key-area{min-height:90px}
.list-area{min-height:260px;line-height:1.5}
.hint{font-size:.7rem;color:var(--muted);
  margin:.2rem 0 .7rem;line-height:1.4}
.divider{height:1px;
  background:var(--divider);
  margin:1.2rem 0;position:relative;
  display:flex;align-items:center;
  justify-content:center}
.divider span{background:var(--card);
  color:var(--accent);font-size:.78rem;
  font-weight:600;padding:0 .8rem;
  position:relative;z-index:1}
.btn{width:100%;padding:.65rem;border:none;
  border-radius:8px;color:#fff;
  font-size:.88rem;font-weight:600;
  cursor:pointer;transition:opacity .2s;
  min-height:2.6rem;display:flex;
  align-items:center;
  justify-content:center;gap:.4rem}
.btn:hover{opacity:.88}
.btn:disabled{opacity:.55;
  cursor:not-allowed}
.btn-key{background:linear-gradient(
  135deg,var(--accent),#7c6cf0)}
.btn-cfg{background:linear-gradient(
  135deg,#e17055,#d63031);margin-top:.2rem}
.btn-save{background:linear-gradient(
  135deg,var(--green),#00cec9);
  margin-top:.2rem}
.btn .spinner-ring{display:none;
  width:1rem;height:1rem;
  border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;
  animation:spin .6s linear infinite}
.btn.loading .spinner-ring{
  display:inline-block}
.btn.loading .btn-label{opacity:.7}
@keyframes spin{to{
  transform:rotate(360deg)}}
.msg{margin:.8rem auto;padding:.7rem 1rem;
  border-radius:8px;font-size:.84rem;
  max-width:720px;width:100%;
  animation:fadeIn .3s;
  white-space:pre-line}
.msg-ok{background:rgba(0,184,148,.12);
  border-left:4px solid var(--green)}
.msg-err{background:rgba(214,48,49,.12);
  border-left:4px solid var(--red)}
@keyframes fadeIn{from{opacity:0;
  transform:translateY(-5px)}
  to{opacity:1;transform:none}}
.counter{font-size:.7rem;
  color:var(--muted);text-align:right;
  margin-top:.15rem}
#update-bar{display:none;max-width:720px;
  width:100%;margin:.6rem auto;
  padding:.6rem 1rem;border-radius:8px;
  font-size:.84rem;text-align:center}
#update-bar.running{display:block;
  background:rgba(108,92,231,.15);
  border-left:4px solid var(--accent);
  color:var(--accent);
  animation:pulse 1.5s ease-in-out infinite}
#update-bar.done{display:block;
  background:rgba(0,184,148,.15);
  border-left:4px solid var(--green);
  color:var(--green);animation:fadeIn .3s}
#update-bar.error{display:block;
  background:rgba(214,48,49,.15);
  border-left:4px solid var(--red);
  color:var(--red);animation:fadeIn .3s}
@keyframes pulse{0%,100%{opacity:1}
  50%{opacity:.5}}
.dns-panel{max-width:720px;width:100%;
  margin-top:1.2rem}
.dns-toggle{background:none;
  border:1px solid var(--border);
  border-radius:8px;padding:.4rem .8rem;
  color:var(--muted);font-size:.75rem;
  cursor:pointer;width:100%;
  text-align:center}
.dns-toggle:hover{color:var(--text);
  border-color:var(--accent)}
.dns-grid{display:none;
  grid-template-columns:repeat(4,1fr);
  gap:.4rem;margin-top:.5rem;
  background:var(--card);
  border:1px solid var(--border);
  border-radius:8px;padding:.8rem}
.dns-grid.open{display:grid}
.dns-port{text-align:center;padding:.3rem;
  border-radius:6px;font-size:.72rem;
  font-family:monospace}
.dns-port.ok{background:
  rgba(0,184,148,.15);color:var(--green)}
.dns-port.fail{background:
  rgba(214,48,49,.15);color:var(--red)}
.dns-port.checking{background:
  rgba(99,110,138,.15);color:var(--muted)}
.dns-label{font-size:.7rem;
  color:var(--muted);margin:.5rem 0 .2rem;
  font-weight:600;grid-column:1/-1}
.info-box{background:rgba(225,112,85,.1);
  border:1px solid var(--orange);
  border-radius:8px;padding:.7rem;
  margin-bottom:1rem;font-size:.78rem;
  line-height:1.5;color:var(--orange)}
.info-box code{background:rgba(0,0,0,.3);
  padding:.1rem .3rem;border-radius:3px;
  font-size:.72rem}
.ver-grid{display:none;
  grid-template-columns:1fr 1fr;gap:.4rem;
  margin-top:.5rem;background:var(--card);
  border:1px solid var(--border);
  border-radius:8px;padding:.8rem}
.ver-grid.open{display:grid}
.lk-presets{display:flex;gap:.4rem;
  flex-wrap:wrap;margin-bottom:.8rem}
.lk-presets button{padding:.3rem .7rem;
  border:1px solid var(--border);
  border-radius:6px;background:var(--card);
  color:var(--muted);cursor:pointer;
  font-size:.75rem;transition:.2s}
.lk-presets button:hover{
  color:var(--accent);
  border-color:var(--accent)}
</style></head><body>
<h1>&#9881;&#65039;
  Генератор конфигураций</h1>
<div id="update-bar"></div>
{% with msgs = get_flashed_messages(
  with_categories=true) %}
{% if msgs %}{% for cat, msg in msgs %}
<div class="msg {{ 'msg-ok'
  if cat=='ok' else 'msg-err' }}">
  {{ msg }}</div>
{% endfor %}{% endif %}{% endwith %}
<div class="tabs">
  <button class="tab-btn
    {% if active=='ss' %}active{% endif %}"
    onclick="go('ss')">Shadowsocks</button>
  <button class="tab-btn
    {% if active=='tr' %}active{% endif %}"
    onclick="go('tr')">Trojan</button>
  <button class="tab-btn
    {% if active=='vl' %}active{% endif %}"
    onclick="go('vl')">VLESS</button>
  <button class="tab-btn
    {% if active=='to' %}active{% endif %}"
    onclick="go('to')">Tor</button>
  <button class="tab-btn
    {% if active=='hy' %}active{% endif %}"
    onclick="go('hy')">Hysteria</button>
  <button class="tab-btn
    {% if active=='bt' %}active{% endif %}"
    onclick="go('bt')">&#129302; Бот</button>
  <button class="tab-btn
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
          onclick="copyLookup()">
          &#128203; Копировать</button>
      </div>
      <p class="hint">
        Скопируйте и вставьте
        в список обхода нужного
        протокола.</p>
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
  </div>
</div>
<div class="dns-panel">
  <button class="dns-toggle"
    onclick="toggleVer()">
    &#128230; Версии</button>
  <div class="ver-grid" id="ver-grid">
    <div class="dns-label">
      Протокол &mdash; Версия</div>
    <div class="dns-port checking"
      id="ver-xray">xray</div>
    <div class="dns-port checking"
      id="ver-hysteria">hysteria</div>
    <div class="dns-port checking"
      id="ver-shadowsocks">ss</div>
    <div class="dns-port checking"
      id="ver-trojan">trojan</div>
    <div class="dns-port checking"
      id="ver-tor">tor</div>
    <div class="dns-port checking"
      id="ver-dnsmasq">dnsmasq</div>
  </div>
</div>
<script>
function go(id){location.href='/?tab='+id}
['ss','tr','vl','to','hy','bt'].forEach(
  function(id){
  var ta=document.getElementById('ta-'+id),
  cnt=document.getElementById('cnt-'+id);
  if(!ta||!cnt)return;
  function u(){cnt.textContent=
    '\u0421\u0442\u0440: '
    +ta.value.split('\n').length}
  ta.addEventListener('input',u);u();});
function btnLock(f){
  var b=f.querySelector('.btn');
  if(!b||b.classList.contains('loading'))
    return false;
  b.classList.add('loading');
  b.disabled=true;return true;}
var _poll=null,_ld=0;
function pollUpdate(){
  fetch('/api/update-status')
  .then(function(r){return r.json()})
  .then(function(d){
    var bar=document.getElementById(
      'update-bar'),
    now=Math.floor(Date.now()/1000);
    if(d.status==='running'){
      var e=now-(d.ts||now);if(e<0)e=0;
      bar.className='running';
      bar.textContent=
        '\u23F3\u041e\u0431\u043d'
        +'\u043e\u0432\u043b\u0435'
        +'\u043d\u0438\u0435\u2026 '
        +e+'\u0441';
      bar.style.display='block';
      if(!_poll)_poll=setInterval(
        pollUpdate,2000);
    }else if(d.status==='done'){
      if(d.ts>_ld){_ld=d.ts;
        bar.className='done';
        bar.textContent=
          '\u2705\u0413\u043e'
          +'\u0442\u043e\u0432\u043e';
        bar.style.display='block';
        setTimeout(function(){
          bar.style.display='none'},8000);}
      if(_poll){clearInterval(_poll);
        _poll=null;}
    }else if(d.status==='error'
        &&d.ts&&(now-d.ts)<120){
      bar.className='error';
      bar.textContent=
        '\u274C'+(d.message||'');
      bar.style.display='block';
      if(_poll){clearInterval(_poll);
        _poll=null;}
    }else{if(_poll){clearInterval(_poll);
      _poll=null;}}
  }).catch(function(){});}
pollUpdate();
var _dO=false;
function toggleDns(){
  var g=document.getElementById('dns-grid');
  _dO=!_dO;
  g.className=_dO?'dns-grid open':'dns-grid';
  if(_dO)fetchDns();}
function fetchDns(){
  [40500,40501,40502,40503,
   40508,40509,40510,40511]
  .forEach(function(p){
    var el=document.getElementById('dp-'+p);
    if(el){el.className='dns-port checking';
      el.textContent=p+'\u2026';}});
  fetch('/api/dns-status')
  .then(function(r){return r.json()})
  .then(function(d){
    ['dot','doh'].forEach(function(t){
      if(!d[t])return;
      Object.keys(d[t]).forEach(function(p){
        var el=document.getElementById(
          'dp-'+p);
        if(el){el.className='dns-port '
          +(d[t][p]?'ok':'fail');
          el.textContent=p
            +(d[t][p]?' \u2713'
              :' \u2717');}});});
  }).catch(function(){});}
var _vO=false;
function toggleVer(){
  var g=document.getElementById('ver-grid');
  _vO=!_vO;
  g.className=_vO?'ver-grid open':'ver-grid';
  if(_vO)fetchVer();}
function fetchVer(){
  ['xray','hysteria','shadowsocks',
   'trojan','tor','dnsmasq'].forEach(
    function(n){
    var el=document.getElementById('ver-'+n);
    if(el){el.className='dns-port checking';
      el.textContent=n+'\u2026';}});
  fetch('/api/protocol-versions')
  .then(function(r){return r.json()})
  .then(function(d){
    if(!d.versions)return;
    var u={};
    if(d.updates){d.updates.forEach(
      function(x){u[x.name]=x.available;});}
    Object.keys(d.versions).forEach(
      function(n){
      var el=document.getElementById(
        'ver-'+n);
      if(!el)return;
      var v=d.versions[n],nv=u[n];
      if(nv){el.className='dns-port fail';
        el.textContent=n+': '+v
          +' \u2192 '+nv;
      }else{el.className='dns-port ok';
        el.textContent=n+': '+v;}});
  }).catch(function(){});}
function lkSet(v){
  document.getElementById('lk-query').value=v;
  doLookup();}
function doLookup(){
  var q=document.getElementById(
    'lk-query').value.trim();
  if(!q)return;
  var sp=document.getElementById('lk-spin');
  sp.style.display='inline-block';
  var fd=new FormData();
  fd.append('query',q);
  fetch('/api/lookup',{method:'POST',body:fd})
  .then(function(r){return r.json()})
  .then(function(d){
    sp.style.display='none';
    document.getElementById(
      'lk-results').style.display='block';
    var info=document.getElementById(
      'lk-info');
    var status=document.getElementById(
      'lk-status');
    var output=document.getElementById(
      'lk-output');
    info.textContent=
      '\u0421\u0430\u0439\u0442\u044b: '
      +(d.domains||[]).length
      +' | IP: '+(d.ips||[]).length
      +' | CIDR: '+(d.cidrs||[]).length;
    var inl=d.in_lists||{};
    var miss=d.missing||[];
    var fnd=d.found||[];
    var cov=d.covered||{};
    var h='<div style="font-size:.8rem">';
    if(fnd.length>0){
      h+='<div style="color:var(--green);'
        +'margin-bottom:.3rem">'
        +'\u2705 \u0412 \u0441\u043f'
        +'\u0438\u0441\u043a\u0430\u0445: '
        +fnd.length+'</div>';
      var keys=Object.keys(inl);
      keys.forEach(function(k){
        h+='<span style="color:var(--green)'
          +';font-size:.72rem">'
          +'  '+k+'.txt: '
          +inl[k].join(', ')
          +'</span><br>';});
      var covKeys=Object.keys(cov);
      if(covKeys.length>0){
        h+='<div style="color:var(--accent);'
          +'font-size:.72rem;'
          +'margin-top:.2rem">'
          +'\u2139\ufe0f '
          +'\u041f\u043e\u043a\u0440\u044b'
          +'\u0442\u044b:</div>';
        covKeys.forEach(function(k){
          h+='<span style="color:'
            +'var(--accent);'
            +'font-size:.72rem">'
            +'  '+k+' \u2192 '+cov[k]
            +'</span><br>';});}}
    if(miss.length>0){
      h+='<div style="color:var(--orange);'
        +'margin-top:.3rem">'
        +'\u26a0\ufe0f \u041d\u0435\u0442 '
        +'\u0432 \u0441\u043f\u0438\u0441'
        +'\u043a\u0430\u0445: '
        +miss.length+'</div>';}
    if(fnd.length===0&&miss.length===0){
      h+='<span style="color:var(--muted)">'
        +'\u041d\u0435\u0442 '
        +'\u0434\u0430\u043d\u043d\u044b'
        +'\u0445</span>';}
    h+='</div>';
    status.innerHTML=h;
    function sortItems(arr){
      var ok=[],no=[];
      arr.forEach(function(v){
        if(miss.indexOf(v)>=0){
          no.push(v);
        }else{ok.push(v);}});
      return ok.concat(no);}
    function markItem(v){
      if(cov[v])
        return v+' #\u2705 '+cov[v];
      if(miss.indexOf(v)>=0)
        return v+' #\u26a0\ufe0f';
      return v+' #\u2705';}
    var lines=[];
    var dn=sortItems(d.domains||[]);
    var ips=sortItems(d.ips||[]);
    var cidrs=sortItems(d.cidrs||[]);
    if(dn.length>0){
      lines.push('#'+q);
      dn.forEach(function(v){
        lines.push(markItem(v));});}
    if(ips.length>0){
      if(lines.length>0)lines.push('');
      lines.push('#'+q+' IP');
      ips.forEach(function(v){
        lines.push(markItem(v));});}
    if(cidrs.length>0){
      if(lines.length>0)lines.push('');
      lines.push('#'+q+' CIDR');
      cidrs.forEach(function(v){
        lines.push(markItem(v));});}
    output.value=lines.join('\n');
  }).catch(function(e){
    sp.style.display='none';
    alert('\u274c '+e);});
}
function copyLookup(){
  var ta=document.getElementById('lk-output');
  ta.select();
  ta.setSelectionRange(0,ta.value.length);
  try{
    document.execCommand('copy');
    var b=event.target;var old=b.textContent;
    b.textContent=
      '\u2705 \u0421\u043a\u043e\u043f'
      +'\u0438\u0440\u043e\u0432\u0430'
      +'\u043d\u043e';
    setTimeout(function(){
      b.textContent=old;},2000);
  }catch(e){}}
document.getElementById('lk-query')
  .addEventListener('keypress',function(e){
    if(e.key==='Enter')doLookup();});
</script></body></html>
'''


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
        csrf_token=generate_csrf())


@app.route('/api/update-status')
def api_update_status():
    return jsonify(_read_update_status())


@app.route('/api/dns-status')
def api_dns_status():
    return jsonify(check_dns_ports())


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
        apply_unblock_async()
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
    for i in ['eth0', 'ppp0',
              'ppp1', 'wan0']:
        r = subprocess.run(
            ['iptables', '-C', 'INPUT',
             '-p', 'tcp', '--dport',
             str(LISTEN_PORT),
             '-i', i, '-j', 'ACCEPT'],
            capture_output=True,
            text=True)
        if r.returncode == 0:
            subprocess.run(
                ['iptables', '-D',
                 'INPUT', '-p', 'tcp',
                 '--dport',
                 str(LISTEN_PORT),
                 '-i', i,
                 '-j', 'ACCEPT'],
                capture_output=True,
                text=True)
    print(
        f"\n  http://{LAN_IP}"
        f":{LISTEN_PORT}\n")
    app.run(
        host=LAN_IP,
        port=LISTEN_PORT,
        debug=False,
        use_reloader=False)
        
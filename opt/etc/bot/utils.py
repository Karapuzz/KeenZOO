# -*- coding: utf-8 -*-
# --- KeenZOO DNS policy v4 (stdlib only; before optional bot imports) ---
import datetime as _v4_datetime
import ast as _v4_ast
import concurrent.futures as _v4_futures
import fcntl as _v4_fcntl
import ipaddress as _v4_ip
import json as _v4_json
import os as _v4_os
from pathlib import Path as _V4Path
import re as _v4_re
import secrets as _v4_secrets
import signal as _v4_signal
import socket as _v4_socket
import socketserver as _v4_server
import struct as _v4_struct
import subprocess as _v4_subprocess
import sys as _v4_sys
import tempfile as _v4_temp
import threading as _v4_thread
import time as _v4_time

V4_PORT = 40512  # Stable loopback facade; never included among candidate ports.
V4_STATE = '/tmp/keenzoo-dns-v4.json'
V4_LOCK = '/tmp/keenzoo-dns-v4.lock'
V4_CONFIG = '/opt/etc/bot/bot_config.py'
V4_PRIORITY = ('hysteria', 'xray', 'trojan')
V4_MARKS = {'hysteria': 0x02000101, 'xray': 0x02000102, 'trojan': 0x02000103}
V4_EMERGENCY_MARK = 0x02000104


def v4_config(path=V4_CONFIG):
    allowed = {'dnsovertls_ports', 'dnsoverhttps_ports', 'bootstrap_resolvers',
               'dns_health_domain', 'dns_policy_interval', 'dns_policy_pool_hours',
               'dns_policy_recovery_interval',
               'localporthysteria', 'localportvless', 'localporttrojan'}
    raw = {}
    tree = _v4_ast.parse(_V4Path(path).read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, _v4_ast.Assign):
            for target in node.targets:
                if isinstance(target, _v4_ast.Name) and target.id in allowed:
                    raw[target.id] = _v4_ast.literal_eval(node.value)
    ports = raw.get('dnsovertls_ports', [40500, 40501, 40502, 40503]) + raw.get('dnsoverhttps_ports', [40508, 40509, 40510, 40511])
    if not ports or len(ports) > 16 or any(type(p) is not int or not 1024 <= p <= 65535 or p == V4_PORT for p in ports):
        raise ValueError('invalid DNS candidate ports')
    bootstrap = list(dict.fromkeys(str(_v4_ip.IPv4Address(p)) for p in raw.get('bootstrap_resolvers', ['9.9.9.9', '8.8.8.8', '1.1.1.1'])))
    if not 1 <= len(bootstrap) <= 8 or any(not _v4_ip.IPv4Address(p).is_global for p in bootstrap):
        raise ValueError('bootstrap_resolvers must contain 1..8 public IPv4 addresses')
    domain = raw.get('dns_health_domain', 'example.com').rstrip('.')
    if len(domain) > 253 or not all(_v4_re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', s) for s in domain.split('.')):
        raise ValueError('invalid DNS health domain')
    interval = raw.get('dns_policy_interval', 3600)
    hours = raw.get('dns_policy_pool_hours', [11, 23])
    recovery = raw.get('dns_policy_recovery_interval', 300)
    if type(interval) is not int or not 1800 <= interval <= 3600:
        raise ValueError('DNS idle control interval must be 1800..3600 seconds; migrate legacy settings')
    if hours != [11, 23] or any(type(h) is not int for h in hours):
        raise ValueError('DNS pool hours must be [11, 23] in router local time')
    if type(recovery) is not int or recovery != 300:
        raise ValueError('DNS Primary recovery interval must be 300 seconds')
    targets = dict(zip(V4_PRIORITY, (raw.get('localporthysteria', 10830), raw.get('localportvless', 10810), raw.get('localporttrojan', 10829))))
    if any(type(p) is not int or not 1024 <= p <= 65535 or p == V4_PORT for p in targets.values()):
        raise ValueError('invalid tunnel listener port')
    return {'ports': list(dict.fromkeys(ports)), 'bootstrap': bootstrap, 'domain': domain,
            'interval': interval, 'pool_hours': hours, 'recovery_interval': recovery, 'targets': targets}


def v4_name(data, offset):
    labels, seen, end = [], set(), None
    for _ in range(128):
        if offset >= len(data) or offset in seen:
            raise ValueError('invalid DNS name')
        seen.add(offset)
        n = data[offset]
        if n & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                raise ValueError('short DNS pointer')
            end = end if end is not None else offset + 2
            offset = ((n & 63) << 8) | data[offset+1]
        elif n == 0:
            return b'.'.join(labels).lower(), end if end is not None else offset + 1
        elif n <= 63 and offset + 1 + n <= len(data):
            labels.append(data[offset+1:offset+1+n]); offset += n + 1
        else:
            raise ValueError('invalid DNS label')
    raise ValueError('DNS name too complex')


def v4_question(data):
    if len(data) < 12 or _v4_struct.unpack('!H', data[4:6])[0] != 1:
        raise ValueError('exactly one DNS question required')
    name, offset = v4_name(data, 12)
    if offset + 4 > len(data):
        raise ValueError('short question')
    return (name, data[offset:offset+4]), offset + 4


def v4_query(domain):
    name = b''.join(bytes([len(s)]) + s.encode('ascii') for s in domain.split('.')) + b'\0'
    return _v4_struct.pack('!HHHHHH', _v4_secrets.randbits(16), 0x0120, 1, 0, 0, 1) + name + b'\0\x01\0\x01' + b'\0\0\x29\x04\xd0\0\0\x80\0\0\0'


def v4_answer(data, query, health=False, secure=False):
    if len(data) < 12 or data[:2] != query[:2]:
        raise ValueError('DNS transaction mismatch')
    flags = _v4_struct.unpack('!H', data[2:4])[0]
    if not flags & 0x8000 or flags & 0x7800 or v4_question(data)[0] != v4_question(query)[0]:
        raise ValueError('DNS response/question mismatch')
    if health:
        if flags & 0x020f or (secure and not flags & 0x0020):
            raise ValueError('health response lacks validated positive result')
        question, offset = v4_question(data)
        if question[1] != b'\0\x01\0\x01':
            raise ValueError('health requires an IN A question')
        addresses, aliases = set(), {}
        for _ in range(_v4_struct.unpack('!H', data[6:8])[0]):
            owner, offset = v4_name(data, offset)
            if offset + 10 > len(data):
                raise ValueError('short resource record')
            kind, cls, _, size = _v4_struct.unpack('!HHIH', data[offset:offset+10]); offset += 10
            if offset + size > len(data):
                raise ValueError('short resource data')
            if kind == 1 and cls == 1 and size == 4:
                addresses.add(owner)
            elif kind == 5 and cls == 1:
                alias, end = v4_name(data, offset)
                if end != offset + size:
                    raise ValueError('invalid CNAME data')
                aliases[owner] = alias
            offset += size
        name = question[0]
        for _ in range(32):
            if name in addresses:
                break
            if name not in aliases:
                raise ValueError('health response has no matching IPv4 answer')
            name = aliases[name]
        else:
            raise ValueError('CNAME chain too complex')
    return data


def v4_recv(sock, count, deadline=None):
    chunks = bytearray()
    deadline = deadline or (_v4_time.monotonic() + (sock.gettimeout() or 2))
    while len(chunks) < count:
        remaining = deadline - _v4_time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS frame deadline")
        sock.settimeout(remaining)
        data = sock.recv(count - len(chunks))
        if not data:
            raise OSError('short DNS TCP frame')
        chunks.extend(data)
    return bytes(chunks)


def v4_exchange(query, host, port, tcp=False, mark=0, timeout=2):
    # Every exchange uses a fresh socket. Mark is set BEFORE connect; a failed
    # SO_MARK never falls back to unmarked/direct DNS.
    with _v4_socket.socket(_v4_socket.AF_INET, _v4_socket.SOCK_STREAM if tcp else _v4_socket.SOCK_DGRAM) as sock:
        deadline = _v4_time.monotonic() + timeout
        sock.settimeout(timeout)
        if mark:
            sock.setsockopt(_v4_socket.SOL_SOCKET, getattr(_v4_socket, 'SO_MARK', 36), mark)
        sock.connect((host, port))
        if tcp:
            remaining = deadline - _v4_time.monotonic()
            if remaining <= 0: raise TimeoutError("DNS connect deadline")
            sock.settimeout(remaining)
            sock.sendall(_v4_struct.pack('!H', len(query)) + query)
            size = _v4_struct.unpack('!H', v4_recv(sock, 2, deadline))[0]
            data = v4_recv(sock, size, deadline)
        else:
            sock.send(query); data = sock.recv(65535)
    v4_answer(data, query)
    if not tcp and data[2] & 2:
        return v4_exchange(query, host, port, True, mark, timeout)
    return data


def v4_fail(query):
    try:
        end = v4_question(query)[1]
        return query[:2] + _v4_struct.pack('!HHHHH', 0x8082 | (query[2] & 1) << 8, 1, 0, 0, 0) + query[12:end]
    except (ValueError, IndexError):
        return b''


def v4_identity(pid):
    text = _V4Path('/proc/%d/stat' % pid).read_text()
    fields = text[text.rfind(')')+2:].split()
    if fields[0] == 'Z': raise ValueError('worker is a zombie')
    return fields[19]


def v4_read_state(path):
    fd = _v4_os.open(path, _v4_os.O_RDONLY | _v4_os.O_NOFOLLOW)
    with _v4_os.fdopen(fd) as stream:
        stat = _v4_os.fstat(stream.fileno())
        if stat.st_uid != _v4_os.geteuid() or stat.st_mode & 0o022:
            raise ValueError('unsafe DNS state ownership')
        return _v4_json.loads(stream.read(65536))


def v4_status(path=V4_STATE, check_age=True):
    try:
        result = v4_read_state(path)
        if result.get('version') != 4 or v4_identity(int(result['pid'])) != result['start']:
            return {}
        age = _v4_time.time() - result['epoch']
        limit = 180 if result.get('health_mode') == 'hybrid' else max(180, int(result.get('interval', 15))*3 + 120)
        if check_age and (age < -2 or age > limit):
            return {}
        return result
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return {}


class DNSPolicyV4:
    # The maintenance tick reads local files and publishes a heartbeat ONLY.
    # It is NOT a DNS probe, subprocess, cron job or connection to the WAN.
    HEARTBEAT = 30
    EVENT_COOLDOWN = 30

    def __init__(self, cfg, state_path=V4_STATE, exchange=v4_exchange):
        self.cfg, self.state_path, self.exchange = cfg, state_path, exchange
        self.stop = _v4_thread.Event()
        self.wake = _v4_thread.Event()
        self.rerank = _v4_thread.Event()
        self.network_event = _v4_thread.Event()
        self.guard = _v4_thread.RLock()
        self.active = None
        self.mode = 'DNS_UNAVAILABLE'
        self.preferred = None
        self.metrics = {}
        self.last_pool = 0
        self.last_restart = {}
        self.deploy_owner = self.deployment_owner()
        self.last_log = None
        self.query_count = 0
        self.health_query_count = 0
        self.passive_confirmations = 0
        self.failure_events = 0
        self.generation = 0
        self.last_checked = 0
        self.last_good = 0
        self.last_evidence_epoch = None
        self.last_control_epoch = None
        self.last_primary_probe = 0
        self.last_primary_probe_epoch = None
        self.last_heartbeat = _v4_time.monotonic()
        self.last_maintenance = None
        self.pending_failure = False
        self.pending_network = False
        self.pending_rerank = False
        self.next_event = 0
        self.initialized = False
        self.check_reason = 'starting'
        self.next_pool_epoch = self.next_pool_time(_v4_time.time())
        self.last_calendar_slot = ''
        self.last_wall = _v4_time.time()
        self.config_stamp = None
        self.listener_stamp = None
        try:
            old = v4_read_state(state_path)
            if old.get('candidates') == cfg['ports'] and old.get('preferred') in cfg['ports']:
                self.preferred = old['preferred']
        except (OSError, ValueError):
            pass

    def next_pool_time(self, now):
        local = _v4_datetime.datetime.fromtimestamp(now)
        for day in (0, 1, 2):
            date = local.date() + _v4_datetime.timedelta(days=day)
            for hour in self.cfg.get('pool_hours', [11, 23]):
                slot = _v4_datetime.datetime.combine(date, _v4_datetime.time(hour))
                # timestamp() uses the same local TZ/DST rules as the router.
                if slot.timestamp() > now:
                    return slot.timestamp()
        raise ValueError('cannot schedule DNS pool')

    def health(self, target, secure=False, samples=1):
        rtts = []
        for _ in range(samples):
            if self.stop.is_set():
                return None
            query = v4_query(self.cfg['domain'])
            started = _v4_time.monotonic()
            with self.guard:
                self.health_query_count += 1
            try:
                response = self.exchange(query, *target)
                v4_answer(response, query, health=True, secure=secure)
                rtts.append((_v4_time.monotonic() - started) * 1000)
            except (OSError, ValueError):
                return None
        return sum(rtts) / len(rtts)

    def scan_local(self, ports):
        if not ports:
            return
        def one(port):
            target = ('127.0.0.1', port, False, 0)
            result = self.health(target, True)
            if result is None:  # Confirm an error; steady healthy port costs ONE query.
                result = self.health(target, True)
            return port, result
        with _v4_futures.ThreadPoolExecutor(max_workers=3) as pool:
            for port, rtt in pool.map(one, ports):
                with self.guard:
                    self.metrics[port] = {'rtt': rtt, 'at': _v4_time.time()}
                    if port == self.preferred:
                        self.last_primary_probe = _v4_time.monotonic()
                        self.last_primary_probe_epoch = _v4_time.time()

    @staticmethod
    def deployment_owner():
        try:
            root = _V4Path('/tmp/keenzoo_deploy.lockdir')
            return ((root/'pid').read_text().strip(), (root/'start').read_text().strip())
        except OSError:
            return None

    @staticmethod
    def listener_identity(protocol, port):
        inodes = set()
        try:
            for name in ('tcp', 'tcp6'):
                with open('/proc/net/' + name) as table:
                    for row in table:
                        columns = row.split()
                        if len(columns) > 9 and columns[3] == '0A' and int(columns[1].split(':')[-1], 16) == int(port):
                            inodes.add('socket:[' + columns[9] + ']')
            if not inodes:
                return False, False
            for directory in _V4Path('/proc').glob('[0-9]*'):
                try:
                    argv0 = (directory/'cmdline').read_bytes().split(b'\0', 1)[0].decode('utf-8', 'replace')
                    if _v4_os.path.basename(argv0) != protocol:
                        continue
                    for fd in (directory/'fd').iterdir():
                        try:
                            if _v4_os.readlink(fd) in inodes:
                                return True, True
                        except OSError:
                            pass
                except OSError:
                    continue
        except (OSError, ValueError):
            return True, False  # Unverifiable is not permission to start/probe.
        return True, False

    def tunnel_ready(self, protocol):
        # Fail-closed proof of the exact marked path. filter blocks tcp/53
        # if NAT redirection disappears; it is not PID/listener verification.
        mark = hex(V4_MARKS[protocol])
        port = str(self.cfg['targets'][protocol])
        rules = [
            ['-t', 'nat', '-C', 'OUTPUT', '-j', 'KZ_DNS_V4'],
            ['-t', 'nat', '-C', 'KZ_DNS_V4', '-p', 'tcp', '--dport', '53', '-m', 'mark', '--mark', mark, '-j', 'REDIRECT', '--to-ports', port],
            ['-t', 'filter', '-C', 'OUTPUT', '-p', 'tcp', '--dport', '53', '-m', 'mark', '--mark', mark, '-j', 'REJECT'],
        ]
        try:
            if not all(_v4_subprocess.run(['iptables', '-w', '2'] + r, stdout=_v4_subprocess.DEVNULL, stderr=_v4_subprocess.DEVNULL, timeout=4).returncode == 0 for r in rules):
                return False
        except (OSError, _v4_subprocess.TimeoutExpired):
            return False
        listening, owned = self.listener_identity(protocol, int(port))
        if listening:
            return owned
        if _V4Path('/tmp/keenzoo_protocol_update.lockdir').exists():
            return False
        if _V4Path('/tmp/keenzoo_installing').exists():
            owner = self.deployment_owner()
            # A new worker is started by deploy only AFTER code/config copy.
            # An old worker must not revive a daemon while binaries are replaced.
            if owner is None or owner != self.deploy_owner:
                return False
        now = _v4_time.monotonic()
        if now - self.last_restart.get(protocol, -1000) < 90:
            return False
        self.last_restart[protocol] = now
        init = {'hysteria': 'S57hysteria', 'xray': 'S24xray', 'trojan': 'S22trojan'}[protocol]
        path = '/opt/etc/init.d/' + init
        try:
            if _v4_re.search(r'^\s*ENABLED\s*=\s*no\b', _V4Path(path).read_text(), _v4_re.M):
                return False
            _v4_subprocess.run([path, 'start'], stdin=_v4_subprocess.DEVNULL, stdout=_v4_subprocess.DEVNULL, stderr=_v4_subprocess.DEVNULL, timeout=8)
            return self.listener_identity(protocol, int(port))[1]  # Then health() must verify the actual DNS exchange.
        except (OSError, _v4_subprocess.TimeoutExpired):
            return False

    def choose(self, full=False, reason='control'):
        """One requested round, NOT a periodic polling loop.

        Only candidates verified in THIS round may be promoted. Saved pool
        metrics are diagnostic, never permission to use a 12-hour-old backup.
        """
        self.check_reason = reason
        active = self.active
        secure_active = bool(active and active[0] == '127.0.0.1')
        recovery = reason == 'primary-recovery' and active is not None
        if full or not self.initialized or (recovery and self.preferred is None):
            ports = list(self.cfg['ports'])
        elif recovery:
            ports = [self.preferred] if self.preferred in self.cfg['ports'] else []
        else:
            ports = [active[1]] if secure_active else []
        tested = set(ports)
        self.scan_local(ports)
        self.initialized = True
        if recovery:
            self.last_primary_probe = _v4_time.monotonic()
            self.last_primary_probe_epoch = _v4_time.time()
        # In event/control mode first confirm the active resolver. The failed
        # preferred resolver has its own five-minute timer, not every event.
        active_ok = secure_active and active[1] in tested and self.metrics[active[1]]['rtt'] is not None
        if not recovery and not active_ok and len(tested) < len(self.cfg['ports']):
            remaining = [p for p in self.cfg['ports'] if p not in tested]
            self.scan_local(remaining)
            tested.update(remaining)
        if len(tested) == len(self.cfg['ports']):
            self.last_pool = _v4_time.time()
            if self.preferred is None:
                self.last_primary_probe = _v4_time.monotonic()
                self.last_primary_probe_epoch = self.last_pool
        with self.guard:
            eligible = sorted((self.metrics[p]['rtt'], p) for p in tested if self.metrics[p]['rtt'] is not None)
        # Keep a working Primary sticky. Keep an already working local backup
        # until Primary recovers, rather than moving between backups for RTT.
        # An explicit rerank is the single exception: it re-evaluates the pure
        # fastest candidate and drops both active and backup stickiness.
        order = [p for _, p in eligible]
        if reason != 'rerank':
            # Insert preferred FIRST so the working active backup wins when
            # both are eligible: the recovery probe/rerank owns the return to
            # Primary; an event/pool scan must not cause a second switch.
            for port in (self.preferred, active[1] if secure_active else None):
                if port in order:
                    order.remove(port); order.insert(0, port)
        for port in order:
            target = ('127.0.0.1', port, False, 0)
            if target != active:
                # First positive was scan_local(); a second is required before
                # entering a different state/target, including initial startup.
                if self.health(target, True) is None:
                    with self.guard:
                        self.metrics[port] = {'rtt': None, 'at': _v4_time.time()}
                    continue
            if self.preferred is None or self.preferred not in self.cfg['ports']:
                self.preferred = port
            if port == self.preferred:
                self.last_primary_probe = _v4_time.monotonic()
                self.last_primary_probe_epoch = _v4_time.time()
            self.commit('LOCAL_DNSSEC', target)
            return
        if recovery:
            # Do NOT ping the working backup or all tunnels every five minutes.
            self.publish()
            return
        for protocol in V4_PRIORITY:
            if self.stop.is_set():
                return
            if not self.tunnel_ready(protocol):
                continue
            for host in self.cfg['bootstrap']:
                target = (host, 53, True, V4_MARKS[protocol])
                if self.target_ready(target, active):
                    self.commit('TUNNEL_DNS', target)
                    return
        for host in self.cfg['bootstrap']:
            for tcp in (False, True):
                target = (host, 53, tcp, V4_EMERGENCY_MARK)
                if self.target_ready(target, active):
                    self.commit('EMERGENCY_DNS', target)
                    return
        self.commit('DNS_UNAVAILABLE', None)

    def target_ready(self, target, active):
        result = self.health(target)
        if result is None:
            result = self.health(target)
        return result is not None and (target == active or self.health(target) is not None)

    def commit(self, mode, target):
        with self.guard:
            if target != self.active or mode != self.mode:
                self.generation += 1
                self.last_good = 0
                self.last_evidence_epoch = None
                self.pending_failure = False
            self.mode, self.active = mode, target
            self.last_checked = self.last_heartbeat = _v4_time.monotonic()
            self.last_control_epoch = _v4_time.time()
            if target:
                self.last_good = self.last_checked
                self.last_evidence_epoch = self.last_control_epoch
            else:
                self.last_primary_probe = self.last_checked
            self.next_event = max(self.next_event, self.last_checked +
                                  (self.EVENT_COOLDOWN if target else self.cfg.get('recovery_interval', 300)))
        self.publish()

    def publish(self):
        with self.guard:
            target, mode = self.active, self.mode
            protocol = next((p for p, mark in V4_MARKS.items() if target and target[3] == mark), None)
            state = {'version': 4, 'pid': _v4_os.getpid(), 'start': v4_identity(_v4_os.getpid()),
                     'epoch': int(_v4_time.time()), 'mode': mode, 'active': list(target) if target else None,
                     'preferred': self.preferred, 'tunnel': protocol, 'listen_port': V4_PORT,
                     'candidates': self.cfg['ports'], 'metrics': self.metrics, 'query_count': self.query_count,
                     'health_mode': 'hybrid', 'interval': self.cfg['interval'],
                     'pool_hours': self.cfg.get('pool_hours', [11, 23]),
                     'recovery_interval': self.cfg.get('recovery_interval', 300),
                     'next_pool_epoch': int(self.next_pool_epoch), 'last_pool_epoch': self.last_pool,
                     'last_evidence_epoch': self.last_evidence_epoch,
                     'last_control_epoch': self.last_control_epoch,
                     'last_primary_probe_epoch': self.last_primary_probe_epoch,
                     'health_query_count': self.health_query_count,
                     'passive_confirmations': self.passive_confirmations,
                     'failure_events': self.failure_events, 'check_reason': self.check_reason}
        path = _V4Path(self.state_path)
        fd, filename = _v4_temp.mkstemp(prefix=path.name+'.', dir=str(path.parent))
        try:
            with _v4_os.fdopen(fd, 'w') as stream:
                stream.write(_v4_json.dumps(state, separators=(',', ':')))
            _v4_os.replace(filename, path)
        finally:
            if _v4_os.path.exists(filename): _v4_os.unlink(filename)
        key = (mode, target, self.preferred)
        # Bound the same inode held by stdout, even during repeated flaps.
        if self.state_path == V4_STATE:
            logfile = _V4Path('/opt/var/log/unblock_dns_v4.log')
            try:
                if logfile.stat().st_size > 65536:
                    with logfile.open('rb') as stream:
                        stream.seek(-32768, 2); tail = stream.read()
                    logfile.write_bytes(tail)
            except OSError:
                pass
        if key != self.last_log:
            self.last_log = key
            # stdout goes to a bounded service log (only transitions, no names).
            print('DNSv4 mode=%s preferred=%s active=%s tunnel=%s' % (mode, self.preferred, target, protocol), flush=True)

    def request_check(self, network=False, rerank=False):
        with self.guard:
            was_pending = self.pending_network or self.pending_failure or self.pending_rerank
            if network:
                self.pending_network = True
            elif not rerank:
                self.pending_failure = True
            if rerank:
                self.pending_rerank = True
            if not was_pending:
                self.wake.set()

    def observe(self, query, response, target, generation, rtt):
        """No DNS I/O here. Only the exact current upstream may refresh proof.

        A positive, matching IN A answer with AD and CD=0 is suitable passive
        evidence. Unsigned domains, NXDOMAIN, CD=1 and non-A replies are NOT
        DNSSEC failures, and cannot indefinitely postpone the control timer.
        """
        flags = _v4_struct.unpack('!H', response[2:4])[0]
        qflags = _v4_struct.unpack('!H', query[2:4])[0]
        positive = False
        try:
            v4_answer(response, query, health=True, secure=self.mode == 'LOCAL_DNSSEC')
            positive = not bool(qflags & 0x0010)
        except ValueError:
            pass
        with self.guard:
            if self.active != target or self.generation != generation:
                return
            secure = self.mode == 'LOCAL_DNSSEC'
            if positive:
                self.last_good = _v4_time.monotonic()
                self.last_evidence_epoch = _v4_time.time()
                self.passive_confirmations += 1
                if secure:
                    self.metrics[target[1]] = {'rtt': rtt, 'at': self.last_evidence_epoch}
            # AD absence is meaningful only for the configured signed control
            # name with an explicit AD request and CD=0; never for arbitrary
            # unsigned names. A probe confirms every failure before switching.
            known_signed = (v4_question(query)[0] ==
                            (self.cfg.get('domain', 'example.com').encode('ascii').lower(), b'\0\x01\0\x01'))
            lost_ad = secure and known_signed and qflags & 0x0020 and not qflags & 0x0010 and not flags & 0x0020
            if flags & 15 in (2, 5) or lost_ad:
                self.failure_events += 1
                self.request_check()

    def forward(self, query, tcp=False):
        # Invalid client packets must not trigger health probes (DoS amplifier).
        try:
            v4_question(query)
            if query[2] & 0xf8:
                raise ValueError('invalid query opcode')
        except (ValueError, IndexError):
            return v4_fail(query)
        with self.guard:
            target, generation = self.active, self.generation
            fresh = _v4_time.monotonic() - self.last_heartbeat <= 180
            self.query_count += 1
        if not target or not fresh:
            self.request_check()
            return v4_fail(query)
        try:
            started = _v4_time.monotonic()
            response = self.exchange(query, *target)
            v4_answer(response, query)
            self.observe(query, response, target, generation, (_v4_time.monotonic()-started)*1000)
            return response
        except (OSError, ValueError, IndexError):
            with self.guard:
                if self.active == target and self.generation == generation:
                    self.failure_events += 1
                    self.request_check()
            return v4_fail(query)

    def listener_fingerprint(self):
        # Socket inode changes expose stubby/DoH restarts without querying DNS
        # or spawning pidof/netstat. Only local IPv4 listener ports are used.
        result = []
        ports = set(self.cfg['ports']) | set(self.cfg.get('targets', {}).values())
        for kind in ('tcp', 'udp'):
            try:
                for row in _V4Path('/proc/net/' + kind).read_text().splitlines()[1:]:
                    cols = row.split()
                    host, port = cols[1].split(':')
                    if host in ('0100007F', '00000000') and int(port, 16) in ports and cols[3] in ('0A', '07'):
                        result.append((kind, port, cols[9]))
            except (OSError, ValueError, IndexError):
                return None  # A failed proc read is not evidence of a restart.
        return tuple(sorted(result))

    def maintenance(self):
        if _V4Path('/opt/etc/unblock/.disabled').exists():
            self.stop.set(); return
        try:
            stat = _V4Path(V4_CONFIG).stat()
        except OSError:
            # A transiently unreadable config keeps the last validated values;
            # it must not mark a working resolver unavailable every tick.
            stat = None
        stamp = (stat.st_ino, stat.st_mtime_ns, stat.st_size) if stat is not None else self.config_stamp
        if stamp is not None and stamp != self.config_stamp:
            updated = v4_config()
            if updated != self.cfg:
                with self.guard:
                    self.cfg = updated
                    self.metrics = {}
                    self.next_pool_epoch = self.next_pool_time(_v4_time.time())
                self.request_check(network=True)
            self.config_stamp = stamp
        listeners = self.listener_fingerprint()
        if listeners is not None:
            if self.listener_stamp is not None and listeners != self.listener_stamp:
                self.request_check(network=True)
            self.listener_stamp = listeners

    def tick(self):
        """Deterministic scheduling step. Heartbeats never call choose()."""
        now, wall = _v4_time.monotonic(), _v4_time.time()
        self.last_heartbeat = now
        if wall < self.last_wall - 120:
            self.next_pool_epoch = self.next_pool_time(wall)
        self.last_wall = wall
        if self.network_event.is_set():
            self.network_event.clear(); self.request_check(network=True)
        if self.rerank.is_set():
            self.rerank.clear(); self.request_check(rerank=True)
        reason, full = None, False
        if not self.initialized:
            reason, full = 'startup', True
        elif wall >= self.next_pool_epoch:
            # A forward clock jump coalesces missed slots to ONE scan. A clock
            # rollback must not scan the same local calendar slot twice.
            slot = _v4_datetime.datetime.fromtimestamp(self.next_pool_epoch).strftime('%Y-%m-%d %H')
            self.next_pool_epoch = self.next_pool_time(wall)
            if slot > self.last_calendar_slot:
                self.last_calendar_slot = slot
                reason, full = 'scheduled-pool', True
        with self.guard:
            if reason is None and now >= self.next_event and (self.pending_network or self.pending_failure or self.pending_rerank):
                full = self.pending_network or self.pending_rerank
                reason = 'rerank' if self.pending_rerank else ('network-event' if full else 'client-error')
                if self.pending_rerank:
                    self.preferred = None
                self.pending_network = self.pending_failure = self.pending_rerank = False
                self.next_event = now + self.EVENT_COOLDOWN
            active_primary = self.active == ('127.0.0.1', self.preferred, False, 0)
            recovery_due = not active_primary and now - self.last_primary_probe >= self.cfg.get('recovery_interval', 300)
            if reason is None and recovery_due:
                reason = 'primary-recovery'
                full = self.active is None
            if reason is None and self.active and now - max(self.last_good, self.last_checked) >= self.cfg['interval']:
                reason = 'idle-control'
        if reason:
            if full:
                with self.guard:
                    if self.pending_rerank:
                        self.preferred = None
                    self.pending_network = self.pending_failure = self.pending_rerank = False
            self.choose(full=full, reason=reason)
        # Bound status age independently of the hour-long health interval.
        # publish() does local atomic file replacement, no DNS requests.
        self.publish()
        now = _v4_time.monotonic()
        waits = [self.HEARTBEAT, max(.05, self.next_pool_epoch - _v4_time.time())]
        with self.guard:
            if self.pending_network or self.pending_failure or self.pending_rerank:
                waits.append(max(.05, self.next_event - now))
            if self.active != ('127.0.0.1', self.preferred, False, 0):
                waits.append(max(.05, self.last_primary_probe + self.cfg.get('recovery_interval', 300) - now))
            if self.active:
                waits.append(max(.05, max(self.last_good, self.last_checked) + self.cfg['interval'] - now))
        return min(waits)

    def monitor(self):
        while not self.stop.is_set():
            self.wake.clear()
            try:
                now = _v4_time.monotonic()
                if self.last_maintenance is None or now-self.last_maintenance >= self.HEARTBEAT:
                    self.maintenance()
                    self.last_maintenance = now
                if self.stop.is_set():
                    break
                delay = self.tick()
            except Exception as exc:
                self.commit('DNS_UNAVAILABLE', None)
                print('DNSv4 monitor error=%s' % type(exc).__name__, flush=True)
                delay = self.HEARTBEAT
            self.wake.wait(delay)


class _V4Bounded(_v4_server.ThreadingMixIn):
    daemon_threads = True
    allow_reuse_address = True
    def process_request(self, request, address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release(); raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()
    def handle_error(self, request, address):
        pass


class V4UDP(_V4Bounded, _v4_server.UDPServer):
    max_packet_size = 65535


class V4TCP(_V4Bounded, _v4_server.TCPServer):
    request_queue_size = 32


class V4UDPHandler(_v4_server.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        result = self.server.policy.forward(data)
        if result:
            sock.sendto(result, self.client_address)


class V4TCPHandler(_v4_server.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        size = _v4_struct.unpack('!H', v4_recv(self.request, 2))[0]
        data = v4_recv(self.request, size)
        result = self.server.policy.forward(data, True)
        if result:
            self.request.sendall(_v4_struct.pack('!H', len(result)) + result)


def v4_shell(state):
    mode = state.get('mode', 'DNS_UNAVAILABLE')
    if mode not in ('LOCAL_DNSSEC', 'TUNNEL_DNS', 'EMERGENCY_DNS'):
        mode = 'DNS_UNAVAILABLE'
    tunnel = state.get('tunnel') if mode == 'TUNNEL_DNS' else ''
    if mode == 'TUNNEL_DNS' and tunnel not in V4_PRIORITY:
        mode, tunnel = 'DNS_UNAVAILABLE', ''
    port = str(V4_PORT)  # Keep dnsmasq attached during outage/recovery.
    fields = {'DNS_MODE': mode, 'DNS_PRIMARY_LEVEL': 'DNSSEC_OK' if mode == 'LOCAL_DNSSEC' else mode,
              'DNS_PRIMARY': port, 'DNS_WORKING_PORTS': port, 'DNS_BACKUP_PORTS': '', 'DNS_PRIMARY_RTT_MS': '',
              'DNS_SECURE_PORTS': port if mode == 'LOCAL_DNSSEC' else '',
              'DNS_INSECURE_PORTS': port if mode in ('TUNNEL_DNS', 'EMERGENCY_DNS') else '',
              'DNS_TUNNEL_REQUIRED': int(mode == 'TUNNEL_DNS'), 'DNS_TUNNEL_READY': int(mode == 'TUNNEL_DNS'),
              'DNS_TUNNEL_PROTOCOL': tunnel or '', 'DNS_RANKING': ''}
    return '\n'.join("%s='%s'" % (k, v) for k, v in fields.items())


def v4_main(command):
    _v4_os.umask(0o077)
    if command == '--dns-status':
        print(_v4_json.dumps(v4_status(), indent=2)); return 0
    if command == '--dns-shell':
        print(v4_shell(v4_status())); return 0
    if command in ('--dns-rerank', '--dns-event'):
        state = v4_status()
        if not state: return 1
        _v4_os.kill(state['pid'], _v4_signal.SIGUSR1 if command == '--dns-rerank' else _v4_signal.SIGUSR2)
        return 0
    if command == '--dns-stop':
        state = v4_status(check_age=False)
        if state:
            _v4_os.kill(state['pid'], _v4_signal.SIGTERM)
            for _ in range(50):
                if not v4_status(check_age=False):
                    return 0
                _v4_time.sleep(.1)
            return 1
        return 0
    if _V4Path('/opt/etc/unblock/.disabled').exists():
        return 1
    if command == '--dns-start':
        if v4_status():
            return 0
        if v4_status(check_age=False) and v4_main('--dns-stop') != 0:
            return 1
        # Validate config before spawning; no imports/credentials executed.
        v4_config()
        log = _V4Path('/opt/var/log/unblock_dns_v4.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        if log.exists() and log.stat().st_size > 65536:
            with log.open('rb') as stream:
                stream.seek(-32768, 2); tail = stream.read()
            log.write_bytes(tail)
        with log.open('ab') as out:
            _v4_subprocess.Popen([_v4_sys.executable, '-u', __file__, '--dns-run'], start_new_session=True,
                                stdin=_v4_subprocess.DEVNULL, stdout=out, stderr=out,
                                env={k: v for k, v in _v4_os.environ.items() if k not in ('KEENZOO_UPDATE_LOCK_HELD', 'KEENZOO_LOCK_DIR', 'KEENZOO_DNS_STAGE', 'DNS_HEALTH_LOG')})
        for _ in range(50):
            if v4_status():
                return 0
            _v4_time.sleep(.1)
        return 1
    if command != '--dns-run':
        return 2
    lock_fd = _v4_os.open(V4_LOCK, _v4_os.O_CREAT | _v4_os.O_RDWR | _v4_os.O_NOFOLLOW, 0o600)
    with _v4_os.fdopen(lock_fd, 'a') as lock:
        if _v4_os.fstat(lock.fileno()).st_uid != _v4_os.geteuid():
            raise ValueError('unsafe DNS lock ownership')
        try:
            _v4_fcntl.flock(lock, _v4_fcntl.LOCK_EX | _v4_fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        policy = DNSPolicyV4(v4_config())
        slots = _v4_thread.BoundedSemaphore(24)
        with V4UDP(('127.0.0.1', V4_PORT), V4UDPHandler) as udp, V4TCP(('127.0.0.1', V4_PORT), V4TCPHandler) as tcp:
            for server in (udp, tcp):
                server.policy, server.slots = policy, slots
                _v4_thread.Thread(target=server.serve_forever, daemon=True).start()
            for sig in (_v4_signal.SIGTERM, _v4_signal.SIGINT):
                _v4_signal.signal(sig, lambda *_: (policy.stop.set(), policy.wake.set()))
            _v4_signal.signal(_v4_signal.SIGUSR1, lambda *_: (policy.rerank.set(), policy.wake.set()))
            _v4_signal.signal(_v4_signal.SIGUSR2, lambda *_: (policy.network_event.set(), policy.wake.set()))
            policy.publish()
            worker = _v4_thread.Thread(target=policy.monitor, daemon=True)
            worker.start()
            while not policy.stop.wait(1):
                if not worker.is_alive():
                    raise RuntimeError("DNS monitor stopped")
            for server in (udp, tcp):
                server.shutdown()
        try:
            _V4Path(V4_STATE).unlink()
        except FileNotFoundError:
            pass
        return 0


if __name__ == '__main__' and len(_v4_sys.argv) == 2 and _v4_sys.argv[1].startswith('--dns-'):
    try:
        raise SystemExit(v4_main(_v4_sys.argv[1]))
    except Exception as _v4_error:
        print('DNSv4 error: %s' % type(_v4_error).__name__, file=_v4_sys.stderr)
        raise SystemExit(1)
# --- end KeenZOO DNS policy v4 ---

import os
import signal
import time
import subprocess
import json
import re
import socket
import requests
import urllib3
import gc
import tempfile
import shutil
import html
from urllib.parse import (
    urlparse, parse_qs, unquote)
import base64
from collections import deque
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
                lines = deque(f, maxlen=keep_lines)
            with open(log_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
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
    """
    Ранее функция скачивала script.sh с внешнего URL и делала его
    исполняемым, после чего бот запускал его с правами root без проверки
    подписи. Внешний источник удалён: используются только локальные
    скрипты из /opt/bin, поставляемые вместе с проектом.
    Возвращает путь к локальному установочному скрипту.
    """
    deploy = config.paths.get(
        "deploy_script", "/opt/bin/deploy_bypass.sh")
    if not os.path.exists(deploy):
        raise FileNotFoundError(
            f"Не найден локальный скрипт: {deploy}")
    try:
        os.chmod(deploy, 0o755)
    except OSError as e:
        log_error(f"chmod {deploy}: {e}")
    return deploy


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


def _preflight_hysteria(tmp_path):
    """Проверка нативного конфига Hysteria2: 'hysteria client -c <файл> --help'
    не валидирует, поэтому используется JSON-схема + обязательные поля."""
    binary = _find_binary(
        'hysteria', ['/opt/sbin/hysteria', '/opt/bin/hysteria'])

    try:
        with open(tmp_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Hysteria: некорректный JSON: {e}")

    if not data.get('server'):
        raise ValueError("Hysteria: не задан server")
    if not data.get('auth'):
        raise ValueError("Hysteria: не задан auth")
    if not isinstance(data.get('tcpRedirect'), dict):
        raise ValueError("Hysteria: отсутствует tcpRedirect")
    if not isinstance(data.get('udpTProxy'), dict):
        raise ValueError("Hysteria: отсутствует udpTProxy (UDP не пойдёт в туннель)")

    if not binary:
        log_error(
            "Preflight: hysteria не найден, проверка бинарником пропущена")
        return


def _preflight_trojan(tmp_path):
    """Структурная проверка Trojan; init дополнительно выполняет trojan -t."""
    try:
        with open(tmp_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Trojan: некорректный JSON: {e}")

    # Здесь важно именно OR: конфиг непригоден, если отсутствует ХОТЯ БЫ
    # одно из обязательных полей (раньше проверка через AND пропускала
    # конфиги без remote_addr или без пароля).
    if (not data.get('remote_addr')
            or not data.get('remote_port')
            or not data.get('password')):
        raise ValueError(
            "Trojan: нужны remote_addr, remote_port и password")

    ssl = data.get('ssl', {})
    if not isinstance(ssl, dict):
        raise ValueError("Trojan: ssl должен быть объектом")
    if ssl.get('verify', True):
        cert = ssl.get('cert', '')
        if not cert:
            raise ValueError(
                "Trojan: ssl.cert не задан; нужен CA bundle "
                "/opt/etc/ssl/certs/ca-certificates.crt")
        if not os.path.isfile(cert):
            raise ValueError(
                f"Trojan: CA bundle не найден: {cert}")


def _preflight_shadowsocks(tmp_path):
    """Структурная проверка конфига shadowsocks-libev."""
    try:
        with open(tmp_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Shadowsocks: некорректный JSON: {e}")

    if not data.get('server'):
        raise ValueError("Shadowsocks: не задан server")
    if not data.get('server_port'):
        raise ValueError("Shadowsocks: не задан server_port")
    if not data.get('password'):
        raise ValueError("Shadowsocks: не задан password")
    if not data.get('method'):
        raise ValueError("Shadowsocks: не задан method")


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


def _refresh_pins_if_needed(file_path):
    """
    Перечитать адреса серверов после изменения конфига протокола.

    Пиннинг хранит IP серверов в /opt/etc/hosts, а туннели ходят именно
    по ним. Пин и canonical DNS обновляются при изменении конфигурации,
    подъёме WAN и штатном обновлении списков, поэтому после ввода нового
    ключа не нужно ждать следующего суточного цикла. Запускается в фоне —
    вызывающий код (панель,
    бот) не должен ждать сетевых запросов.
    """
    watched = (
        config.paths.get("vless_config"),
        config.paths.get("hysteria_config"),
        config.paths.get("trojan_config"),
        config.paths.get("shadowsocks_config"),
    )
    try:
        real = os.path.realpath(file_path)
    except Exception:
        real = file_path
    hit = False
    for w in watched:
        if not w:
            continue
        try:
            if os.path.realpath(w) == real:
                hit = True
                break
        except Exception:
            if w == file_path:
                hit = True
                break
    if not hit:
        return

    script = config.paths.get(
        "unblock_dnsmasq", "/opt/bin/unblock_dnsmasq.sh")
    if not os.path.exists(script):
        return
    try:
        # start_new_session отвязывает процесс: панель может быть
        # перезапущена, а обновление пина обязано завершиться.
        subprocess.Popen(
            [script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True)
    except Exception as e:
        log_error(f"pin refresh ({script}): {e}")


def _mark_tunnel_configured(file_path):
    """Record that this tunnel config was explicitly submitted by a user.

    A syntactically complete JSON file can survive from an older /opt or from
    a sample archive. The init guards must not treat that alone as permission
    to open a tunnel listener. The marker is deliberately a sidecar so it is
    not passed to xray, Trojan, or Hysteria as an unknown JSON field.
    """
    configured_dir = config.get(
        'tunnel_configured_dir', '/opt/etc/unblock/.configured') \
        if isinstance(config, dict) else getattr(
            config, 'tunnel_configured_dir',
            '/opt/etc/unblock/.configured')
    configured_dir = str(configured_dir)
    target = os.path.realpath(file_path)
    mapping = {
        os.path.realpath(config.paths.get('vless_config', '')): 'xray',
        os.path.realpath(config.paths.get('trojan_config', '')): 'trojan',
        os.path.realpath(config.paths.get('hysteria_config', '')): 'hysteria',
    }
    service = mapping.get(target)
    if not service:
        return
    os.makedirs(configured_dir, exist_ok=True)
    marker = os.path.join(configured_dir, service)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f'.{service}.', suffix='.tmp', dir=configured_dir)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as marker_file:
            marker_file.write('configured=1\n')
            marker_file.flush()
            os.fsync(marker_file.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, marker)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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

            # Preflight выполняется на ВРЕМЕННОМ файле: боевой конфиг
            # заменяется только после успешной проверки, поэтому неудачная
            # генерация не оставляет сервис с нерабочим конфигом.
            real_path = os.path.realpath(file_path)
            checks = {
                os.path.realpath(config.paths.get('vless_config', '')):
                    _preflight_xray,
                os.path.realpath(config.paths.get('tor_config', '')):
                    _preflight_tor,
                os.path.realpath(config.paths.get('hysteria_config', '')):
                    _preflight_hysteria,
                os.path.realpath(config.paths.get('trojan_config', '')):
                    _preflight_trojan,
                os.path.realpath(config.paths.get('shadowsocks_config', '')):
                    _preflight_shadowsocks,
            }
            checker = checks.get(real_path)
            if checker is not None:
                checker(tmp_path)

            os.replace(tmp_path, file_path)
            # Do not let a preserved or hand-copied complete JSON authorize
            # a listener. This marker exists only after the bot/web config
            # submission itself has succeeded.
            _mark_tunnel_configured(file_path)

            # Адрес сервера в конфиге только что мог смениться, а в
            # /opt/etc/hosts остался пин от прежнего ключа. Туннель пошёл
            # бы на старый IP, и обход молча не работал бы до 06:00.
            # Обновляем закреплённые адреса сразу после записи конфига
            # любого из протоколов, к которым применяется пиннинг.
            _refresh_pins_if_needed(file_path)

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


def _endpoint_host(value):
    """Extract a host from a direct-config host or host:port value."""
    if not isinstance(value, str):
        return ''
    value = value.strip()
    if value.startswith('['):
        host, sep, _port = value[1:].partition(']')
        return host if sep else value
    if value.count(':') == 1:
        host, port = value.rsplit(':', 1)
        if port.isdigit():
            return host
    return value


def _reject_endpoint_ipv6(value, context="адрес сервера"):
    _reject_ipv6_host(_endpoint_host(value), context)


def _endpoint_port(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith('['):
        end = value.find(']')
        if end < 0:
            return None
        value = value[end + 1:]
        if value.startswith(':'):
            return value[1:]
        return None
    if value.count(':') == 1:
        return value.rsplit(':', 1)[1]
    return None


def _validate_port(value, context="порт"):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Некорректный {context}: {value}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Некорректный {context}: {value}")
    return port


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
    port = 443 if parsed_url.port is None else parsed_url.port
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
    # Ключи из HTML/Telegram иногда содержат &amp; вместо '&'.
    # Нормализуем только URL-сущности, сохраняя пароль, SNI и path.
    key = key.strip()
    # Поддерживаем как обычный URL из Telegram, так и дважды HTML-
    # экранированный вариант (&amp;amp;), который появляется после
    # последовательного копирования через HTML/Markdown.
    for _ in range(3):
        _decoded_key = html.unescape(key)
        if _decoded_key == key:
            break
        key = _decoded_key
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
    # Проверка сертификата отключается ТОЛЬКО при явном allowInsecure=1
    # в ссылке. По умолчанию (в т.ч. при отсутствии параметра) — включена:
    # прежде шаблон трояна жёстко получал verify=false, что снимало защиту
    # от подмены сертификата на всём трафике Trojan.
    result['verify'] = (
        'false'
        if str(result['allowInsecure']).lower() in ('1', 'true', 'yes')
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
        'httpupgradeSettings',
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



# Ключи, значения которых подставляются в шаблон как «сырой» JSON
# (числа, булевы литералы, готовые списки alpn), а не как строка.
_JSON_RAW_KEYS = {
    'insecure', 'alpn', 'ws_enabled',
    'verify', 'localportvless',
    'localporttrojan', 'localportsh',
    'localporthysteria',
}

# Значения этих ключей формируются кодом, а не пользователем.
_JSON_RAW_ALLOWED = {
    'true', 'false', '',
}


def _tpl_value(key, value):
    """
    Готовит значение к подстановке в JSON-шаблон.

    Строки экранируются через json.dumps (кавычки, обратные слеши,
    переводы строк). Прежняя версия для «сырых» ключей возвращала
    str(value) без проверки, поэтому специально сформированный ключ
    (например, alpn с кавычкой) ломал структуру JSON или позволял
    дописать в конфиг произвольные поля.
    """
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)

    if key in _JSON_RAW_KEYS:
        raw = str(value)
        if raw in _JSON_RAW_ALLOWED:
            return raw
        if raw.lstrip('-').isdigit():
            return raw
        if key == 'alpn':
            # alpn собирается из уже проверенных токенов вида "h3", "h2".
            parts = []
            for token in raw.split(','):
                token = token.strip().strip('"')
                if not token:
                    continue
                if not re.match(r'^[A-Za-z0-9.\-/]+$', token):
                    raise ValueError(
                        f"Недопустимое значение alpn: {token}")
                parts.append(json.dumps(token, ensure_ascii=False))
            return ', '.join(parts)
        raise ValueError(
            f"Недопустимое значение поля {key}: {raw}")

    return json.dumps(
        str(value), ensure_ascii=False)[1:-1]


def _ensure_xray_quiet_log(parsed):
    """
    Ограничивает журналирование xray. Без секции "log" xray пишет
    предупреждения и, при access-логе, строку на КАЖДОЕ соединение —
    на накопителе с Entware это быстро съедает место. Оставляем
    только ошибки, access-лог отключаем.
    """
    if not isinstance(parsed, dict):
        return parsed
    log = parsed.get('log')
    if not isinstance(log, dict):
        log = {}
    log['access'] = 'none'
    log['loglevel'] = 'error'
    # Пустая строка означает вывод в stdout; оставляем как есть, если
    # путь задан пользователем осознанно.
    if not log.get('error'):
        log['error'] = ''
    parsed['log'] = log
    return parsed



def _xray_version_known():
    """Return True only when the installed Xray version is observable.

    Removing a user-supplied Xray dns block changes runtime DNS semantics.
    Do not perform that migration when the binary is absent or its CLI
    format is unknown; preserving the block is safer than guessing.
    """
    binary = _find_binary(
        'xray', ['/opt/sbin/xray', '/opt/bin/xray'])
    if not binary:
        return False
    for args in ([binary, 'version'], [binary, '--version']):
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        text = (result.stdout or '') + '\n' + (result.stderr or '')
        if result.returncode == 0 and re.search(
                r'\b[0-9]+\.[0-9]+\.[0-9]+\b', text):
            return True
    return False


# Ownership is explicit rather than inferred from nameservers or ports:
# a user may legitimately run a local resolver on the same address. These
# markers are carried by the project-managed Xray dns object and are removed
# before the config is written to Xray, so they never become runtime fields.
_XRAY_PROJECT_DNS_MARKERS = frozenset((
    'keenzoo',
    'keenzoo-dns',
    'keenzoo-managed-dns',
    'KeenZOO managed DNS',
))


def _xray_dns_block_owned(parsed):
    """Return True only for an explicitly project-owned Xray dns block."""
    if not isinstance(parsed, dict):
        return False
    dns = parsed.get('dns')
    if not isinstance(dns, dict):
        return False

    # ``tag`` is the Xray-native identity field. ``owner`` and ``managedBy``
    # are accepted for configs produced by older project revisions; they are
    # not guessed from arbitrary server addresses.
    for key in ('tag', 'owner', 'managedBy'):
        marker = dns.get(key)
        if isinstance(marker, str) and marker.strip() in \
                _XRAY_PROJECT_DNS_MARKERS:
            return True
    # A JSON-side marker is useful for migrations and is deliberately strict:
    # only the literal boolean True grants ownership.
    return dns.get('_keenzoo_managed') is True


def _remove_xray_dns_block(parsed):
    """Remove only project-owned Xray DNS objects after a version check.

    DNS clients are intended to use the system DoH/DoT proxy through
    dnsmasq. A user-provided Xray dns block is preserved, even when Xray's
    version is known, unless its explicit ownership marker is present. This
    prevents a config migration from silently changing user DNS semantics.
    """
    if not isinstance(parsed, dict):
        return parsed
    if 'dns' not in parsed:
        return parsed
    if not _xray_dns_block_owned(parsed):
        log_error(
            "Xray dns block preserved: ownership marker is absent")
        return parsed
    if not _xray_version_known():
        log_error(
            "Xray dns block preserved: version check unavailable")
        return parsed

    # Delete only after both guards pass. The associated inbound tags are
    # project-owned by definition of the same migration and are never
    # touched in a user-owned config.
    parsed.pop('dns', None)
    inbounds = parsed.get('inbounds')
    if isinstance(inbounds, list):
        parsed['inbounds'] = [
            ib for ib in inbounds
            if not (isinstance(ib, dict)
                    and ib.get('tag') in (
                        'dns-tunnel-tcp', 'dns-tunnel-udp'))]
    return parsed


def _ensure_xray_tproxy(parsed):
    """
    Гарантирует наличие двух inbound-ов dokodemo-door на порту
    config.localportvless:
      * TCP — приходит через nat/REDIRECT, sockopt.tproxy = "redirect";
      * UDP — приходит через mangle/TPROXY, sockopt.tproxy = "tproxy".

    Оба слушают один и тот же порт: TCP- и UDP-сокеты не конфликтуют,
    а правило TPROXY в 100-redirect.sh использует тот же номер порта.
    Без UDP-инбаунда весь UDP-трафик ресурсов из vless.txt (QUIC/HTTP3,
    DNS, игровой трафик, звонки) уходил мимо туннеля.

    Функция вызывается и при генерации из шаблона, и при вставке готового
    конфига через бота/веб-панель, поэтому UDP-инбаунд не теряется при
    смене ключа.
    """
    if not isinstance(parsed, dict):
        return parsed

    port = int(config.localportvless)
    inbounds = parsed.setdefault('inbounds', [])
    if not isinstance(inbounds, list):
        inbounds = []
        parsed['inbounds'] = inbounds

    # Убрать ранее добавленные служебные inbound-ы, чтобы не плодить дубли.
    inbounds[:] = [
        ib for ib in inbounds
        if not isinstance(ib, dict)
        or ib.get('tag') not in (
            'vless-udp-tproxy', 'vless-tcp-redirect')
    ]

    base = None
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        try:
            ib_port = int(ib.get('port', 0))
        except (TypeError, ValueError):
            continue
        if (ib.get('protocol') == 'dokodemo-door'
                and ib_port == port):
            base = ib
            break

    if base is None:
        base = {
            'port': port,
            # IPv6 на роутере отключён — слушаем только IPv4.
            'listen': '0.0.0.0',
            'protocol': 'dokodemo-door',
            'settings': {},
            'sniffing': {
                'enabled': True,
                'destOverride': ['http', 'tls', 'quic'],
            },
        }
        inbounds.insert(0, base)

    base['tag'] = 'vless-tcp-redirect'
    base['port'] = port
    base['listen'] = '0.0.0.0'
    base['protocol'] = 'dokodemo-door'
    base.setdefault('settings', {})
    base['settings']['network'] = 'tcp'
    base['settings']['followRedirect'] = True
    base.setdefault('sniffing', {})
    base['sniffing']['enabled'] = True
    base['sniffing']['destOverride'] = ['http', 'tls', 'quic']
    base.setdefault('streamSettings', {})
    base['streamSettings'].setdefault('sockopt', {})
    base['streamSettings']['sockopt']['tproxy'] = 'redirect'

    udp = json.loads(json.dumps(base))
    udp['tag'] = 'vless-udp-tproxy'
    udp['settings']['network'] = 'udp'
    udp['settings']['followRedirect'] = True
    # Для UDP важен sniffing по QUIC, иначе маршрутизация по доменам
    # для HTTP/3 работать не будет.
    udp['sniffing'] = {
        'enabled': True,
        'destOverride': ['quic'],
    }
    udp['streamSettings']['sockopt']['tproxy'] = 'tproxy'
    inbounds.append(udp)

    # DNS listener Xray не создаётся: dnsmasq использует системные
    # DoH/DoT upstream-ы, а их внешние TCP/443 и TCP/853 соединения
    # перенаправляет 100-redirect.sh в активный tunnel.  Migration of an
    # existing dns block is performed by the outer config path only after
    # the Xray version check.
    _ensure_xray_udp_routing(parsed)

    # Пакеты, которые xray отправляет наружу, помечаются XRAY_SOCK_MARK.
    # Правило OUTPUT в 100-redirect.sh делает RETURN по этой метке, иначе
    # исходящий трафик самого xray заворачивался бы в его же inbound
    # (bot.txt перехватывается в OUTPUT) и получалась бы петля.
    _ensure_xray_outbound_mark(parsed)

    return parsed


# Должно совпадать с XRAY_MARK в /opt/etc/ndm/netfilter.d/100-redirect.sh
XRAY_SOCK_MARK = 0x2000000


def _ensure_xray_outbound_mark(parsed):
    """
    Проставляет sockopt.mark всем исходящим соединениям xray, кроме
    blackhole (у него нет сетевого выхода).
    """
    for ob in parsed.get('outbounds') or []:
        if not isinstance(ob, dict):
            continue
        # 'type' — вариант ключа в sing-box-конфигах.
        if (ob.get('protocol') or ob.get('type')) == 'blackhole':
            continue
        ss = ob.setdefault('streamSettings', {})
        sockopt = ss.setdefault('sockopt', {})
        sockopt['mark'] = XRAY_SOCK_MARK

    return parsed


def _ensure_xray_udp_routing(parsed):
    """
    Проверяет, что в routing нет правил, отбрасывающих UDP, и что
    существует общее правило на прокси-outbound. Без него UDP-инбаунд
    работал бы «в никуда» при конфигах, где правила заданы только для TCP.
    """
    outbounds = parsed.get('outbounds') or []
    if not outbounds:
        return parsed

    # Протокол берётся из 'protocol' (xray) либо 'type' (sing-box): при
    # вставке готового блока outbounds sing-box-конфига ключа 'protocol'
    # нет, из-за чего proxy_tag не находился и UDP-правило не добавлялось —
    # UDP из vless.txt приходил в inbound и отбрасывался за отсутствием
    # маршрута.
    proxy_kinds = ('vless', 'vmess', 'trojan', 'shadowsocks')
    direct_kinds = ('freedom', 'direct', 'blackhole', 'dns')

    proxy_tag = None
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        kind = ob.get('protocol') or ob.get('type')
        if kind in proxy_kinds:
            proxy_tag = ob.get('tag') or 'proxy'
            ob['tag'] = proxy_tag
            break

    if not proxy_tag:
        # Протокол не распознан (нестандартный или новый) — берём первый
        # outbound, который заведомо не является прямым выходом.
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            kind = ob.get('protocol') or ob.get('type')
            if kind in direct_kinds:
                continue
            proxy_tag = ob.get('tag') or 'proxy'
            ob['tag'] = proxy_tag
            break

    if not proxy_tag:
        return parsed

    routing = parsed.get('routing')
    if not isinstance(routing, dict):
        routing = {}
        parsed['routing'] = routing
    routing.setdefault('domainStrategy', 'IPIfNonMatch')
    rules = routing.setdefault('rules', [])
    if not isinstance(rules, list):
        rules = []
        routing['rules'] = rules

    has_catch_all = any(
        r.get('outboundTag') == proxy_tag
        and r.get('port') in ('0-65535', None)
        and not r.get('network')
        for r in rules
        if isinstance(r, dict))

    has_udp_rule = any(
        isinstance(r, dict)
        and 'udp' in str(r.get('network', ''))
        and r.get('outboundTag') == proxy_tag
        for r in rules)

    if not has_catch_all and not has_udp_rule:
        rules.append({
            'type': 'field',
            'network': 'udp,tcp',
            'outboundTag': proxy_tag,
        })

    return parsed


def _ensure_hysteria_tproxy(parsed):
    """
    Приводит нативный конфиг Hysteria2 к режиму прозрачного проксирования:
      * tcpRedirect — приём TCP из nat/REDIRECT;
      * udpTProxy   — приём UDP из mangle/TPROXY.

    Оба слушателя используют один порт config.localporthysteria, тот же,
    что указан в правилах 100-redirect.sh. Раньше udpTProxy мог
    отсутствовать (например, при вставке готового конфига), и весь UDP
    ресурсов из hysteria.txt шёл напрямую, минуя туннель.
    """
    if not isinstance(parsed, dict):
        return parsed

    port = int(config.localporthysteria)
    listen = f'0.0.0.0:{port}'

    tcp = parsed.get('tcpRedirect')
    if not isinstance(tcp, dict):
        tcp = {}
        parsed['tcpRedirect'] = tcp
    udp = parsed.get('udpTProxy')
    if not isinstance(udp, dict):
        udp = {}
        parsed['udpTProxy'] = udp
    tcp['listen'] = listen
    udp['listen'] = listen

    # Таймаут UDP-сессий: значение по умолчанию у hysteria велико для
    # роутера, 60 секунд достаточно для игр и звонков.
    parsed['udpTProxy'].setdefault('timeout', '60s')

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
            parsed = _remove_xray_dns_block(parsed)
            parsed = _ensure_xray_quiet_log(parsed)
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
    port = _validate_port(sb.get('server_port', 443), 'server_port')
    uuid = sb.get('uuid', '')
    flow = sb.get('flow', '')
    if not server:
        raise ValueError("Нет server")
    _reject_endpoint_ipv6(server, "server")
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
    # Параметры переносятся БЕЗ самодеятельности: сервер сверяет их при
    # рукопожатии, и любая подстановка «разумного» значения приводит к
    # отказу в подключении. Поэтому поля, которых нет во входном конфиге,
    # не выдумываются, а просто не попадают в выход.
    fp = utls.get('fingerprint', tls.get('fingerprint', ''))
    transport = sb.get('transport', {})
    if not isinstance(transport, dict):
        raise ValueError("transport должен быть объектом")
    network = transport.get('type', 'tcp')

    def _singbox_text(value, field):
        """Normalize scalar fields from subscription JSON variants.

        Xray expects WS Host and xhttp/httpupgrade host as strings. Some
        sing-box/Clash converters emit a one-item JSON array instead. Accept
        that harmless variant, but reject multiple values instead of writing
        an invalid Xray config or silently choosing the wrong Host.
        """
        if value is None:
            return ''
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            if not value:
                return ''
            if len(value) == 1 and isinstance(value[0], str):
                return value[0]
        raise ValueError(
            f"{field} должен быть строкой или массивом из одной строки")

    headers = transport.get('headers', {})
    if headers is None:
        headers = {}
    if not isinstance(headers, dict):
        raise ValueError("transport.headers должен быть объектом")
    header_host = _singbox_text(
        headers.get('Host', headers.get('host', '')),
        'transport.headers.Host')
    explicit_host = (_singbox_text(
        transport.get('host'), 'transport.host')
        if 'host' in transport else header_host)

    stream = {
        "network": network,
        "security": security,
    }
    if security == 'reality':
        rs = {
            "publicKey": reality.get('public_key', ''),
            "serverName": sni,
            "shortId": reality.get('short_id', ''),
        }
        # fingerprint подставлять нельзя: 'chrome' вместо заданного 'qq'
        # меняет отпечаток TLS ClientHello, и Reality-сервер отвергает
        # соединение. Ключ добавляется, только если задан пользователем.
        if fp:
            rs["fingerprint"] = fp
        # spiderX ("/") раньше добавлялся всегда. Это параметр Reality,
        # который сервер учитывает; навязывать его нельзя.
        spx = reality.get('spider_x', reality.get('spiderX', ''))
        if spx:
            rs["spiderX"] = spx
        stream["realitySettings"] = rs
    elif security == 'tls':
        ts = {"serverName": sni}
        if fp:
            ts["fingerprint"] = fp
        # insecure из входного конфига раньше игнорировался: жёстко
        # писалось allowInsecure=False, и конфиг с самоподписанным
        # сертификатом переставал работать.
        ts["allowInsecure"] = bool(tls.get('insecure', False))
        alpn = tls.get('alpn')
        if alpn:
            ts["alpn"] = alpn if isinstance(alpn, list) else [alpn]
        stream["tlsSettings"] = ts
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
                # Xray's wsSettings.headers.Host is a string. A number of
                # subscription JSONs use ["host"] here; header_host above
                # normalizes that one-item form before serialization.
                "Host": header_host,
            },
        }
    elif network == 'xhttp':
        # Транспорт xhttp (бывший splithttp). Без этого блока xray
        # получал "network": "xhttp" БЕЗ настроек: path и mode терялись,
        # клиент стучался в корень "/" вместо рабочего пути, и сервер
        # рвал соединение. Шаблон vless_template.json xhttpSettings уже
        # умеет — ссылки vless:// работали, а JSON sing-box нет.
        stream["xhttpSettings"] = {
            "mode": transport.get('mode', 'auto'),
            "path": transport.get('path', '/'),
            "host": explicit_host,
        }
    elif network == 'httpupgrade':
        stream["httpupgradeSettings"] = {
            "path": transport.get('path', '/'),
            "host": explicit_host,
        }
    elif network not in ('tcp', ''):
        # Неизвестный транспорт молча пропускать нельзя: xray получит
        # network без соответствующих настроек и будет подключаться
        # неверно. Лучше отказать сразу с понятным текстом.
        raise ValueError(
            f"Транспорт '{network}' не поддерживается. "
            "Поддерживаются: tcp, ws, grpc, xhttp, httpupgrade.")
    user = {
        "id": uuid,
        # encryption обязателен для vless и всегда "none" по спецификации
        # протокола — это не подстановка, а требование формата xray.
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
        # Inbound-ы (TCP redirect + UDP tproxy) добавит _ensure_xray_tproxy.
        "inbounds": [],
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
                "network": "udp,tcp",
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
        if not isinstance(ob, dict):
            continue
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
    port = _validate_port(port, 'server_port')
    _reject_endpoint_ipv6(address, "server")
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
        },
        # UDP-приём обязателен, иначе QUIC/игровой трафик пойдёт мимо.
        "udpTProxy": {
            "listen": (
                f"0.0.0.0:"
                f"{config.localporthysteria}"),
            "timeout": "60s",
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
    port = _validate_port(sb.get('server_port', 443), 'server_port')
    password = sb.get('password', '')
    if not server:
        raise ValueError("Нет server")
    _reject_endpoint_ipv6(server, "server")
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
        },
        "udpTProxy": {
            "listen": (
                f"0.0.0.0:"
                f"{config.localporthysteria}"),
            "timeout": "60s",
        }
    }
    if alpn:
        native['tls']['alpn'] = alpn
    return native


def _validate_direct_endpoints(protocol, parsed):
    """Reject invalid endpoints in formats used by direct-config flow."""
    if protocol == 'vless':
        valid = False
        for outbound in parsed.get('outbounds') or []:
            if not isinstance(outbound, dict):
                continue
            settings = outbound.get('settings') or {}
            if not isinstance(settings, dict):
                continue
            for vnext in settings.get('vnext') or []:
                if not isinstance(vnext, dict) or not vnext.get('address'):
                    continue
                valid = True
                _reject_endpoint_ipv6(vnext['address'], 'VLESS server')
                if 'port' in vnext:
                    _validate_port(vnext['port'], 'server_port')
        if not valid:
            raise ValueError("Нет VLESS outbound с server address")
    elif protocol == 'shadowsocks':
        servers = parsed.get('server', [])
        if not isinstance(servers, list):
            servers = [servers]
        for server in servers:
            _reject_endpoint_ipv6(server, 'Shadowsocks server')
        _validate_port(parsed.get('server_port'), 'server_port')
    elif protocol == 'trojan':
        _reject_endpoint_ipv6(
            parsed.get('remote_addr', ''), 'Trojan server')
    elif protocol == 'hysteria':
        server = parsed.get('server', '')
        _reject_endpoint_ipv6(server, 'Hysteria server')
        port = _endpoint_port(server)
        if port is None:
            raise ValueError("Hysteria server must be host:port")
        _validate_port(port, 'server_port')


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
    # JSON из файлов/Telegram может начинаться с UTF-8 BOM.
    # Удаляем только BOM в начале, не изменяя токены и значения полей.
    data = config_data.lstrip('\ufeff').strip()
    if not data:
        raise ValueError("Пустой конфиг")
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON: {e}")
    if not isinstance(parsed, dict):
        raise ValueError("Корневой JSON должен быть объектом")

    if protocol == 'vless':
        if 'outbounds' in parsed:
            # xray формат. Inbound-ы формирует _ensure_xray_tproxy ниже:
            # отдельно TCP (redirect) и UDP (tproxy). Прежняя версия
            # ставила один inbound "tcp,udp" с followRedirect, из-за чего
            # UDP приходил без оригинального адреса назначения.
            parsed['inbounds'] = []
            rt = parsed.get('routing')
            if not isinstance(rt, dict):
                rt = {}
                parsed.pop('routing', None)
            rules = rt.get('rules', [])
            if not isinstance(rules, list):
                rules = []
            cr = [r for r in rules
                  if isinstance(r, dict)
                  and 'domain' not in r]
            if cr:
                rt['rules'] = cr
                parsed['routing'] = rt
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
        parsed['remote_port'] = _validate_port(
            parsed['remote_port'], 'remote_port')
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

    _validate_direct_endpoints(protocol, parsed)

    if protocol == 'vless':
        parsed = _remove_xray_dns_block(parsed)
        parsed = _ensure_xray_quiet_log(parsed)
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
    # Очищенные строки: в torrc должен попасть нормализованный текст,
    # иначе markdown-разметка из буфера обмена уедет в конфиг и Tor
    # не сможет разобрать мост.
    cleaned = []

    # Адрес моста: IPv4 (1.2.3.4:443) либо IPv6 в квадратных скобках
    # ([2001:db8::1]:443). Мосты webtunnel часто публикуются именно
    # с IPv6-адресами, а прежняя проверка принимала только IPv4 и
    # отвергала такие строки целиком.
    # Октеты и порт проверяются по значению: regex вида \d{1,3}
    # пропускал мусор наподобие 999.999.999.999:99999.
    def _valid_endpoint(value):
        if not value:
            return False
        if value.startswith('['):
            host, sep, port = value.rpartition(']:')
            if not sep:
                return False
            host = host[1:]
            family = socket.AF_INET6
        else:
            host, sep, port = value.rpartition(':')
            if not sep:
                return False
            family = socket.AF_INET
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            return False
        try:
            socket.inet_pton(family, host)
        except (OSError, ValueError):
            return False
        return True

    urp = re.compile(
        r"^https?://[^\s/$.?#].\S*$")

    for line in bl:
        line = line.strip()
        if not line:
            continue
        # Строки часто копируют из мессенджера или веб-страницы вместе с
        # markdown-разметкой: ++[https://a/b](https://a/b)++. Tor такой
        # формат не понимает, а пользователь видел невнятную ошибку.
        # Разметка снимается, ссылка берётся из адресной части.
        if '](' in line or '++[' in line:
            line = re.sub(
                r'\+*\[([^\]]+)\]\((?:[^)]*)\)\+*', r'\1', line)
            line = line.replace('++', '').strip()
        cleaned.append(line)
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
            if not _valid_endpoint(bd):
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
            if not _valid_endpoint(bd):
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
        bo = "\n".join(cleaned) if cleaned else bridges.strip()
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
        # Крупный архив делится долго, но не бесконечно.
        subprocess.run(
            ["split", "-b", str(max_size),
             archive_path, sp],
            check=True, timeout=600)
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
    except subprocess.TimeoutExpired as e:
        log_error(f"[!] split не завершился: {e}")
        return False
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
    # KeenSnap — внешний скрипт, он НЕ входит в проект и ставится
    # отдельно. Без этой проверки Popen поднимал FileNotFoundError,
    # обработчик бота падал с необработанным исключением, и кнопка
    # «Бэкап» молча переставала отвечать.
    if not os.path.exists(args[0]):
        bot.edit_message_text(
            "❌ Не найден скрипт бэкапа:\n"
            f"{args[0]}\n"
            "Установите KeenSnap или поправьте "
            "paths['script_bu'] в bot_config.py",
            chat_id, progress_msg_id)
        log_error(f"script_bu отсутствует: {args[0]}")
        return None

    try:
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
            universal_newlines=True)
    except OSError as e:
        bot.edit_message_text(
            f"❌ Не удалось запустить бэкап: {e}",
            chat_id, progress_msg_id)
        log_error(f"Popen {args[0]}: {e}")
        return None
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

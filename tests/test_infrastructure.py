# -*- coding: utf-8 -*-
"""Межфайловая согласованность констант и shell-обвязки."""
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOT = os.path.join(REPO, "opt", "etc", "bot")
sys.path.insert(0, BOT)

import bot_config as config  # noqa: E402

REDIRECT = os.path.join(REPO, "opt/etc/ndm/netfilter.d/100-redirect.sh")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_ports_match_between_python_and_iptables():
    sh = _read(REDIRECT)
    for var, val in [("PORT_SS", config.localportsh),
                     ("PORT_TOR", config.localporttor),
                     ("PORT_VLESS", config.localportvless),
                     ("PORT_TROJAN", config.localporttrojan),
                     ("PORT_HYSTERIA", config.localporthysteria),
                     ("PORT_WEB", config.generator_settings["listen_port"])]:
        m = re.search(rf'^{var}=(\d+)', sh, re.M)
        assert m and int(m.group(1)) == val, f"{var} расходится с bot_config"


def test_xray_mark_matches_shell():
    sh = _read(REDIRECT)
    m = re.search(r'^XRAY_MARK="(0x[0-9a-fA-F]+)"', sh, re.M)
    assert m and int(m.group(1), 16) == utils_mark()


def utils_mark():
    import utils
    return utils.XRAY_SOCK_MARK


def test_ipset_names_consistent():
    sh = _read(REDIRECT)
    for s in config.ipset_names.values():
        assert s in sh, f"набор {s} не упоминается в 100-redirect.sh"
    fs = _read(os.path.join(REPO, "opt/etc/ndm/fs.d/100-ipset.sh"))
    for s in config.ipset_names.values():
        assert s in fs, f"набор {s} не создаётся в 100-ipset.sh"


def test_tproxy_mark_and_table_in_shell():
    sh = _read(REDIRECT)
    assert re.search(r'^TPROXY_MARK="0x1000000"', sh, re.M)
    assert re.search(r'^TPROXY_TABLE=100', sh, re.M)
    # policy routing обязана быть: fwmark -> таблица 100 -> local route
    assert "ip rule add fwmark" in sh
    assert "ip route replace local default dev lo table" in sh


def test_shell_scripts_pass_sh_n():
    scripts = [
        "opt/bin/unblock_update.sh", "opt/bin/unblock_ipset.sh",
        "opt/bin/unblock_dnsmasq.sh", "opt/bin/rotate_logs.sh",
        "opt/etc/ndm/netfilter.d/100-redirect.sh",
        "opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh",
        "opt/etc/ndm/fs.d/100-ipset.sh",
        "opt/etc/init.d/S99unblock", "opt/etc/init.d/S99telegram_bot",
    ]
    for s in scripts:
        p = os.path.join(REPO, s)
        r = subprocess.run(["sh", "-n", p], capture_output=True, text=True)
        assert r.returncode == 0, f"{s}: {r.stderr}"


def test_wrapper_from_generator_is_valid_sh():
    import generator
    w = generator._build_wrapper("/opt/bin/unblock_update.sh",
                                 only_sets="unblockvless")
    r = subprocess.run(["sh", "-n", "-"], input=w,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "ONLY_SETS=unblockvless" in w


def test_vpn_naming_consistent_redirect_vs_hook():
    """100-unblock-vpn.sh создаёт unblockvpn-<desc>-<id>; 100-redirect.sh
    выводит тип интерфейса из ПОСЛЕДНЕГО '-'-поля имени файла."""
    hook = _read(os.path.join(
        REPO, "opt/etc/ndm/ifstatechanged.d/100-unblock-vpn.sh"))
    red = _read(REDIRECT)
    assert 'unblockvpn="unblockvpn-${vpn_name}-${vpn}"' in hook
    assert "vpn-${vpn_name}-${vpn}.txt" in hook
    assert "awk '{print $NF}'" in red  # последний сегмент = id интерфейса

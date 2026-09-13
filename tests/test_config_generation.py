# -*- coding: utf-8 -*-
"""Генерация конфигов + инварианты UDP-пути (VLESS/Hysteria/SS)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "opt", "etc", "bot"))

import bot_config as config
import pytest
import utils

VLESS_KEY = ("vless://3f7c3d2e-1111-2222-3333-445566778899@"
             "srv.example:443?type=tcp&security=reality"
             "&pbk=PUB&sni=www.microsoft.com&fp=chrome")
HY_KEY = "hy2://secret@hy.example:8443?sni=hy.example&alpn=h3"
SS_KEY = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388"


def _read(path):
    with open(path) as f:
        return json.load(f)


def test_vless_config_udp_tproxy_inbounds(tmp_path):
    """UDP-путь VLESS: два inbound (tcp redirect + udp tproxy),
    один порт с правилами iptables, UDP-маршрут на proxy."""
    utils.vless_config(VLESS_KEY)
    cfg = _read(config.paths["vless_config"])
    inb = {i["tag"]: i for i in cfg["inbounds"]}
    port = config.localportvless  # 10810

    tcp_i = inb["vless-tcp-redirect"]
    udp_i = inb["vless-udp-tproxy"]
    assert tcp_i["port"] == port and udp_i["port"] == port
    assert tcp_i["settings"]["network"] == "tcp"
    assert tcp_i["streamSettings"]["sockopt"]["tproxy"] == "redirect"
    assert udp_i["settings"]["network"] == "udp"
    assert udp_i["streamSettings"]["sockopt"]["tproxy"] == "tproxy"
    assert "quic" in udp_i["sniffing"]["destOverride"]

    # UDP обязан уходить в proxy-outbound
    out_tags = {o.get("tag") for o in cfg["outbounds"]}
    rules = cfg["routing"]["rules"]
    proxy_tag = next(t for t in out_tags if t and
                     any(r.get("outboundTag") == t for r in rules))
    udp_rule = [r for r in rules
                if "udp" in str(r.get("network", ""))
                and r.get("outboundTag") == proxy_tag]
    assert udp_rule, "нет правила маршрутизации UDP -> proxy"

    # Антипетля: исходящие пакеты xray помечены меткой из 100-redirect.sh
    for ob in cfg["outbounds"]:
        if (ob.get("protocol") or ob.get("type")) == "blackhole":
            continue
        assert ob["streamSettings"]["sockopt"]["mark"] == 0x2000000


def test_hysteria_config_listeners(tmp_path):
    """UDP-путь Hysteria2: udpTProxy на том же порту, что TPROXY-правило."""
    utils.hysteria_config(HY_KEY)
    cfg = _read(config.paths["hysteria_config"])
    port = config.localporthysteria  # 10830
    assert cfg["tcpRedirect"]["listen"] == f"0.0.0.0:{port}"
    assert cfg["udpTProxy"]["listen"] == f"0.0.0.0:{port}"
    assert cfg["tls"]["sni"] == "hy.example"
    assert cfg["server"] == "hy.example:8443"


def test_ss_config_written(tmp_path):
    utils.shadowsocks_config(SS_KEY)
    cfg = _read(config.paths["shadowsocks_config"])
    assert cfg["local_port"] == config.localportsh
    assert cfg["server"] == ["1.2.3.4"]
    assert cfg["method"] == "aes-256-gcm"


def test_bad_key_leaves_old_config_intact(tmp_path):
    """Невалидный ключ НЕ должен портить существующий конфиг."""
    p = config.paths["trojan_config"]
    utils.trojan_config("trojan://goodpw@ok.example:443")
    before = open(p).read()
    with pytest.raises(Exception):
        utils.trojan_config("trojan://@no-pass.example:443")
    assert open(p).read() == before


def test_config_file_permissions(tmp_path):
    utils.vless_config(VLESS_KEY)
    mode = os.stat(config.paths["vless_config"]).st_mode & 0o777
    assert mode == 0o600, "конфиг содержит секреты, нужен 0600"

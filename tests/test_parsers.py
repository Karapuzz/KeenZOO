# -*- coding: utf-8 -*-
"""Юнит-тесты парсеров ключей и валидаторов записей (pure functions)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "opt", "etc", "bot"))

import pytest
import utils
import generator


# ── parse_vless_key ─────────────────────────────────────────────────────
VLESS = ("vless://3f7c3d2e-1111-2222-3333-445566778899@"
         "example.com:443?type=tcp&security=reality"
         "&pbk=PUBKEY&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision")

def test_vless_ok():
    p = utils.parse_vless_key(VLESS)
    assert p["address"] == "example.com"
    assert p["port"] == 443
    assert p["id"].startswith("3f7c3d2e")
    assert p["security"] == "reality"
    assert p["sni"] == "www.microsoft.com"
    assert p["flow"] == "xtls-rprx-vision"

def test_vless_default_port():
    p = utils.parse_vless_key(
        "vless://uuid123@example.com?type=ws")
    assert p["port"] == 443
    assert p["transport"] == "ws"

def test_vless_rejects_non_vless():
    with pytest.raises(ValueError):
        utils.parse_vless_key("ss://abc@host:1")

def test_vless_rejects_ipv6():
    with pytest.raises(ValueError):
        utils.parse_vless_key("vless://u@[2001:db8::1]:443")


# ── parse_trojan_key ────────────────────────────────────────────────────
def test_trojan_ok():
    p = utils.parse_trojan_key(
        "trojan://pass%40word@host.example:443"
        "?security=tls&sni=host.example&type=ws&path=%2Fws")
    assert p["pw"] == "pass@word"
    assert p["host"] == "host.example"
    assert p["port"] == 443
    assert p["sni"] == "host.example"
    assert p["ws_enabled"] == "true"
    assert p["path"] == "/ws"
    assert p["verify"] == "true"   # insecure не задан -> проверка ВКЛ

def test_trojan_insecure_disables_verify():
    p = utils.parse_trojan_key(
        "trojan://pw@h.example:443?allowInsecure=1")
    assert p["verify"] == "false"

def test_trojan_requires_password():
    with pytest.raises(ValueError):
        utils.parse_trojan_key("trojan://@h.example:443")

def test_trojan_requires_port():
    with pytest.raises(ValueError):
        utils.parse_trojan_key("trojan://pw@h.example")


# ── parse_shadowsocks_key ───────────────────────────────────────────────
def test_ss_plain():
    p = utils.parse_shadowsocks_key(
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388")
    assert p["server"] == "1.2.3.4"
    assert p["port"] == 8388
    assert p["method"] == "aes-256-gcm"
    assert p["password"] == "password"

def test_ss_fully_encoded():
    import base64
    raw = base64.urlsafe_b64encode(
        b"aes-256-gcm:secret@5.6.7.8:443").decode().rstrip("=")
    p = utils.parse_shadowsocks_key("ss://" + raw)
    assert p["server"] == "5.6.7.8"
    assert p["password"] == "secret"

def test_ss_rejects_ipv6():
    with pytest.raises(ValueError):
        utils.parse_shadowsocks_key(
            "ss://YWVzLTI1Ni1nY206cA@[2001:db8::1]:8388")


# ── parse_hysteria_key ─────────────────────────────────────────────────
def test_hysteria_ok():
    p = utils.parse_hysteria_key(
        "hy2://authpass@srv.example:8443?sni=srv.example&alpn=h3&insecure=0")
    assert p["server"] == "srv.example"
    assert p["port"] == 8443
    assert p["auth"] == "authpass"
    assert p["insecure"] == "false"
    assert '"h3"' in p["alpn"]

def test_hysteria_obfs():
    p = utils.parse_hysteria_key(
        "hy2://p@h.example:443?obfs=salamander&obfs-password=xyz")
    assert p["obfs_type"] == "salamander"
    assert p["obfs_password"] == "xyz"

def test_hysteria_requires_auth():
    with pytest.raises(ValueError):
        utils.parse_hysteria_key("hy2://@h.example:443")


# ── валидатор записей списка обхода (generator._validate_entry) ────────
@pytest.mark.parametrize("good", [
    "example.com", "a.b.c.d", "xn--80ak6aa92e.com",
    "1.2.3.4", "10.0.0.0/8", "91.108.56.0/22",
])
def test_valid_entries(good):
    assert generator._validate_entry(good) is not None

@pytest.mark.parametrize("bad", [
    "", "#comment",
    "1.2.3.4/33", "10.0.0.0/8/8", "bad_domain!", "-bad.com", "bad-.com",
    "a..b.com",
])
def test_invalid_entries(bad):
    assert generator._validate_entry(bad) is None

# ЗАДАокументированные проблемы валидатора (см. отчёт): битые IP проходят
# как «домены», потому что в regex нет запрета числового TLD.
def test_broken_ips_pass_as_domain_DOCUMENTS_ISSUE():
    for e in ("1.2.3", "1.2.3.4.5", "256.1.1.1"):
        assert generator._validate_entry(e) is not None
        assert generator._validate_entry(e)[0] == "domain"

# Проблема: строка диапазона "1.2.3.4-5.6.7.8" проходит как «домен»
def test_range_string_treated_as_domain_DOCUMENTS_ISSUE():
    r = generator._validate_entry("1.2.3.4-5.6.7.8")
    assert r is not None and r[0] == "domain"


# ── оптимизация CIDR ───────────────────────────────────────────────────
def test_optimize_merges_cidrs():
    sections = [
        ("s", ["192.168.2.0/24", "192.168.3.0/24"]),
    ]
    ns, rep = generator._optimize_networks(sections)
    all_entries = [e for _c, es in ns for e in es]
    assert "192.168.2.0/23" in all_entries
    assert "192.168.2.0/24" not in all_entries
    assert rep  # отчёт сформирован

def test_optimize_noop_when_no_gain():
    sections = [("s", ["1.2.3.4", "example.com"])]
    ns, rep = generator._optimize_networks(sections)
    assert rep == []
    assert ns[0][1] == ["1.2.3.4", "example.com"]

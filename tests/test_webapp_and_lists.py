# -*- coding: utf-8 -*-
"""parse_and_save (сквозной) и дымовые тесты Flask-панели."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "opt", "etc", "bot"))

import bot_config as config  # noqa: E402
import generator  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture()
def client():
    config.web_username = "admin"
    config.web_password = "secret"
    generator.app.config["TESTING"] = True
    with generator.app.test_client() as c:
        yield c


def _auth(client):
    return client.get("/", headers={"Authorization":
                                    "Basic YWRtaW46c2VjcmV0"})  # admin:secret


def test_panel_requires_auth(client):
    r = client.get("/")
    assert r.status_code == 401


def test_panel_rejects_wrong_password(client):
    r = client.get("/", headers={"Authorization": "Basic YWRtaW46d3Jvbmc"})
    assert r.status_code == 401


def test_panel_index_ok(client):
    r = _auth(client)
    assert r.status_code == 200
    assert b"csrf_token" in r.data


def test_panel_blocks_cross_origin_post(client):
    import base64
    ah = {"Authorization": "Basic " +
          base64.b64encode(b"admin:secret").decode()}
    _auth(client)
    # без Origin/Referer POST должен получить 403 (CSRF)
    r = client.post("/list/vl", data={"content": "x.com"}, headers=ah)
    assert r.status_code == 403


def test_list_save_and_file_written(client):
    import base64
    ah = {"Authorization": "Basic " +
          base64.b64encode(b"admin:secret").decode()}
    html = client.get("/?tab=vl", headers=ah).data.decode()
    import re
    token = re.search(r'name="csrf_token"\s+value="([0-9a-f]+)"',
                      html, re.S).group(1)
    r = client.post("/list/vl",
               data={"content": "example.com\n#Sec\n1.2.3.4",
                     "csrf_token": token},
               headers={"Origin": "http://127.0.0.1:8080",
                        "Authorization": ah["Authorization"]})
    assert r.status_code == 302
    with open(config.list_files["vless"]) as f:
        text = f.read()
    assert "example.com" in text and "1.2.3.4" in text


# ── parse_and_save напрямую ────────────────────────────────────────────
def test_parse_and_save_roundtrip(tmp_path):
    fp = os.path.join(config.paths["unblock_dir"], "unit.txt")
    res = generator.parse_and_save(
        fp, "# Sec A\nzzz.com\naaa.com\n\n172.19.77.31\n"
            "172.19.77.31\nbad_d!\n")
    assert res["errors"] and "bad_d!" in res["errors"][0]
    assert res["duplicates"], "дубликат 172.19.77.31 не обнаружен"
    text = open(fp).read()
    lines = text.splitlines()
    assert lines[0] == "#Sec A"
    # домены отсортированы, дубликат удалён
    assert lines[1] == "aaa.com" and lines[2] == "zzz.com"
    assert text.count("172.19.77.31") == 1


def test_parse_and_save_rejects_path_traversal():
    with pytest.raises(ValueError):
        generator.parse_and_save("/etc/passwd", "x.com")


def test_parse_and_save_max_lines():
    big = "\n".join(f"d{i}.example" for i in range(
        generator.MAX_LIST_LINES + 10))
    with pytest.raises(ValueError):
        generator.parse_and_save(
            os.path.join(config.paths["unblock_dir"], "big.txt"), big)

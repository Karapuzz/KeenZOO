# -*- coding: utf-8 -*-
"""Фикстуры: импорт модулей проекта без /opt (в песочнице репозиторий лежит
в /home/user/KeenZOO). Патчим пути bot_config до временных каталогов ДО
импорта generator (он читает настройки при импорте)."""
import os
import sys
import tempfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOT_DIR = os.path.join(REPO, "opt", "etc", "bot")

_tmp = tempfile.mkdtemp(prefix="keenzoo_test_")


def _preconfigure_config():
    if "bot_config" in sys.modules:
        return sys.modules["bot_config"]
    sys.path.insert(0, BOT_DIR)
    import bot_config as cfg
    cfg.paths["templates_dir"] = os.path.join(BOT_DIR, "templates")
    cfg.paths["unblock_dir"] = os.path.join(_tmp, "unblock") + "/"
    cfg.paths["vless_config"] = os.path.join(_tmp, "xray", "config.json")
    cfg.paths["trojan_config"] = os.path.join(_tmp, "trojan", "config.json")
    cfg.paths["hysteria_config"] = os.path.join(_tmp, "hysteria", "config.json")
    cfg.paths["shadowsocks_config"] = os.path.join(_tmp, "shadowsocks.json")
    cfg.paths["tor_config"] = os.path.join(_tmp, "tor", "torrc")
    cfg.paths["hosts_file"] = os.path.join(_tmp, "hosts")
    cfg.paths["xray_dir"] = os.path.join(_tmp, "xray")
    cfg.paths["trojan_dir"] = os.path.join(_tmp, "trojan")
    cfg.paths["hysteria_dir"] = os.path.join(_tmp, "hysteria")
    cfg.paths["error_log"] = os.path.join(_tmp, "error.log")
    cfg.generator_settings["secret_file"] = os.path.join(_tmp, ".secret_key")
    cfg.generator_settings["log_file"] = os.path.join(_tmp, "generator.log")
    for k in cfg.list_files:
        cfg.list_files[k] = os.path.join(
            cfg.paths["unblock_dir"], os.path.basename(cfg.list_files[k]))
    os.makedirs(cfg.paths["unblock_dir"], exist_ok=True)
    return cfg


_preconfigure_config()

from telebot import types
import bot_config as config
import os


class Menu:
    def __init__(self, name, markup, level, back_level=None):
        self.name = name
        self.markup = markup
        self.level = level
        self.back_level = back_level



def create_menu(buttons, resize_keyboard=True):
    markup = types.ReplyKeyboardMarkup(
        resize_keyboard=resize_keyboard)
    for row in buttons:
        markup.add(*row)
    return markup


def create_button(text, callback_data):
    return types.InlineKeyboardButton(
        text, callback_data=callback_data)


def create_bypass_files_menu():
    dirname = config.paths["unblock_dir"]
    buttons = []
    if os.path.exists(dirname) and os.listdir(dirname):
        file_buttons = [
            fln[:-4] for fln in sorted(os.listdir(dirname))
            if fln.endswith(".txt")
            and os.path.isfile(os.path.join(dirname, fln))
        ]
        buttons.append(file_buttons if file_buttons else ["Нет доступных файлов"])
    else:
        buttons.append(["Нет доступных файлов"])
    buttons.append(["🔙 Назад"])
    MENU_BYPASS_FILES.markup = create_menu(buttons)
    return MENU_BYPASS_FILES.markup



def create_dns_override_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        create_button("✅ ВКЛ", "dns_override_on"),
        create_button("✖️ ВЫКЛ", "dns_override_off"))
    markup.add(
        create_button("🔙 Назад", "menu_service"))
    return markup


def create_updates_menu(need_update):
    markup = types.InlineKeyboardMarkup()
    if need_update:
        markup.add(
            create_button("🆕 Обновить", "trigger_update"))
    markup.add(
        create_button("🔙 Назад", "menu_service"))
    return markup


def create_install_remove_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        create_button("📲 Установка", "install"),
        create_button("🗑 Удаление", "remove"))
    markup.add(
        create_button("🔙 Назад", "menu_main"))
    return markup


MENU_MAIN = Menu("🤖 Добро пожаловать в меню!", create_menu([
    ["🔑 Ключи и мосты", "📑 Списки обхода"],
    ["📲 Установка и удаление", "⚙️ Сервис"]
]), 0)

MENU_BYPASS_FILES = Menu("📑 Списки обхода", None, 1, 0)

MENU_BYPASS_LIST = Menu("Выберите действие:", create_menu([
    ["📄 Показать список",
     "➕ Добавить в список",
     "➖ Удалить из списка"],
    ["🔙 Назад"]
]), 2, 1)

MENU_ADD_BYPASS = Menu("➕ Добавить в список",
                       create_menu([["🔙 Назад"]]), 3, 2)
MENU_REMOVE_BYPASS = Menu("➖ Удалить из списка",
                          create_menu([["🔙 Назад"]]), 4, 2)

MENU_KEYS_BRIDGES = Menu("🔑 Ключи и мосты", create_menu([
    ["Tor", "Vless", "Trojan"],
    ["Shadowsocks", "Hysteria"],
    ["🔙 Назад"]
]), 5, 0)

MENU_TOR = Menu("Tor", create_menu([["🔙 Назад"]]), 8, 5)
MENU_SHADOWSOCKS = Menu("Shadowsocks",
                        create_menu([["🔙 Назад"]]), 9, 5)
MENU_VLESS = Menu("Vless",
                  create_menu([["🔙 Назад"]]), 10, 5)
MENU_TROJAN = Menu("Trojan",
                   create_menu([["🔙 Назад"]]), 11, 5)
MENU_HYSTERIA = Menu("Hysteria",
                     create_menu([["🔙 Назад"]]), 12, 5)

MENU_SERVICE = Menu("⚙️ Сервисное меню!", create_menu([
    ["🤖 Перезапуск бота",
     "🔌 Перезапуск роутера",
     "🔁 Перезапуск сервисов"],
    ["⁉️ DNS Override", "🆕 Обновления", "💾 Бэкап"],
    ["🔙 Назад"]
]), 6, 0)

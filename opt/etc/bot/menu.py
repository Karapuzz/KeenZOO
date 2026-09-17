from telebot import types
import bot_config as config
import os


class Menu:
    def __init__(self, name, markup, level, back_level=None):
        self.name = name
        self.markup = markup
        self.level = level
        self.back_level = back_level


class BackupState:
    def __init__(self):
        self.startup_config = False
        self.firmware = False
        self.entware = False
        self.custom_files = False
        self.selected_drive = None
        self.delete_archive = False

    def get_selected_count(self):
        return sum([self.startup_config, self.firmware,
                    self.entware, self.custom_files])

    def get_selected_types(self):
        types_list = []
        if self.startup_config:
            types_list.append("Конфигурация")
        if self.firmware:
            types_list.append("Прошивка")
        if self.entware:
            types_list.append("Entware")
        if self.custom_files:
            types_list.append("Другие файлы")
        return types_list


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


def create_backup_menu(backup_state):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        create_button(
            f"{'✅' if backup_state.startup_config else '✖️'}"
            f" Конфигурация", "backup_toggle_startup"),
        create_button(
            f"{'✅' if backup_state.firmware else '✖️'}"
            f" Прошивка", "backup_toggle_firmware"))
    markup.add(
        create_button(
            f"{'✅' if backup_state.entware else '✖️'}"
            f" Entware", "backup_toggle_entware"),
        create_button(
            f"{'✅' if backup_state.custom_files else '✖️'}"
            f" Другие файлы", "backup_toggle_custom"))
    if backup_state.get_selected_count() > 0:
        markup.add(
            create_button("💾 Создать бэкап", "backup_create"))
    markup.add(
        create_button("🔙 Назад", "menu_service"))
    return markup


def create_drive_selection_menu(drives):
    markup = types.InlineKeyboardMarkup(row_width=1)
    for drive in drives:
        button_text = (f"💽 {drive['label']} "
                       f"({drive['size']} GB свободно)")
        markup.add(create_button(
            button_text, f"backup_drive_{drive['uuid']}"))
    markup.add(create_button("🔙 Назад", "backup_menu"))
    return markup


def create_delete_archive_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        create_button("Да", "backup_delete_yes"),
        create_button("Нет", "backup_delete_no"))
    markup.add(
        create_button("🔙 Назад", "backup_create"))
    return markup


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

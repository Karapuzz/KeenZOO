import subprocess
import os
import re
import time
import json
import bot_config as config
from menu import (
    MENU_MAIN, MENU_BYPASS_FILES, MENU_SERVICE,
    MENU_KEYS_BRIDGES, MENU_BYPASS_LIST,
    MENU_ADD_BYPASS, MENU_REMOVE_BYPASS,
    MENU_TOR, MENU_SHADOWSOCKS, MENU_VLESS,
    MENU_TROJAN, MENU_HYSTERIA,
    create_bypass_files_menu, create_backup_menu,
    BackupState, create_drive_selection_menu,
    create_delete_archive_menu,
    create_dns_override_menu,
    create_install_remove_menu
)
from utils import (
    download_script, vless_config, trojan_config,
    shadowsocks_config, tor_config, hysteria_config,
    get_available_drives,
    create_backup_with_params, log_error
)

# Единый префикс защищённых callback-действий: любое из них выполняет
# привилегированную операцию (перезапуск, обновление, бэкап, изменение
# конфигурации) и требует проверки пользователя.

_gen = None


def _load_gen():
    global _gen
    if _gen is None:
        import importlib
        _gen = importlib.import_module('generator')
    return _gen


def _is_valid_cidr(entry):
    m = re.match(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.'
        r'(\d{1,3})/(\d{1,2})$', entry)
    if not m:
        return False
    octets = [int(m.group(i)) for i in range(1, 5)]
    prefix = int(m.group(5))
    return (all(o <= 255 for o in octets)
            and 0 <= prefix <= 32)


def _is_valid_ip(entry):
    m = re.match(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.'
        r'(\d{1,3})$', entry)
    if not m:
        return False
    return all(
        int(m.group(i)) <= 255
        for i in range(1, 5))


def _is_valid_entry(clean):
    if '/' in clean:
        return _is_valid_cidr(clean)
    if _is_valid_ip(clean):
        return True
    if clean.startswith('#'):
        return False
    return bool(re.match(
        r'^(\*\.)?[a-zA-Z0-9]'
        r'([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]'
        r'([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$',
        clean))


class BotState:
    """
    Состояние меню. Хранится отдельно для каждого чата: раньше объект был
    один на весь процесс, и параллельная работа двух администраторов
    приводила к тому, что действие одного применялось к файлу, выбранному
    другим.
    """

    def __init__(self):
        self._by_chat = {}

    def _get(self, chat_id):
        st = self._by_chat.get(chat_id)
        if st is None:
            st = {'menu': MENU_MAIN, 'file': ''}
            self._by_chat[chat_id] = st
        return st

    def get_menu(self, chat_id):
        return self._get(chat_id)['menu']

    def set_menu(self, chat_id, menu):
        self._get(chat_id)['menu'] = menu

    def get_file(self, chat_id):
        return self._get(chat_id)['file']

    def set_file(self, chat_id, name):
        self._get(chat_id)['file'] = name


def get_clean_entry(entry):
    return entry.split('#')[0].strip()


def load_bypass_blocks(filepath):
    if not os.path.exists(filepath):
        return []
    sections = []
    current_section = None
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = (
                line.rstrip('\n')
                .rstrip('\r').strip())
            if not stripped:
                current_section = None
                continue
            if stripped.startswith('#'):
                comment = stripped[1:].strip()
                current_section = {
                    'comment': comment,
                    'entries': []}
                sections.append(current_section)
            else:
                if current_section is None:
                    current_section = {
                        'comment': None,
                        'entries': []}
                    sections.append(current_section)
                current_section['entries'].append(
                    stripped)
    return sections


def sections_to_text(sections):
    lines = []
    for section in sections:
        if section['comment'] is not None:
            if lines:
                lines.append('')
            lines.append(
                f"#{section['comment']}")
        elif lines:
            lines.append('')
        for entry in section['entries']:
            lines.append(entry)
    return '\n'.join(lines)


def save_via_generator(filepath, sections):
    g = _load_gen()
    text = sections_to_text(sections)
    is_bot = (
        os.path.basename(filepath) == 'bot.txt')
    return g.parse_and_save(
        filepath, text,
        skip_global_dedup=is_bot)


def parse_input_blocks(text):
    sections = []
    current_section = None
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped:
            current_section = None
            continue
        if stripped.startswith('#'):
            comment = stripped[1:].strip()
            current_section = {
                'comment': comment,
                'entries': []}
            sections.append(current_section)
        else:
            if current_section is None:
                current_section = {
                    'comment': None,
                    'entries': []}
                sections.append(current_section)
            current_section['entries'].append(
                stripped)
    return [s for s in sections if s['entries']]


def format_blocks_for_display(sections):
    if not sections:
        return "Список пуст"
    lines = []
    named = [
        s for s in sections
        if s['comment'] is not None
        and s['entries']]
    unnamed = [
        e for s in sections
        if s['comment'] is None
        for e in s['entries']]
    for i, section in enumerate(named):
        if i > 0:
            lines.append('')
        lines.append(
            f"#{section['comment']}")
        for entry in sorted(
                section['entries'],
                key=lambda e:
                    get_clean_entry(e).lower()):
            lines.append(entry)
    if unnamed:
        if named:
            lines.append('')
        for entry in sorted(
                unnamed,
                key=lambda e:
                    get_clean_entry(e).lower()):
            lines.append(entry)
    return ('\n'.join(lines)
            if lines else "Список пуст")


def _all_bypass_filepaths():
    filepaths = [
        os.path.join(
            config.paths['unblock_dir'],
            'shadowsocks.txt'),
        os.path.join(
            config.paths['unblock_dir'],
            'tor.txt'),
        os.path.join(
            config.paths['unblock_dir'],
            'vless.txt'),
        os.path.join(
            config.paths['unblock_dir'],
            'trojan.txt'),
        os.path.join(
            config.paths['unblock_dir'],
            'hysteria.txt'),
    ]
    try:
        for name in os.listdir(
                config.paths['unblock_dir']):
            if (name.startswith('vpn-')
                    and name.endswith('.txt')):
                filepaths.append(
                    os.path.join(
                        config.paths['unblock_dir'],
                        name))
    except Exception:
        pass
    return filepaths


def _build_global_bypass_index(
        exclude_filepath=None):
    global_map = {}
    for filepath in _all_bypass_filepaths():
        if (exclude_filepath
                and os.path.realpath(filepath)
                == os.path.realpath(
                    exclude_filepath)):
            continue
        sections = load_bypass_blocks(filepath)
        file_label = os.path.splitext(
            os.path.basename(filepath))[0]
        for section in sections:
            comment = section['comment']
            for entry in section['entries']:
                clean = get_clean_entry(entry)
                if clean and clean not in global_map:
                    global_map[clean] = {
                        'file': file_label,
                        'comment': comment}
    return global_map


def setup_handlers(bot):
    state = BotState()
    backup_state = BackupState()


    def _allowed_user(user):
        try:
            allowed = {
                int(value)
                for value in getattr(
                    config,
                    'allowed_user_ids',
                    [])
            }
            user_id = int(
                getattr(user, 'id', 0))
        except (TypeError, ValueError):
            return False

        return bool(allowed) and user_id in allowed

    def is_allowed_message(message):
        if (message.chat.type != 'private'
                or not _allowed_user(message.from_user)):
            try:
                bot.send_message(
                    message.chat.id,
                    '⚠️ Нет доступа!')
            except Exception:
                pass
            return False
        return True

    def is_allowed_call(call):
        if (not getattr(call, 'message', None)
                or call.message.chat.type != 'private'
                or not _allowed_user(call.from_user)):
            try:
                bot.answer_callback_query(
                    call.id,
                    '⚠️ Нет доступа!',
                    show_alert=True)
            except Exception:
                pass
            return False
        return True



    def set_menu_and_reply(
            chat_id, new_menu,
            text=None, markup=None):
        state.set_menu(chat_id, new_menu)
        if not text:
            text = new_menu.name
        bot.send_message(
            chat_id, text,
            reply_markup=(
                markup if markup
                else new_menu.markup))

    def go_to_bypass_files(chat_id):
        create_bypass_files_menu()
        set_menu_and_reply(
            chat_id, MENU_BYPASS_FILES)

    def handle_bypass_files_selection(message):
        filepath = (
            f"{config.paths['unblock_dir']}"
            f"{message.text}.txt")
        if not os.path.exists(filepath):
            bot.send_message(
                message.chat.id,
                "❌ Неверный выбор",
                reply_markup=(
                    MENU_BYPASS_FILES.markup))
            return
        state.set_file(message.chat.id, message.text)
        set_menu_and_reply(
            message.chat.id,
            MENU_BYPASS_LIST,
            "Меню " + state.get_file(message.chat.id))

    def send_long_message(
            chat_id, text, parse_mode=None):
        current_part = ""
        for line in text.split('\n'):
            if (len(current_part + '\n' + line)
                    > 4096):
                bot.send_message(
                    chat_id, current_part,
                    parse_mode=parse_mode)
                current_part = line
            else:
                current_part += (
                    '\n' + line
                    if current_part else line)
        if current_part:
            bot.send_message(
                chat_id, current_part,
                parse_mode=parse_mode)

    def handle_bypass_list_menu(message):
        selected = state.get_file(message.chat.id)
        filepath = (
            f"{config.paths['unblock_dir']}"
            f"{selected}.txt")
        if message.text == "📄 Показать список":
            sections = load_bypass_blocks(filepath)
            text = format_blocks_for_display(
                sections)
            send_long_message(
                message.chat.id, text)
            bot.send_message(
                message.chat.id,
                "Меню " + selected,
                reply_markup=(
                    MENU_BYPASS_LIST.markup))
        elif message.text == "➕ Добавить в список":
            set_menu_and_reply(
                message.chat.id,
                MENU_ADD_BYPASS,
                "Введите сайт, домен, IP "
                "или CIDR\n\n"
                "#Секция\ngoogle.com\nbing.com"
                "\n\n"
                "130.255.77.28 #заметка\n"
                "216.13.24.0/24\n\n"
                "💡 CIDR объединяются "
                "автоматически")
        elif message.text == "➖ Удалить из списка":
            set_menu_and_reply(
                message.chat.id,
                MENU_REMOVE_BYPASS,
                "Введите адрес для удаления")
        else:
            bot.send_message(
                message.chat.id,
                "❌ Выберите действие из меню",
                reply_markup=(
                    MENU_BYPASS_LIST.markup))

    def handle_add_to_bypass(message):
        selected = state.get_file(message.chat.id)
        filepath = (
            f"{config.paths['unblock_dir']}"
            f"{selected}.txt")
        existing_sections = load_bypass_blocks(
            filepath)
        existing_clean_map = {}
        for s in existing_sections:
            for entry in s['entries']:
                clean = get_clean_entry(entry)
                if clean not in existing_clean_map:
                    existing_clean_map[clean] = (
                        entry, s['comment'])
        is_bot = (
            os.path.basename(filepath)
            == 'bot.txt')
        if is_bot:
            global_clean_map = {}
        else:
            global_clean_map = (
                _build_global_bypass_index(
                    exclude_filepath=filepath))
        sections_map = {}
        for section in existing_sections:
            sec_key = section['comment']
            if sec_key not in sections_map:
                sections_map[sec_key] = section
        new_sections = parse_input_blocks(
            message.text)
        if not new_sections:
            bot.send_message(
                message.chat.id,
                "❕Не введено ни одного адреса",
                reply_markup=(
                    MENU_ADD_BYPASS.markup))
            return
        added_count = 0
        duplicate_msgs = []
        error_msgs = []
        input_seen = {}
        for new_section in new_sections:
            comment = new_section['comment']
            if comment in sections_map:
                target = sections_map[comment]
            else:
                target = {
                    'comment': comment,
                    'entries': []}
                sections_map[comment] = target
                if comment is None:
                    existing_sections.append(target)
                else:
                    none_idx = next(
                        (i for i, s in enumerate(
                            existing_sections)
                         if s['comment'] is None),
                        None)
                    if none_idx is not None:
                        existing_sections.insert(
                            none_idx, target)
                    else:
                        existing_sections.append(
                            target)
            for entry in new_section['entries']:
                clean = get_clean_entry(entry)
                if not clean:
                    continue
                if not _is_valid_entry(clean):
                    error_msgs.append(
                        f"⚠️ Некорректно: {clean}")
                    continue
                if clean in input_seen:
                    fc = input_seen[clean]
                    duplicate_msgs.append(
                        f"• {clean} → дубликат"
                        + (f" (#{fc})"
                           if fc else ""))
                    continue
                input_seen[clean] = comment
                if clean in existing_clean_map:
                    _, ec = (
                        existing_clean_map[clean])
                    duplicate_msgs.append(
                        f"• {clean} → уже"
                        + (f" в #{ec}" if ec
                           else " в списке"))
                    continue
                if clean in global_clean_map:
                    info = global_clean_map[clean]
                    duplicate_msgs.append(
                        f"• {clean} → в "
                        f"{info['file']}.txt"
                        + (f" (#{info['comment']})"
                           if info['comment']
                           else ""))
                    continue
                target['entries'].append(entry)
                existing_clean_map[clean] = (
                    entry, comment)
                added_count += 1
        if added_count > 0:
            result = save_via_generator(
                filepath, existing_sections)
            msg_parts = [
                "✅ Добавлено, применяю..."]
            if result.get('cidr_report'):
                msg_parts.extend(
                    result['cidr_report'])
            bot.send_message(
                message.chat.id,
                '\n'.join(msg_parts))
            subprocess.Popen(
                config.services["unblock_update"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True)
        if duplicate_msgs:
            bot.send_message(
                message.chat.id,
                "❕Дубликаты:\n"
                + "\n".join(duplicate_msgs))
        if error_msgs:
            bot.send_message(
                message.chat.id,
                "❌ Некорректные:\n"
                + "\n".join(error_msgs))
        if (added_count == 0
                and not duplicate_msgs
                and not error_msgs):
            bot.send_message(
                message.chat.id,
                "❕Было добавлено ранее")
        set_menu_and_reply(
            message.chat.id,
            MENU_BYPASS_LIST,
            "Меню " + selected)

    def handle_remove_from_bypass(message):
        selected = state.get_file(message.chat.id)
        filepath = (
            f"{config.paths['unblock_dir']}"
            f"{selected}.txt")
        to_remove = {
            get_clean_entry(line)
            for line in message.text.split('\n')
            if line.strip()
            and not line.strip().startswith('#')}
        if not to_remove:
            bot.send_message(
                message.chat.id,
                "❕Введите адрес для удаления",
                reply_markup=(
                    MENU_REMOVE_BYPASS.markup))
            return
        existing_sections = load_bypass_blocks(
            filepath)
        removed_count = 0
        for section in existing_sections:
            before = len(section['entries'])
            section['entries'] = [
                e for e in section['entries']
                if get_clean_entry(e)
                not in to_remove]
            removed_count += (
                before - len(section['entries']))
        existing_sections = [
            s for s in existing_sections
            if s['entries']]
        if removed_count > 0:
            result = save_via_generator(
                filepath, existing_sections)
            msg_parts = [
                "✅ Удалено, применяю..."]
            if result.get('cidr_report'):
                msg_parts.extend(
                    result['cidr_report'])
            bot.send_message(
                message.chat.id,
                '\n'.join(msg_parts))
            subprocess.Popen(
                config.services["unblock_update"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True)
        else:
            bot.send_message(
                message.chat.id,
                "❕Не найдено в списке")
        set_menu_and_reply(
            message.chat.id,
            MENU_BYPASS_LIST,
            "Меню " + selected)

    def handle_keys_bridges_selection(message):
        if message.text == 'Tor':
            set_menu_and_reply(
                message.chat.id, MENU_TOR,
                "🔑 Вставьте мосты Tor")
        elif message.text == 'Shadowsocks':
            set_menu_and_reply(
                message.chat.id,
                MENU_SHADOWSOCKS,
                "🔑 Вставьте ключ Shadowsocks")
        elif message.text == 'Vless':
            set_menu_and_reply(
                message.chat.id, MENU_VLESS,
                "🔑 Вставьте ключ Vless")
        elif message.text == 'Trojan':
            set_menu_and_reply(
                message.chat.id, MENU_TROJAN,
                "🔑 Вставьте ключ Trojan")
        elif message.text == 'Hysteria':
            set_menu_and_reply(
                message.chat.id,
                MENU_HYSTERIA,
                "🔑 Вставьте ключ Hysteria2\n"
                "hy2://пароль@сервер:порт"
                "?sni=домен&alpn=h3#имя")
        else:
            bot.send_message(
                message.chat.id,
                "❌ Выберите протокол",
                reply_markup=(
                    MENU_KEYS_BRIDGES.markup))

    def update_service(
            chat_id, service_name,
            config_func, restart_cmd):
        try:
            config_func()
            # Перезапуск службы не должен подвешивать бота.
            result = subprocess.run(
                restart_cmd,
                capture_output=True,
                text=True,
                timeout=120)
            if result.returncode == 0:
                bot.send_message(
                    chat_id,
                    f'✅ {service_name} '
                    f'перезапущен')
                return True, None
            else:
                err = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "Неизвестная ошибка")
                bot.send_message(
                    chat_id,
                    f'❌ Ошибка '
                    f'{service_name}: {err}')
                return False, err
        except Exception as e:
            log_error(f"{service_name}: {e}")
            return False, str(e)

    def handle_tor_manually(message):
        success, _ = update_service(
            message.chat.id, "Tor",
            lambda: tor_config(
                message.text, bot,
                message.chat.id),
            config.services["tor_restart"])
        if success:
            set_menu_and_reply(
                message.chat.id,
                MENU_KEYS_BRIDGES)
        else:
            bot.send_message(
                message.chat.id,
                "❕Попробуйте заново",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    def handle_shadowsocks(message):
        success, _ = update_service(
            message.chat.id, "Shadowsocks",
            lambda: shadowsocks_config(
                message.text, bot,
                message.chat.id),
            config.services[
                "shadowsocks_restart"])
        if success:
            set_menu_and_reply(
                message.chat.id,
                MENU_KEYS_BRIDGES)
        else:
            bot.send_message(
                message.chat.id,
                "❕Попробуйте заново",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    def handle_vless(message):
        success, _ = update_service(
            message.chat.id, "Vless",
            lambda: vless_config(
                message.text, bot,
                message.chat.id),
            config.services["vless_restart"])
        if success:
            set_menu_and_reply(
                message.chat.id,
                MENU_KEYS_BRIDGES)
        else:
            bot.send_message(
                message.chat.id,
                "❕Попробуйте заново",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    def handle_trojan(message):
        success, _ = update_service(
            message.chat.id, "Trojan",
            lambda: trojan_config(
                message.text, bot,
                message.chat.id),
            config.services[
                "trojan_restart"])
        if success:
            set_menu_and_reply(
                message.chat.id,
                MENU_KEYS_BRIDGES)
        else:
            bot.send_message(
                message.chat.id,
                "❕Попробуйте заново",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    def handle_hysteria(message):
        success, _ = update_service(
            message.chat.id, "Hysteria",
            lambda: hysteria_config(
                message.text, bot,
                message.chat.id),
            config.services[
                "hysteria_restart"])
        if success:
            set_menu_and_reply(
                message.chat.id,
                MENU_KEYS_BRIDGES)
        else:
            bot.send_message(
                message.chat.id,
                "❕Попробуйте заново",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    def handle_restart(chat_id):
        bot.send_message(
            chat_id,
            "⏳ Бот будет перезапущен!\n"
            "Это займет 15-30 секунд",
            reply_markup=MENU_SERVICE.markup)
        with open(
                config.paths["chat_id_path"],
                'w') as f:
            f.write(str(chat_id))
        subprocess.Popen(
            config.services['service_script'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True)

    def handle_backup(chat_id):
        bot.send_message(
            chat_id,
            "Выберите файлы для бэкапа:",
            reply_markup=create_backup_menu(
                backup_state))

    def handle_install_remove(chat_id):
        bot.send_message(
            chat_id, "Выберите действие:",
            reply_markup=(
                create_install_remove_menu()))

    def handle_dns_override(chat_id):
        bot.send_message(
            chat_id, "Выберите действие:",
            reply_markup=(
                create_dns_override_menu()))

    def get_local_version():
        vf = os.path.join(
            os.path.dirname(__file__),
            "version.md")
        try:
            with open(vf, "r",
                      encoding="utf-8") as f:
                return f.read().strip()
        except FileNotFoundError:
            return "N/A"

    def get_remote_version():
        """
        Внешний источник версии удалён вместе с bot_url. Доступная версия
        берётся из результата check_updates.sh (локальный скрипт), а при
        его отсутствии считается равной установленной.
        """
        return get_local_version()

    def handle_updates(chat_id):
        # Сохранить chat_id для уведомлений
        try:
            with open(
                    config.paths.get(
                        "chat_id_notify",
                        "/opt/var/run/"
                        "bot_chat_id_notify.txt"),
                    'w') as f:
                f.write(str(chat_id))
        except Exception:
            pass

        bot.send_message(
            chat_id, "⏳ Проверяю обновления...")

        # Запустить проверку протоколов
        check_script = config.paths.get(
            "check_updates",
            "/opt/bin/check_updates.sh")
        if os.path.exists(check_script):
            try:
                subprocess.run(
                    [check_script], timeout=60)
            except Exception:
                pass

        # Прочитать результат
        updates_info = None
        status_file = config.paths.get(
            "updates_status",
            "/tmp/updates_status.json")
        try:
            if os.path.exists(status_file):
                with open(status_file, 'r') as f:
                    updates_info = json.load(f)
        except Exception:
            pass

        # Версии бота
        bot_version = get_local_version()
        bot_new = get_remote_version()

        # Формируем сообщение
        msg = ""
        if updates_info:
            versions = updates_info.get(
                'versions', {})
            if versions:
                msg += ("📦 <b>Версии "
                        "протоколов:</b>\n")
                for name, ver in versions.items():
                    msg += (f"• {name}: "
                            f"<code>{ver}</code>\n")

        msg += "\n🤖 <b>Бот:</b>\n"
        msg += (f"• Установлена: "
                f"<code>{bot_version}</code>\n")
        msg += (f"• Доступна: "
                f"<code>{bot_new}</code>\n")

        updates = (updates_info.get('updates', [])
                   if updates_info else [])
        has_proto_updates = bool(updates)
        need_bot_update = False

        if (bot_version != "N/A"
                and bot_new != "N/A"):
            try:
                if (tuple(map(int,
                              bot_version.split(".")))
                        < tuple(map(int,
                                    bot_new
                                    .split(".")))):
                    need_bot_update = True
            except ValueError:
                pass

        if has_proto_updates:
            msg += ("\n🆕 <b>Доступны "
                    "обновления:</b>\n")
            for upd in updates:
                msg += (
                    f"• <b>{upd['name']}</b>: "
                    f"{upd['current']} → "
                    f"{upd['available']} "
                    f"({upd['source']})\n")

        if (not has_proto_updates
                and not need_bot_update):
            msg += "\n✅ Всё актуально"

        # Inline-кнопки
        from telebot import types as tg_types
        markup = tg_types.InlineKeyboardMarkup(
            row_width=2)

        if has_proto_updates:
            has_github = any(
                u['source'] == 'github'
                for u in updates)
            has_opkg = any(
                u['source'] == 'opkg'
                for u in updates)
            if has_github:
                markup.add(
                    tg_types.InlineKeyboardButton(
                        "🔄 xray/hysteria",
                        callback_data=(
                            "update_github")))
            if has_opkg:
                markup.add(
                    tg_types.InlineKeyboardButton(
                        "🔄 opkg пакеты",
                        callback_data=(
                            "update_opkg")))
            markup.add(
                tg_types.InlineKeyboardButton(
                    "🔄 Обновить всё",
                    callback_data=(
                        "update_all")))

        if need_bot_update:
            markup.add(
                tg_types.InlineKeyboardButton(
                    "🆕 Обновить бота",
                    callback_data=(
                        "trigger_update")))

        markup.add(
            tg_types.InlineKeyboardButton(
                "🔄 Перепроверить",
                callback_data=(
                    "recheck_updates")))
        markup.add(
            tg_types.InlineKeyboardButton(
                "🔙 Назад",
                callback_data=(
                    "menu_service")))

        bot.send_message(
            chat_id, msg,
            parse_mode="HTML",
            reply_markup=markup)

    def _safe_reboot():
        """Перезагрузка роутера, не роняющая обработчик при сбое ndmc."""
        try:
            subprocess.run(
                ["ndmc", "-c", "system reboot"],
                timeout=60, check=False)
        except (subprocess.SubprocessError, OSError) as e:
            log_error(f"[!] reboot: {e}")

    def toggle_dns_override(chat_id, enable):
        cmd = (
            ["ndmc", "-c",
             "opkg dns-override"]
            if enable
            else ["ndmc", "-c",
                  "no opkg dns-override"])
        st = ("включен" if enable
              else "выключен")
        # ndmc обращается к службе прошивки: при её зависании бот не
        # должен блокироваться навсегда. Истёкшее ожидание — обычная
        # ошибка, о которой сообщаем пользователю, а не аварийное
        # завершение обработчика.
        try:
            subprocess.run(cmd, timeout=60, check=False)
            time.sleep(2)
            subprocess.run(
                ["ndmc", "-c",
                 "system configuration save"],
                timeout=60, check=False)
        except (subprocess.SubprocessError, OSError) as e:
            log_error(f"[!] dns-override: {e}")
            bot.send_message(
                chat_id,
                "❌ Не удалось применить DNS Override: "
                "служба ndmc не ответила.")
            return

        bot.send_message(
            chat_id,
            f'{"✅" if enable else "✖️"} '
            f'DNS Override {st}!\n'
            f'⏳ Роутер перезапускается!')
        time.sleep(5)
        try:
            subprocess.run(
                ["ndmc", "-c", "system reboot"],
                timeout=60, check=False)
        except (subprocess.SubprocessError, OSError) as e:
            log_error(f"[!] reboot: {e}")

    MENU_TRANSITIONS = {
        '🔙 Назад': lambda cid: (
            set_menu_and_reply(cid, next(
                (m for m in [
                    MENU_MAIN, MENU_SERVICE,
                    MENU_BYPASS_FILES,
                    MENU_KEYS_BRIDGES,
                    MENU_TOR,
                    MENU_SHADOWSOCKS,
                    MENU_VLESS,
                    MENU_TROJAN,
                    MENU_HYSTERIA,
                    MENU_BYPASS_LIST,
                    MENU_ADD_BYPASS,
                    MENU_REMOVE_BYPASS]
                 if m.level == (
                     state.get_menu(cid)
                     .back_level)),
                MENU_MAIN))),
        '📑 Списки обхода':
            go_to_bypass_files,
        '🔑 Ключи и мосты':
            lambda cid: (
                set_menu_and_reply(
                    cid,
                    MENU_KEYS_BRIDGES)),
        '⚙️ Сервис':
            lambda cid: (
                set_menu_and_reply(
                    cid, MENU_SERVICE)),
        '🤖 Перезапуск бота':
            handle_restart,
        '🔌 Перезапуск роутера':
            lambda cid: (
                bot.send_message(
                    cid,
                    "⏳ Роутер "
                    "перезапускается!",
                    reply_markup=(
                        MENU_SERVICE.markup)),
                _safe_reboot()),
        '⁉️ DNS Override':
            handle_dns_override,
        '🔁 Перезапуск сервисов':
            lambda cid: (
                bot.send_message(
                    cid,
                    '⏳ Перезапуск '
                    'сервисов...'),
                update_service(
                    cid, "Shadowsocks",
                    lambda: None,
                    config.services[
                        "shadowsocks_restart"]),
                update_service(
                    cid, "Tor",
                    lambda: None,
                    config.services[
                        "tor_restart"]),
                update_service(
                    cid, "Vless",
                    lambda: None,
                    config.services[
                        "vless_restart"]),
                update_service(
                    cid, "Trojan",
                    lambda: None,
                    config.services[
                        "trojan_restart"]),
                update_service(
                    cid, "Hysteria",
                    lambda: None,
                    config.services[
                        "hysteria_restart"]),
                bot.send_message(
                    cid,
                    '❕ Перезапуск завершен',
                    reply_markup=(
                        MENU_MAIN.markup))),
        '🆕 Обновления':
            handle_updates,
        '📲 Установка и удаление':
            handle_install_remove,
        '💾 Бэкап':
            handle_backup,
    }

    LEVEL_HANDLERS = {
        1: handle_bypass_files_selection,
        2: handle_bypass_list_menu,
        3: handle_add_to_bypass,
        4: handle_remove_from_bypass,
        5: handle_keys_bridges_selection,
        8: handle_tor_manually,
        9: handle_shadowsocks,
        10: handle_vless,
        11: handle_trojan,
        12: handle_hysteria,
    }

    @bot.message_handler(commands=['start'])
    def start(message):
        if not is_allowed_message(message):
            return
        set_menu_and_reply(
            message.chat.id, MENU_MAIN)

    @bot.message_handler(
        content_types=['text'])
    def bot_message(message):
        if not is_allowed_message(message):
            return
        if message.text in MENU_TRANSITIONS:
            MENU_TRANSITIONS[message.text](
                message.chat.id)
        elif (state.get_menu(
                message.chat.id).level
              in LEVEL_HANDLERS):
            LEVEL_HANDLERS[
                state.get_menu(
                    message.chat.id).level](
                    message)
        else:
            bot.send_message(
                message.chat.id,
                "❌ Выберите из меню",
                reply_markup=(
                    state.get_menu(
                        message.chat.id).markup))

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "menu_service")
    def handle_backup_return(call):
        if not is_allowed_call(call):
            return
        state.set_menu(
            call.message.chat.id, MENU_SERVICE)
        bot.delete_message(
            call.message.chat.id,
            call.message.message_id)
        bot.send_message(
            call.message.chat.id,
            MENU_SERVICE.name,
            reply_markup=MENU_SERVICE.markup)
        backup_state.__init__()

    @bot.callback_query_handler(
        func=lambda c:
            c.data.startswith(
                "backup_toggle_"))
    def handle_backup_toggle(call):
        if not is_allowed_call(call):
            return
        bt = call.data.replace(
            "backup_toggle_", "")
        if bt == "startup":
            backup_state.startup_config = (
                not backup_state.startup_config)
        elif bt == "firmware":
            backup_state.firmware = (
                not backup_state.firmware)
        elif bt == "entware":
            backup_state.entware = (
                not backup_state.entware)
        elif bt == "custom":
            backup_state.custom_files = (
                not backup_state.custom_files)
        bot.edit_message_reply_markup(
            call.message.chat.id,
            call.message.message_id,
            reply_markup=create_backup_menu(
                backup_state))

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "backup_create")
    def handle_backup_create(call):
        if not is_allowed_call(call):
            return
        drives = get_available_drives()
        if not drives:
            bot.answer_callback_query(
                call.id,
                "❌ Нет дисков",
                show_alert=True)
            return
        msg = bot.edit_message_text(
            "Выберите диск:",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=(
                create_drive_selection_menu(
                    drives)))
        backup_state.selection_msg_id = (
            msg.message_id)

    @bot.callback_query_handler(
        func=lambda c:
            c.data.startswith(
                "backup_drive_"))
    def handle_backup_drive_select(call):
        if not is_allowed_call(call):
            return
        uuid = call.data.replace(
            "backup_drive_", "")
        drives = get_available_drives()
        sel = next(
            (d for d in drives
             if d['uuid'] == uuid), None)
        if not sel:
            bot.answer_callback_query(
                call.id,
                "❌ Диск недоступен",
                show_alert=True)
            return
        backup_state.selected_drive = sel
        bot.edit_message_text(
            f"☑️ Диск: {sel['label']}\n"
            f"Удалить архив после?",
            call.message.chat.id,
            backup_state.selection_msg_id,
            reply_markup=(
                create_delete_archive_menu()))

    @bot.callback_query_handler(
        func=lambda c: c.data in [
            "backup_delete_yes",
            "backup_delete_no"])
    def handle_delete_archive_choice(call):
        if not is_allowed_call(call):
            return
        if call.data == "backup_delete_yes":
            backup_state.delete_archive = True
            ch = "Да"
        else:
            backup_state.delete_archive = False
            ch = "Нет"
        bot.edit_message_text(
            f"☑️ Диск: "
            f"{backup_state.selected_drive['label']}"
            f"\n☑️ Удалить: {ch}",
            call.message.chat.id,
            backup_state.selection_msg_id)
        pm = bot.send_message(
            call.message.chat.id,
            "⏳ Создаю бэкап!")
        create_backup_with_params(
            bot, call.message.chat.id,
            backup_state,
            backup_state.selected_drive,
            pm.message_id)
        backup_state.__init__()

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "backup_menu")
    def handle_backup_menu_return(call):
        if not is_allowed_call(call):
            return
        bot.edit_message_text(
            "Выберите файлы:",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=create_backup_menu(
                backup_state))

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "dns_override_on")
    def handle_dns_on(call):
        if not is_allowed_call(call):
            return
        bot.edit_message_reply_markup(
            chat_id=call.message.chat.id,
            message_id=(
                call.message.message_id),
            reply_markup=None)
        toggle_dns_override(
            call.message.chat.id, True)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "dns_override_off")
    def handle_dns_off(call):
        if not is_allowed_call(call):
            return
        bot.edit_message_reply_markup(
            chat_id=call.message.chat.id,
            message_id=(
                call.message.message_id),
            reply_markup=None)
        toggle_dns_override(
            call.message.chat.id, False)

    @bot.callback_query_handler(
        func=lambda c: c.data in [
            "update_github",
            "update_opkg",
            "update_all"])
    def handle_protocol_update(call):
        if not is_allowed_call(call):
            return
        cid = call.message.chat.id
        bot.edit_message_reply_markup(
            chat_id=cid,
            message_id=(
                call.message.message_id),
            reply_markup=None)

        action_map = {
            "update_github": "xray/hysteria",
            "update_opkg": "opkg пакеты",
            "update_all": "все протоколы",
        }
        label = action_map.get(
            call.data, "протоколы")
        msg = bot.send_message(
            cid, f"⏳ Обновляю {label}...")

        script = config.paths.get(
            "update_protocols",
            "/opt/bin/update_protocols.sh")
        output = ""

        # Успех определяется кодом возврата скрипта, а не поиском
        # символа "❌" в выводе: сообщение об ошибке могло не содержать
        # этот символ, и неудачное обновление считалось успешным.
        failed = False

        if call.data == "update_github":
            for proto in ["xray", "hysteria"]:
                try:
                    result = subprocess.run(
                        [script, proto],
                        capture_output=True,
                        text=True,
                        timeout=300)
                    out = (
                        result.stdout.strip()
                        or result.stderr.strip())
                    if result.returncode != 0:
                        failed = True
                    if out:
                        output += out + "\n"
                        bot.edit_message_text(
                            f"⏳ {out}",
                            cid,
                            msg.message_id)
                except Exception as e:
                    failed = True
                    output += (
                        f"❌ {proto}: {e}\n")
        else:
            action = ("opkg"
                      if call.data
                      == "update_opkg"
                      else "all")
            try:
                result = subprocess.run(
                    [script, action],
                    capture_output=True,
                    text=True,
                    timeout=600)
                if result.returncode != 0:
                    failed = True
                output = (
                    result.stdout.strip()
                    or result.stderr.strip()
                    or "")
            except Exception as e:
                failed = True
                output = f"❌ Ошибка: {e}"

        final = (
            f"❌ Обновление завершилось с ошибкой\n{output}"
            if failed
            else f"✅ Обновление завершено\n{output}")
        bot.edit_message_text(
            final[:4000], cid, msg.message_id)

        time.sleep(2)
        handle_updates(cid)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "recheck_updates")
    def handle_recheck(call):
        if not is_allowed_call(call):
            return
        bot.delete_message(
            call.message.chat.id,
            call.message.message_id)
        handle_updates(call.message.chat.id)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "trigger_update")
    def handle_update(call):
        if not is_allowed_call(call):
            return
        cid = call.message.chat.id
        bot.edit_message_reply_markup(
            chat_id=cid,
            message_id=(
                call.message.message_id),
            reply_markup=None)
        msg = bot.send_message(
            cid, '⏳ Обновление компонентов...')
        with open(
                config.paths["chat_id_path"],
                'w') as f:
            f.write(str(cid))

        # Обновление выполняется локальным проверенным скриптом
        # (скачивание бинарников там идёт с проверкой SHA256/GPG).
        script = config.paths.get(
            "update_protocols",
            "/opt/bin/update_protocols.sh")
        try:
            result = subprocess.run(
                [script, "all"],
                capture_output=True,
                text=True, timeout=600)
            out = (result.stdout.strip()
                   or result.stderr.strip()
                   or "")
            ok = (result.returncode == 0)
        except Exception as e:
            out = str(e)
            ok = False

        bot.edit_message_text(
            (f"✅ Обновление завершено\n{out}"
             if ok else
             f"❌ Ошибка обновления\n{out}")[:4000],
            cid, msg.message_id)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "install")
    def handle_install(call):
        if not is_allowed_call(call):
            return
        cid = call.message.chat.id
        try:
            deploy = download_script()
        except Exception as e:
            bot.send_message(
                cid, f"❌ {e}")
            return
        bot.edit_message_reply_markup(
            chat_id=cid,
            message_id=(
                call.message.message_id),
            reply_markup=None)
        msg = bot.send_message(
            cid, '⏳ Установка!')
        process = subprocess.Popen(
            [deploy, '-install'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        for line in process.stdout:
            bot.edit_message_text(
                f"⏳ {line.strip()}",
                cid, msg.message_id)
        process.wait()
        bot.send_message(
            cid,
            '✅ Установка завершена'
            if process.returncode == 0
            else '❌ Ошибка установки',
            reply_markup=MENU_MAIN.markup)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "remove")
    def handle_remove(call):
        if not is_allowed_call(call):
            return
        cid = call.message.chat.id
        bot.edit_message_reply_markup(
            chat_id=cid,
            message_id=(
                call.message.message_id),
            reply_markup=None)
        try:
            deploy = download_script()
        except Exception as e:
            bot.send_message(
                cid, f"❌ {e}")
            return
        msg = bot.send_message(
            cid, '⏳ Удаление!')
        process = subprocess.Popen(
            [deploy, '-remove'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        for line in process.stdout:
            bot.edit_message_text(
                f"⏳ {line.strip()}",
                cid, msg.message_id)
        process.wait()
        bot.send_message(
            cid,
            '✅ Удаление завершено'
            if process.returncode == 0
            else '❌ Ошибка удаления',
            reply_markup=MENU_MAIN.markup)

    @bot.callback_query_handler(
        func=lambda c:
            c.data == "menu_main")
    def handle_back_main(call):
        if not is_allowed_call(call):
            return
        state.set_menu(
            call.message.chat.id, MENU_MAIN)
        bot.delete_message(
            call.message.chat.id,
            call.message.message_id)
        bot.send_message(
            call.message.chat.id,
            MENU_MAIN.name,
            reply_markup=MENU_MAIN.markup)

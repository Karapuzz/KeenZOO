#!/opt/bin/python3
import os
import sys
import signal
import time
import telebot
import subprocess
import requests.exceptions
from handlers import setup_handlers
from utils import log_error, clean_log, check_restart, signal_handler
import bot_config as config

if not config.token or config.token.strip() == "" or ":" not in config.token or len(config.token) < 10:
    log_error("Ошибка: Токен не указан или имеет неверный формат в bot_config.py")
    sys.exit(1)
    
current_pid = str(os.getpid())
# dns4.2.20: единственность экземпляра — без pgrep. BusyBox pgrep -f даёт
# ложные совпадения на команду-обёртку (задокументировано в
# S99telegram_bot), а timeout=30 мог подвешивать старт. Guard удалять
# нельзя: при ручном двойном запуске второй экземпляр получил бы
# 409 Conflict от getUpdates. Проверка повторяет check_process из
# S99telegram_bot: argv0 ∈ python*, отдельный argv == MAIN_SCRIPT,
# собственный PID исключён.
def _other_bot_instances():
    main_script = config.paths["bot_path"]
    found = []
    try:
        proc_entries = os.listdir('/proc')
    except OSError:
        return found
    for entry in proc_entries:
        if not entry.isdigit() or entry == current_pid:
            continue
        try:
            with open('/proc/' + entry + '/cmdline', 'rb') as cmdline_file:
                raw = cmdline_file.read()
        except OSError:
            # Процесс мог завершиться между listdir и чтением.
            continue
        argv = [arg.decode('utf-8', 'replace') for arg in raw.split(b'\0') if arg]
        if not argv:
            continue
        if not os.path.basename(argv[0]).startswith('python'):
            continue
        if any(arg == main_script for arg in argv[1:]):
            found.append(entry)
    return found

_other_pids = _other_bot_instances()
if _other_pids:
    log_error(f"Бот уже запущен с PID: {', '.join(_other_pids)}")
    sys.exit(1)

if not config.allowed_user_ids:
    log_error(
        "Ошибка: не задан ни один allowed_user_ids в bot_config.py — "
        "бот не запущен, иначе доступ был бы у любого пользователя")
    sys.exit(1)

bot = telebot.TeleBot(config.token)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    clean_log(config.paths["error_log"])

    # Запуск бота и обработчиков
    setup_handlers(bot)
    check_restart(bot)

    restart_count = 0
    while restart_count < config.MAX_RESTARTS:
        try:
            bot.infinity_polling(
                timeout=30,
                long_polling_timeout=30)
            # Штатный выход из polling (например, по сигналу) — не ошибка.
            break
        except (telebot.apihelper.ApiException,
                requests.exceptions.RequestException) as err:
            # Сетевые сбои (нет DNS, нет WAN, туннель не поднялся)
            # НЕ считаются фатальными: при старте роутера резолвер
            # часто ещё не готов, и прежняя логика исчерпывала
            # MAX_RESTARTS за пару минут, после чего бот выходил
            # навсегда — до ручного перезапуска.
            text = str(err)
            transient = (
                'resolve' in text
                or 'Temporary failure' in text
                or 'Max retries' in text
                or 'Connection' in text
                or 'timed out' in text)
            log_error(
                f"Ошибка соединения или Telegram API: {text}")
            if transient:
                # Ждём дольше, но счётчик не наращиваем.
                time.sleep(max(config.RESTART_DELAY, 30))
                continue
            restart_count += 1
            time.sleep(config.RESTART_DELAY)
        except SystemExit:
            raise
        except Exception as err:
            log_error(f"Неизвестная ошибка: {str(err)}")
            restart_count += 1
            time.sleep(config.RESTART_DELAY)
    else:
        log_error(
            "Бот остановлен после достижения максимального "
            "количества попыток перезапуска")
        sys.exit(1)

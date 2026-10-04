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
# Проверка «бот уже запущен» не должна мешать старту: если pgrep
# отсутствует или завис, считаем, что других экземпляров нет.
try:
    pids_output = subprocess.run(
        ['pgrep', '-f', f'python3 {config.paths["bot_path"]}'],
        capture_output=True, text=True, timeout=30).stdout.strip()
except (subprocess.SubprocessError, OSError) as e:
    log_error(f"[!] pgrep недоступен: {e}")
    pids_output = ""
running_pids = [pid for pid in pids_output.splitlines() if pid and pid != current_pid]
if running_pids:
    log_error(f"Бот уже запущен с PID: {', '.join(running_pids)}")
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

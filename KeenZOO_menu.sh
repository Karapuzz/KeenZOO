#!/bin/sh
# KeenZOO_menu.sh — меню жизненного цикла проекта (ред. 29, G23–G27).
#
# Предусловие: Entware уже установлена и доступен её Linux-shell.
# Меню НЕ устанавливает Entware: без shell запустить shell-меню всё равно
# невозможно. Первичная установка Entware выполняется штатно через WEB/OPKG
# Keenetic; затем этот файл и KeenZOO_full_*.tar.gz кладутся рядом (обычно
# в /tmp), и выбирается пункт 1.
#
# Сценарии:
#   1 — deploy_bypass.sh <архив>, только если проекта ещё нет;
#   2 — свежий deploy_bypass.sh из архива, только если проект установлен;
#   3 — установленный backup_project.sh;
#   4 — установленный deploy_bypass.sh -remove (с подтверждением внутри);
#   5 — выход.
set -u

die() { echo "❌ $*" >&2; exit 1; }

SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" 2>/dev/null && pwd)" \
    || die "не удалось определить каталог скрипта"
KZ_DIR="${KZ_MENU_TMPDIR:-/tmp/kz}"
OPT_BIN="${KZ_MENU_OPTBIN:-/opt/bin}"
OPT_ETC="${KZ_MENU_OPTETC:-/opt/etc}"
OPKG_BIN="${KZ_MENU_OPKG:-/opt/bin/opkg}"
ARC=""
KZ_BIN=""

# Свежая редакция — по НОМЕРУ в конце имени; нечисловой суффикс = 0.
pick_archive() {
    for _pa_d in "$SCRIPT_DIR" /tmp; do
        ls -1 "$_pa_d"/KeenZOO_full_*.tar.gz 2>/dev/null
    done | while IFS= read -r _pa_f; do
        _pa_n="${_pa_f##*-}"; _pa_n="${_pa_n%.tar.gz}"
        case "$_pa_n" in
            ''|*[!0-9]*) _pa_n=0 ;;
        esac
        printf '%s %s\n' "$_pa_n" "$_pa_f"
    done | sort -k1,1nr -k2,2r | head -1 | cut -d' ' -f2-
}

project_present() {
    [ -x "$OPT_BIN/deploy_bypass.sh" ] && return 0
    [ -d "$OPT_ETC/unblock" ] && return 0
    [ -d "$OPT_ETC/bot" ] && return 0
    return 1
}

require_entware() {
    [ -x "$OPKG_BIN" ] \
        || die "Entware не готова: нет исполняемого $OPKG_BIN. Сначала установите Entware через WEB/OPKG Keenetic"
}

require_archive() {
    [ -n "$ARC" ] \
        || die "не найден KeenZOO_full_*.tar.gz рядом с меню или в /tmp — сначала передайте архив на роутер"
}

# Распаковываем архив только когда действительно нужен свежий deploy.
# Бэкап/удаление установленного проекта не должны зависеть от архива.
load_archive_tools() {
    require_archive
    _lat_mark="$KZ_DIR/.from-$(basename "$ARC")"
    if [ -x "$KZ_DIR/opt/bin/deploy_bypass.sh" ] \
        && [ -f "$_lat_mark" ]; then
        KZ_BIN="$KZ_DIR/opt/bin"
        return 0
    fi
    rm -rf "$KZ_DIR"
    mkdir -p "$KZ_DIR" || die "$KZ_DIR недоступен для распаковки"
    tar xzf "$ARC" -C "$KZ_DIR" 2>/dev/null \
        || die "архив $ARC не распаковался (усечённый/битый?)"
    [ -x "$KZ_DIR/opt/bin/deploy_bypass.sh" ] \
        || die "в архиве нет исполняемого opt/bin/deploy_bypass.sh"
    : > "$_lat_mark"
    KZ_BIN="$KZ_DIR/opt/bin"
}

find_deploy() {
    if [ -x "$OPT_BIN/deploy_bypass.sh" ]; then
        printf '%s\n' "$OPT_BIN/deploy_bypass.sh"
        return 0
    fi
    [ -n "$KZ_BIN" ] && [ -x "$KZ_BIN/deploy_bypass.sh" ] || return 1
    printf '%s\n' "$KZ_BIN/deploy_bypass.sh"
}

ARC="$(pick_archive || true)"

echo ""
echo "═══════════════════ KeenZOO ═══════════════════"
printf '   Архив: %s\n' "${ARC:-НЕ НАЙДЕН — нужен только для установки/обновления}"
cat <<'MENU'
 1. Новая установка KeenZOO (на роутер с Entware)
 2. Обновление KeenZOO
 3. Бэкап KeenZOO
 4. Удаление KeenZOO
 5. Выход
═══════════════════════════════════════════════
MENU
printf 'Выбор [1-5]: '
read -r M_CH

case "$M_CH" in
    5|q|Q|0)
        echo "Выход."
        exit 0
        ;;
    1)
        require_entware
        if project_present; then
            die "KeenZOO уже установлен — для новой редакции выберите пункт 2 «Обновление»"
        fi
        load_archive_tools
        M_DP="$(find_deploy)" \
            || die "deploy_bypass.sh не найден в архиве"
        echo "→ Новая установка KeenZOO: sh $M_DP $ARC"
        exec sh "$M_DP" "$ARC"
        ;;
    2)
        require_entware
        project_present \
            || die "KeenZOO ещё не установлен — выберите пункт 1 «Новая установка»"
        # Ред. 26: обновление обязано выполняться deploy-скриптом ИЗ НОВОГО
        # архива. Иначе установленная старая копия не знает новых preflight/
        # consent-правил и применит их только после уже завершённого update.
        load_archive_tools
        M_DP="$KZ_BIN/deploy_bypass.sh"
        [ -x "$M_DP" ] || die "в новом архиве нет deploy_bypass.sh"
        echo "→ Обновление KeenZOO свежим deploy: sh $M_DP $ARC"
        exec sh "$M_DP" "$ARC"
        ;;
    3)
        require_entware
        project_present \
            || die "KeenZOO ещё не установлен — создавать бэкап нечего"
        M_BP="$OPT_BIN/backup_project.sh"
        [ -x "$M_BP" ] \
            || die "не найден установленный $M_BP"
        echo "→ Бэкап KeenZOO: sh $M_BP"
        exec sh "$M_BP"
        ;;
    4)
        require_entware
        project_present \
            || die "KeenZOO не установлен — удалять нечего"
        M_DP="$(find_deploy || true)"
        if [ -z "$M_DP" ] && [ -n "$ARC" ]; then
            load_archive_tools
            M_DP="$(find_deploy || true)"
        fi
        [ -n "$M_DP" ] \
            || die "deploy_bypass.sh не найден — автоматическое удаление невозможно"
        echo "→ Удаление KeenZOO (Entware останется): sh $M_DP -remove"
        exec sh "$M_DP" -remove
        ;;
    *)
        die "нет пункта «${M_CH}» — выберите 1-5"
        ;;
esac

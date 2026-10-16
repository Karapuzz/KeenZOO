#!/bin/sh
# KeenZOO_menu.sh — меню жизненного цикла проекта (ред. 30).
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

_menu_tar_safe() {
    # rc: 0 ок; 1 tar не читает целиком; 2 имена-атаки (абсолютные/«..»);
    # 3 недопустимая ссылка (nolink: любая; links-ok: hardlink всегда,
    # symlink с выходом за пределы своего каталога / абсолютной целью).
    _kts_f="$1"; _kts_mode="${2:-links-ok}"
    tar tzf "$_kts_f" >/dev/null 2>&1 || return 1
    tar tzf "$_kts_f" 2>/dev/null | grep -qE '^/|(^|/)\.\.(/|$)' && return 2
    # G18 (аудиты v13-4.1 / rev19-P2): verbose-листинг — единственный
    # источник типов членов без спецпарсера, но человекочитаемый формат
    # разный: GNU tar показывает symlink «l… имя -> цель» и hardlink
    # «h… имя link to цель», а BusyBox — symlink «lrw… имя -> цель» и
    # hardlink «-rw… имя -> цель» (без буквы h: grep '^[lh]' был к нему
    # слеп, и nolink его пропускал). Две крайности парсинга закрыты так:
    # имя члена НЕ извлекается из verbose-строки (ломалось о пробелы в
    # имени) — берётся из обычного «tar tzf» по порядковому номеру строки
    # (оба listing'а идут по архиву в одном порядке, член = строка);
    # цель symlink'а — суффикс после последнего « -> ». Компоненты «.»
    # нормализуются и в имени, и в цели (старый подсчёт глубины на
    # «opt/./x» занижал/завышал родительский каталог). Повторный « -> »
    # внутри имени/цели (неоднозначный разбор) — недоверие, rc=3.
    # hardlink запрещён в обоих режимах: внутридеревных hardlink не несут
    # ни EN-установщики (187 symlink, 0 hardlink — сверено), ни проект.
    _kts_n="/tmp/.kts_names.$$"
    _kts_v="/tmp/.kts_verbose.$$"
    # GNU tar по умолчанию экранирует control bytes и тем самым скрывает
    # их от побайтового grep ниже. Если поддерживается literal quoting,
    # просим сырой listing; BusyBox такой опции не знает и идёт fallback.
    _kts_q=""
    if tar tzf "$_kts_f" --quoting-style=literal >/dev/null 2>&1; then
        _kts_q="--quoting-style=literal"
    fi
    # shellcheck disable=SC2086  # пусто либо один доверенный long-option
    tar tzf  "$_kts_f" $_kts_q 2>/dev/null > "$_kts_n" \
        || { rm -f "$_kts_n"; return 1; }
    # shellcheck disable=SC2086
    tar tzvf "$_kts_f" $_kts_q 2>/dev/null > "$_kts_v" \
        || { rm -f "$_kts_n" "$_kts_v"; return 1; }
    # G25 (ред. 27): ниже member и verbose-запись сопоставляются по FNR.
    # BusyBox печатает LF внутри symlink target как новую физическую строку:
    # без проверки кардинальности хвост цели терял связь со ссылкой и мог
    # скрыть выход через «..». Любое расхождение = недоверенный архив.
    _kts_nc="$(wc -l < "$_kts_n" 2>/dev/null | tr -d ' ')"
    _kts_vc="$(wc -l < "$_kts_v" 2>/dev/null | tr -d ' ')"
    if [ -z "$_kts_nc" ] || [ "$_kts_nc" != "$_kts_vc" ]; then
        rm -f "$_kts_n" "$_kts_v"
        return 3
    fi
    # Каждая физическая строка verbose-listing обязана быть полноценной
    # tar-записью с десятисимвольным mode. Встроенный LF в имени/target
    # создаёт строку-продолжение; её нельзя молча принять за новый member.
    if ! LC_ALL=C awk '
        !/^[bcdlpsh-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][rwxStTs-][[:space:]]/ { bad=1 }
        END { exit bad }' "$_kts_v" 2>/dev/null; then
        rm -f "$_kts_n" "$_kts_v"
        return 3
    fi
    # CR/TAB/ESC/DEL и прочие видимые control bytes в имени/цели также
    # запрещены. LF-разделители строк grep не считает частью записи, а
    # внедрённый LF уже закрыт инвариантом числа строк выше.
    if LC_ALL=C grep -q '[[:cntrl:]]' "$_kts_n" "$_kts_v" 2>/dev/null; then
        rm -f "$_kts_n" "$_kts_v"
        return 3
    fi
    _kts_bad="$(awk -v mode="$_kts_mode" '
        FNR==NR { kz_nm[FNR]=$0; next }
        {
            sig=substr($0,1,1)
            narr=split($0,kz_s," -> ")
            ishl=(index($0," link to ")>0)
            isbb=(sig!="l" && narr>1)            # BusyBox hardlink
            if (!(sig=="l" || sig=="h" || isbb || ishl)) next
            if (mode=="nolink") { print 3; exit }
            if (sig=="h" || isbb || ishl) { print 3; exit }
            if (narr>2) { print 3; exit }        # неоднозначный разбор
            nm=kz_nm[FNR]
            while (substr(nm,1,2)=="./") nm=substr(nm,3)
            nd=split(nm,kz_a,"/"); depth=-1
            for (i=1;i<=nd;i++) if (kz_a[i]!="" && kz_a[i]!=".") depth++
            tgt=kz_s[narr]
            if (substr(tgt,1,1)=="/") { print 3; exit }
            m=split(tgt,kz_c,"/"); cur=depth
            for (i=1;i<=m;i++) {
                if (kz_c[i]=="" || kz_c[i]==".") continue
                if (kz_c[i]=="..") { cur--; if (cur<0) { print 3; exit } }
                else cur++
            }
        }' "$_kts_n" "$_kts_v" 2>/dev/null)"
    _kts_arc=$?
    rm -f "$_kts_n" "$_kts_v"
    [ "$_kts_arc" = 0 ] || return 1
    [ "$_kts_bad" = "3" ] && return 3
    return 0
}

SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" 2>/dev/null && pwd)" \
    || die "не удалось определить каталог скрипта"
KZ_DIR="${KZ_MENU_TMPDIR:-/tmp/keenzoo-menu.$$}"
case "$KZ_DIR" in
    /tmp/?*) : ;;
    *) die "небезопасный временный каталог: $KZ_DIR (разрешён только непустой путь внутри /tmp)" ;;
esac
case "/${KZ_DIR#/tmp/}/" in
    *'/../'*|*'/./'*|*'//'*) die "небезопасный временный каталог: $KZ_DIR (компоненты . и .. запрещены)" ;;
esac
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
    # Меню одноразовое и после выбора делает exec: кэш не нужен. Старый
    # marker учитывал только basename архива и мог запустить deploy из
    # предыдущей редакции при замене файла с тем же именем.
    rm -rf "$KZ_DIR"
    (umask 077 && mkdir -p "$KZ_DIR") \
        || die "$KZ_DIR недоступен для распаковки"
    _lat_arc="$KZ_DIR/archive.tar.gz"
    cp "$ARC" "$_lat_arc" \
        || die "не удалось создать защищённый snapshot архива"
    _lat_rc=0
    _menu_tar_safe "$_lat_arc" nolink || _lat_rc=$?
    case "$_lat_rc" in
        0) : ;;
        1) die "архив не читается целиком" ;;
        2) die "архив содержит абсолютный путь или ../" ;;
        *) die "архив содержит ссылку/control-byte" ;;
    esac
    if tar tzf "$_lat_arc" 2>/dev/null \
        | grep -qvE '^(\./)?(opt/|opt$|$)'; then
        die "архив содержит файлы вне opt/"
    fi
    tar xzf "$_lat_arc" -C "$KZ_DIR" 2>/dev/null \
        || die "архив $ARC не распаковался (усечённый/битый?)"
    [ -x "$KZ_DIR/opt/bin/deploy_bypass.sh" ] \
        || die "в архиве нет исполняемого opt/bin/deploy_bypass.sh"
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

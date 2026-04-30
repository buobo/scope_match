# -*- coding: utf-8 -*-
# scope_sticky_braces.py
# IDA 9.0 IDAPython plugin

import os
import re
import sys
import glob
import html
import weakref

import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_lines

try:
    import ida_name
except Exception:
    ida_name = None

try:
    import ida_segment
except Exception:
    ida_segment = None

try:
    import ida_funcs
except Exception:
    ida_funcs = None

try:
    import ida_typeinf
except Exception:
    ida_typeinf = None

try:
    import ida_nalt
except Exception:
    ida_nalt = None

try:
    import ida_diskio
except Exception:
    ida_diskio = None

try:
    import ida_registry
except Exception:
    ida_registry = None


def _get_ida_kernel_version_tuple():
    for module in (ida_kernwin, ida_idaapi):
        try:
            fn = getattr(module, "get_kernel_version", None)
            if callable(fn):
                value = str(fn())
                m = re.search(r"(\d+)\.(\d+)", value)
                if m:
                    return int(m.group(1)), int(m.group(2)), value
        except Exception:
            pass
    return 0, 0, "unknown"


IDA_VERSION_MAJOR, IDA_VERSION_MINOR, IDA_VERSION_TEXT = _get_ida_kernel_version_tuple()
IDA_GE_92 = (IDA_VERSION_MAJOR, IDA_VERSION_MINOR) >= (9, 2)
IDA92_SAFE_MODE = IDA_GE_92


PLUGIN_NAME = "scope_match"
PLUGIN_VERSION = "v21-ida90-ida92-brace-color-20260430"
BACK_JUMP_STACK_MAX = 10
BACK_JUMP_STACK = []
TARGET_LINE_BELOW_STICKY_OVERLAY = True
TARGET_LINE_EXTRA_TOP_PADDING_ROWS = 0

UPDATE_INTERVAL_MS = 160
MAX_STICKY_LEVELS = 10
TEXT_MAX_LEN = 180

PANEL_MARGIN_LEFT = 0
PANEL_MARGIN_RIGHT = 0
PANEL_MARGIN_TOP = 0
PANEL_MARGIN_BOTTOM = 0

ROW_HEIGHT_DEFAULT = 20
ROW_HEIGHT_MIN = 16
ROW_HEIGHT_MAX = 36

TEXT_LEFT_PADDING = 0
TEXT_RIGHT_PADDING = 0

PRESERVE_HEXRAYS_TEXT_INDENT = True
INDENT_TAB_SIZE = 2
INDENT_MAX_COLS = 120

ENABLE_GUTTER_LINE_OVERLAY = True
LINE_NO_OVERLAY_MIN_WIDTH = 34
LINE_NO_OVERLAY_MAX_WIDTH = 72
LINE_NO_OVERLAY_IDA92_MIN_WIDTH = 44
LINE_NO_OVERLAY_IDA92_TEXT_LEFT_MAX = 170
LINE_NO_OVERLAY_IDA92_MARKER_MARGIN_MIN = 48
LINE_NO_OVERLAY_IDA92_MARKER_MARGIN_MAX = 68
LINE_NO_OVERLAY_IDA92_MARKER_MARGIN_RATIO = 1.25
LINE_NO_OVERLAY_LEFT_PAD = 2
LINE_NO_OVERLAY_RIGHT_PAD = 6
LINE_NO_OVERLAY_COLOR = "#555555"
LINE_NO_OVERLAY_BG_ALPHA = 242
LINE_NO_OVERLAY_BORDER = "#cfd3d9"
LINE_NO_OVERLAY_SEPARATOR = "#e5e7eb"

GUTTER_DETECT_MAX_LEFT = 140
GUTTER_DETECT_MAX_TOP = 32
GUTTER_DETECT_MAX_DEPTH = 5

USE_SCROLLBAR_TOP_LINE = True
BOTTOM_TOUCH_PROMOTION = True
ENABLE_HEXRAYS_BRACE_COLOR = True
ENABLE_STICKY_COLORED_TEXT = True

# Compatibility/performance knobs. In IDA 9.2, Hex-Rays runs on Qt6/PySide6.
# The sticky/gutter overlay uses the v20 screen-level implementation. Brace
# coloring is enabled for both 9.0 and 9.2, but the coloring routine is kept
# idempotent and refresh-time recoloring is skipped on 9.2 to avoid recursive
# Hex-Rays refresh loops.
ENABLE_HEXRAYS_TEXT_REWRITE = ENABLE_HEXRAYS_BRACE_COLOR
IDA92_SKIP_TEXT_REWRITE_ON_REFRESH = True
UPDATE_DEBOUNCE_MS = 40 if IDA92_SAFE_MODE else 0
TIMER_UPDATE_INTERVAL_MS = 500 if IDA92_SAFE_MODE else UPDATE_INTERVAL_MS
# In IDA 9.2, draw the sticky text and line-number gutter in one overlay
# parented to the stable pseudocode root widget. This keeps the row->scope
# mapping identical to the original plugin and avoids the separate gutter widget
# drifting to the right when focus changes.
USE_INTEGRATED_ROOT_OVERLAY = IDA92_SAFE_MODE
# IDA 9.2 exposes the pseudocode view as multiple Qt6 widgets. A child widget
# cannot reliably cover the original line-number gutter if the converted widget
# is already the inner code viewport. Therefore, on IDA 9.2 we draw the sticky
# overlay as a small top-level tool window using global screen coordinates.
# The jump source remains the real pseudocode widget, so row->scope mapping is unchanged.
USE_SCREEN_STICKY_OVERLAY = IDA92_SAFE_MODE

BRACE_SCOLOR_SEQUENCE = [
    "SCOLOR_NUMBER",
    "SCOLOR_STRING",
    "SCOLOR_CNAME",
    "SCOLOR_KEYWORD",
    "SCOLOR_LOCNAME",
    "SCOLOR_IMPNAME",
    "SCOLOR_LIBNAME",
    "SCOLOR_MACRO",
    "SCOLOR_ALTOPND",
    "SCOLOR_SEGNAME",
    "SCOLOR_CHAR",
]

BOTTOM_PROMOTION_KINDS = {
    "if",
    "else if",
    "else",
    "for",
    "while",
    "switch",
    "do",
    "try",
    "catch",
    "case",
    "default",
}

BRANCH_KINDS = {
    "if",
    "else if",
    "else",
    "case",
    "default",
    "catch",
}

BRANCH_CONTINUATION_WORDS = {
    "else",
    "catch",
    "finally",
}

CONTROL_WORD_RE = re.compile(
    r"\b(else\s+if|if|else|for|while|switch|do|try|catch|case|default)\b",
    re.IGNORECASE,
)

C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "int", "long",
    "register", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
    "__int8", "__int16", "__int32", "__int64", "__fastcall", "__stdcall",
    "__cdecl", "__thiscall", "__usercall", "__noreturn", "_BYTE", "_WORD",
    "_DWORD", "_QWORD", "bool", "true", "false", "nullptr", "NULL",
}

IMPORT_NAME_CACHE = None
IMPORT_EA_CACHE = None
FUNCTION_TOKEN_KIND_CACHE = {}


# IDA 9.2 moved to Qt6/PySide6. Prefer PySide6 there; keep PyQt5 first on IDA 9.0/9.1.
QtCore = None
QtGui = None
QtWidgets = None
QT_BINDING = None

if IDA_GE_92:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets
        QT_BINDING = "PySide6"
    except Exception:
        QtCore = None
        QtGui = None
        QtWidgets = None
        QT_BINDING = None

if QtCore is None:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        QT_BINDING = "PyQt5"
    except Exception:
        try:
            from PySide6 import QtCore, QtGui, QtWidgets
            QT_BINDING = "PySide6"
        except Exception:
            QtCore = None
            QtGui = None
            QtWidgets = None
            QT_BINDING = None


def _const_value(name, fallback=None):
    try:
        return getattr(ida_lines, name)
    except Exception:
        return fallback


def _tag_char(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:1]
    if isinstance(value, bytes):
        try:
            return value.decode("latin1")[:1]
        except Exception:
            return ""
    if isinstance(value, int):
        try:
            return chr(value & 0xFF)
        except Exception:
            return ""
    try:
        return str(value)[:1]
    except Exception:
        return ""


def _pick_scolor_value(name, fallback=None):
    if fallback is None:
        fallback = _const_value("SCOLOR_DEFAULT", 0)
    try:
        return getattr(ida_lines, name)
    except Exception:
        return fallback


COLOR_ON_CH = _tag_char(_const_value("COLOR_ON", "\x01"))
COLOR_OFF_CH = _tag_char(_const_value("COLOR_OFF", "\x02"))
COLOR_ESC_CH = _tag_char(_const_value("COLOR_ESC", "\x03"))
COLOR_INV_CH = _tag_char(_const_value("COLOR_INV", "\x04"))

SCOLOR_ON_CH = _tag_char(_const_value("SCOLOR_ON", COLOR_ON_CH))
SCOLOR_OFF_CH = _tag_char(_const_value("SCOLOR_OFF", COLOR_OFF_CH))
SCOLOR_ESC_CH = _tag_char(_const_value("SCOLOR_ESC", COLOR_ESC_CH))
SCOLOR_INV_CH = _tag_char(_const_value("SCOLOR_INV", COLOR_INV_CH))

COLOR_ADDR_CH = _tag_char(_const_value("COLOR_ADDR", None))
COLOR_ADDR_SIZE = int(_const_value("COLOR_ADDR_SIZE", 16) or 16)

ON_TAGS = {COLOR_ON_CH, SCOLOR_ON_CH}
OFF_TAGS = {COLOR_OFF_CH, SCOLOR_OFF_CH}
ESC_TAGS = {COLOR_ESC_CH, SCOLOR_ESC_CH}
INV_TAGS = {COLOR_INV_CH, SCOLOR_INV_CH}

ON_TAGS.discard("")
OFF_TAGS.discard("")
ESC_TAGS.discard("")
INV_TAGS.discard("")


def _build_scolor_name_map():
    result = {}

    for name in dir(ida_lines):
        if not name.startswith("SCOLOR_"):
            continue
        try:
            value = getattr(ida_lines, name)
        except Exception:
            continue

        result[value] = name

        ch = _tag_char(value)
        if ch:
            result[ch] = name

        if isinstance(value, int):
            result[value & 0xFF] = name

    alias = {
        "SCOLOR_ALTOPND": ["SCOLOR_ALTOP", "SCOLOR_ALTNAME"],
    }

    for canonical, names in alias.items():
        for alias_name in names:
            try:
                value = getattr(ida_lines, alias_name)
            except Exception:
                continue

            result[value] = canonical

            ch = _tag_char(value)
            if ch:
                result[ch] = canonical

            if isinstance(value, int):
                result[value & 0xFF] = canonical

    return result


SCOLOR_NAME_MAP = _build_scolor_name_map()

SCOLOR_TO_CSS_PROPS = {
    "SCOLOR_DEFAULT": ["qproperty-line-fg-default"],
    "SCOLOR_REGCMT": ["qproperty-line-fg-regular-comment"],
    "SCOLOR_RPTCMT": ["qproperty-line-fg-repeatable-comment"],
    "SCOLOR_AUTOCMT": ["qproperty-line-fg-automatic-comment"],
    "SCOLOR_INSN": ["qproperty-line-fg-insn"],
    "SCOLOR_DATNAME": ["qproperty-line-fg-dummy-data-name"],
    "SCOLOR_DNAME": ["qproperty-line-fg-regular-data-name"],
    "SCOLOR_DEMNAME": ["qproperty-line-fg-demangled-name"],
    "SCOLOR_SYMBOL": ["qproperty-line-fg-punctuation"],
    "SCOLOR_CHAR": ["qproperty-line-fg-charlit-in-insn"],
    "SCOLOR_STRING": ["qproperty-line-fg-strlit-in-insn"],
    "SCOLOR_NUMBER": ["qproperty-line-fg-numlit-in-insn"],
    "SCOLOR_VOIDOP": ["qproperty-line-fg-void-opnd"],
    "SCOLOR_CREF": ["qproperty-line-fg-code-xref"],
    "SCOLOR_DREF": ["qproperty-line-fg-data-xref"],
    "SCOLOR_CREFTAIL": ["qproperty-line-fg-code-xref-to-tail"],
    "SCOLOR_DREFTAIL": ["qproperty-line-fg-data-xref-to-tail"],
    "SCOLOR_ERROR": ["qproperty-line-fg-error"],
    "SCOLOR_PREFIX": ["qproperty-line-fg-line-prefix"],
    "SCOLOR_BINPREF": ["qproperty-line-fg-opcode-byte"],
    "SCOLOR_EXTRA": ["qproperty-line-fg-extra-line"],
    "SCOLOR_ALTOPND": ["qproperty-line-fg-alt-opnd"],
    "SCOLOR_ALTOP": ["qproperty-line-fg-alt-opnd"],
    "SCOLOR_ALTNAME": ["qproperty-line-fg-alt-opnd"],
    "SCOLOR_HIDNAME": ["qproperty-line-fg-hidden"],
    "SCOLOR_LIBNAME": ["qproperty-line-fg-libfunc"],
    "SCOLOR_LOCNAME": ["qproperty-line-fg-locvar"],
    "SCOLOR_CODNAME": ["qproperty-line-fg-dummy-code-name"],
    "SCOLOR_DUMMY": ["qproperty-line-fg-dummy-code-name"],
    "SCOLOR_ASMDIR": ["qproperty-line-fg-asm-directive"],
    "SCOLOR_MACRO": ["qproperty-line-fg-macro"],
    "SCOLOR_DSTR": ["qproperty-line-fg-strlit-in-data"],
    "SCOLOR_DCHAR": ["qproperty-line-fg-charlit-in-data"],
    "SCOLOR_DNUM": ["qproperty-line-fg-numlit-in-data"],
    "SCOLOR_KEYWORD": ["qproperty-line-fg-keyword"],
    "SCOLOR_REG": ["qproperty-line-fg-register-name"],
    "SCOLOR_IMPNAME": ["qproperty-line-fg-import-name"],
    "SCOLOR_SEGNAME": ["qproperty-line-fg-segment-name"],
    "SCOLOR_UNKNAME": ["qproperty-line-fg-dummy-unknown-name"],
    "SCOLOR_CNAME": ["qproperty-line-fg-code-name"],
    "SCOLOR_UNAME": ["qproperty-line-fg-unknown-name"],
    "SCOLOR_COLLAPSED": ["qproperty-line-fg-collapsed-line"],
}

CSS_LIGHT_PROPS = {}
CSS_DARK_PROPS = {}
CSS_LOADED_FILES = []
CSS_LOAD_DONE = False
CSS_CURRENT_THEME_NAME = ""


def _normalize_color_value(value):
    value = str(value or "").strip()
    value = value.strip("'\"")

    if not value:
        return ""

    if value.endswith("!important"):
        value = value[:-10].strip()

    if value.lower() in ("transparent", "none"):
        return value.lower()

    value = re.sub(r"\s+", " ", value)

    m = re.fullmatch(
        r"rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*[\d.]+)?\s*\)",
        value,
        re.IGNORECASE,
    )

    if m:
        r = max(0, min(255, int(m.group(1))))
        g = max(0, min(255, int(m.group(2))))
        b = max(0, min(255, int(m.group(3))))
        return "#{:02x}{:02x}{:02x}".format(r, g, b)

    if QtGui is not None:
        try:
            color = QtGui.QColor(value)
            if color.isValid():
                return color.name()
        except Exception:
            pass

    return value


def _strip_css_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _read_text_file(path):
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception:
            return ""
    return ""


def _append_existing_path(paths, path):
    if not path:
        return
    try:
        path = os.path.abspath(path)
    except Exception:
        return
    if os.path.exists(path) and path not in paths:
        paths.append(path)


def _find_ida_roots():
    roots = []

    env_idadir = os.environ.get("IDADIR")
    if env_idadir:
        _append_existing_path(roots, env_idadir)

    for attr_name in ("idadir", "IDA_DIR", "IDADIR"):
        try:
            attr = getattr(ida_idaapi, attr_name, None)
            value = attr() if callable(attr) else attr
        except Exception:
            value = None

        if isinstance(value, str) and value:
            _append_existing_path(roots, value)

    try:
        _append_existing_path(roots, os.path.dirname(sys.executable))
    except Exception:
        pass

    _append_existing_path(roots, r"D:\Program Files\IDA Professional 9.0")
    _append_existing_path(roots, r"C:\Program Files\IDA Professional 9.0")
    _append_existing_path(roots, r"C:\Program Files\IDA Pro 9.0")

    result = []
    for root in roots:
        if root not in result:
            result.append(root)
    return result


def _get_ida_user_dir():
    if ida_diskio is not None:
        try:
            path = ida_diskio.get_user_idadir()
            if path and os.path.exists(path):
                return os.path.abspath(path)
        except Exception:
            pass

    env_idausr = os.environ.get("IDAUSR")
    if env_idausr:
        first = env_idausr.split(os.pathsep)[0].strip()
        if first and os.path.exists(first):
            return os.path.abspath(first)

    home = os.path.expanduser("~")
    candidates = [
        os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro"),
        os.path.join(home, ".idapro"),
    ]

    for path in candidates:
        if path and os.path.exists(path):
            return os.path.abspath(path)

    return ""


def _theme_roots():
    roots = []

    for root in _find_ida_roots():
        _append_existing_path(roots, os.path.join(root, "themes"))

    user_dir = _get_ida_user_dir()
    if user_dir:
        _append_existing_path(roots, os.path.join(user_dir, "themes"))

    return roots


def _list_installed_theme_names():
    names = set()

    for themes_root in _theme_roots():
        try:
            for name in os.listdir(themes_root):
                theme_dir = os.path.join(themes_root, name)
                if not os.path.isdir(theme_dir):
                    continue
                if name.lower() == "_base":
                    continue
                if os.path.exists(os.path.join(theme_dir, "theme.css")):
                    names.add(name)
        except Exception:
            pass

    return names


def _clean_theme_name(value):
    value = str(value or "").strip()
    value = value.strip("'\"")

    if not value:
        return ""

    value = value.replace("\\", "/")
    value = value.rstrip("/")

    if "/" in value:
        value = value.split("/")[-1]

    if value.lower().endswith(".css"):
        value = os.path.splitext(value)[0]

    value = value.strip()
    if not value:
        return ""

    if value.lower() in ("_base", "theme", "user"):
        return ""

    return value


def _read_registry_string(name, subkey=None):
    if ida_registry is None:
        return ""

    try:
        value = ida_registry.reg_read_string(name, subkey, "")
        if value:
            return str(value)
    except Exception:
        pass

    try:
        value = ida_registry.reg_read_string(name, subkey)
        if value:
            return str(value)
    except Exception:
        pass

    return ""


def _registry_subkey_join(parent, child):
    parent = str(parent or "").strip("\\/")
    child = str(child or "").strip("\\/")
    if not parent:
        return child
    if not child:
        return parent
    return parent + "\\" + child


def _iter_registry_strings(subkey="", depth=0, max_depth=4, seen=None):
    if ida_registry is None:
        return

    if seen is None:
        seen = set()

    key = str(subkey or "")
    if key in seen:
        return
    seen.add(key)

    try:
        values = ida_registry.reg_subkey_values(key)
    except Exception:
        values = []

    for value_name in values or []:
        text = _read_registry_string(str(value_name), key if key else None)
        if text:
            yield text

    if depth >= max_depth:
        return

    try:
        subkeys = ida_registry.reg_subkey_subkeys(key)
    except Exception:
        subkeys = []

    for child in subkeys or []:
        child_key = _registry_subkey_join(key, child)
        for text in _iter_registry_strings(child_key, depth + 1, max_depth, seen):
            yield text


def _get_current_ida_theme_name():
    global CSS_CURRENT_THEME_NAME

    if CSS_CURRENT_THEME_NAME:
        return CSS_CURRENT_THEME_NAME

    installed_names = _list_installed_theme_names()
    installed_lower = {name.lower(): name for name in installed_names}

    env_theme = _clean_theme_name(os.environ.get("IDA_THEME") or os.environ.get("IDA_CURRENT_THEME"))
    if env_theme and env_theme.lower() in installed_lower:
        CSS_CURRENT_THEME_NAME = installed_lower[env_theme.lower()]
        return CSS_CURRENT_THEME_NAME

    direct_registry_candidates = [
        ("ThemeName", None),
        ("CurrentTheme", None),
        ("Current theme", None),
        ("Theme", None),
        ("ThemeName", "Theme"),
        ("CurrentTheme", "Theme"),
        ("Current theme", "Theme"),
        ("Name", "Theme"),
        ("ThemeName", "Colors"),
        ("CurrentTheme", "Colors"),
        ("Current theme", "Colors"),
        ("Current", "Colors"),
    ]

    for value_name, subkey in direct_registry_candidates:
        candidate = _clean_theme_name(_read_registry_string(value_name, subkey))
        if candidate and candidate.lower() in installed_lower:
            CSS_CURRENT_THEME_NAME = installed_lower[candidate.lower()]
            return CSS_CURRENT_THEME_NAME

    for text in _iter_registry_strings():
        candidate = _clean_theme_name(text)
        if candidate and candidate.lower() in installed_lower:
            CSS_CURRENT_THEME_NAME = installed_lower[candidate.lower()]
            return CSS_CURRENT_THEME_NAME

    dark = False
    if QtWidgets is not None and QtGui is not None:
        try:
            app = QtWidgets.QApplication.instance()
            if app is not None:
                for prop_name in ("theme", "themeName", "currentTheme", "current_theme", "idaTheme"):
                    try:
                        candidate = _clean_theme_name(app.property(prop_name))
                        if candidate and candidate.lower() in installed_lower:
                            CSS_CURRENT_THEME_NAME = installed_lower[candidate.lower()]
                            return CSS_CURRENT_THEME_NAME
                    except Exception:
                        pass

                base = app.palette().color(QtGui.QPalette.Base)
                dark = base.lightness() < 128
        except Exception:
            dark = False

    preferred = "dark" if dark else "default"
    if preferred.lower() in installed_lower:
        CSS_CURRENT_THEME_NAME = installed_lower[preferred.lower()]
        return CSS_CURRENT_THEME_NAME

    if installed_names:
        for fallback in ("default", "dark"):
            if fallback in installed_lower:
                CSS_CURRENT_THEME_NAME = installed_lower[fallback]
                return CSS_CURRENT_THEME_NAME

        CSS_CURRENT_THEME_NAME = sorted(installed_names)[0]
        return CSS_CURRENT_THEME_NAME

    CSS_CURRENT_THEME_NAME = preferred
    return CSS_CURRENT_THEME_NAME


def _find_theme_file(theme_name, file_name):
    result = []

    theme_name = _clean_theme_name(theme_name)
    if not theme_name:
        return result

    for themes_root in _theme_roots():
        path = os.path.join(themes_root, theme_name, file_name)
        _append_existing_path(result, path)

    return result


def _read_imported_themes_from_css(path):
    text = _read_text_file(path)
    if not text:
        return []

    text = _strip_css_comments(text)

    imports = []
    for m in re.finditer(r"@importtheme\s+['\"]?([^'\";\r\n]+)['\"]?\s*;", text, re.IGNORECASE):
        name = _clean_theme_name(m.group(1))
        if name:
            imports.append(name)

    return imports


def _expand_theme_css_files(theme_name, seen=None):
    if seen is None:
        seen = set()

    theme_name = _clean_theme_name(theme_name)
    if not theme_name:
        return []

    key = theme_name.lower()
    if key in seen:
        return []
    seen.add(key)

    files = []

    theme_css_files = _find_theme_file(theme_name, "theme.css")

    for css_path in theme_css_files:
        for imported_theme in _read_imported_themes_from_css(css_path):
            for imported_path in _expand_theme_css_files(imported_theme, seen):
                _append_existing_path(files, imported_path)

    for css_path in theme_css_files:
        _append_existing_path(files, css_path)

    for user_css_path in _find_theme_file(theme_name, "user.css"):
        _append_existing_path(files, user_css_path)

    return files


def _find_css_files():
    files = []

    theme_name = _get_current_ida_theme_name()

    for base_path in _find_theme_file("_base", "theme.css"):
        _append_existing_path(files, base_path)

    for legacy_base in _find_theme_file("_base", "_base.css"):
        _append_existing_path(files, legacy_base)

    for path in _expand_theme_css_files(theme_name):
        _append_existing_path(files, path)

    if files:
        return files

    for root in _find_ida_roots():
        candidates = [
            os.path.join(root, "themes", "_base", "theme.css"),
            os.path.join(root, "themes", "_base.css"),
            os.path.join(root, "themes", "default", "theme.css"),
            os.path.join(root, "themes", "dark", "theme.css"),
        ]

        for path in candidates:
            _append_existing_path(files, path)

    user_dir = _get_ida_user_dir()
    if user_dir:
        candidates = [
            os.path.join(user_dir, "themes", "_base", "theme.css"),
            os.path.join(user_dir, "themes", "default", "theme.css"),
            os.path.join(user_dir, "themes", "default", "user.css"),
            os.path.join(user_dir, "themes", "dark", "theme.css"),
            os.path.join(user_dir, "themes", "dark", "user.css"),
        ]

        for path in candidates:
            _append_existing_path(files, path)

    return files


def _substitute_css_value(value, variables):
    value = str(value or "").strip()

    def replace_dollar_var(m):
        name = m.group(1).strip().lower()
        return variables.get(name, m.group(0))

    value = re.sub(r"\$\{([^}]+)\}", replace_dollar_var, value)

    if value.startswith("@"):
        name = value[1:].strip().lower()
        value = variables.get(name, value)

    return value


def _parse_css_file(path, variables, light_props, dark_props):
    text = _read_text_file(path)
    if not text:
        return False

    text = _strip_css_comments(text)

    for name, value in re.findall(r"@def\s+([\w\-]+)\s+([^;]+);", text):
        variables[name.strip().lower()] = value.strip()

    for name, value in re.findall(r"@([\w\-]+)\s*:\s*([^;]+);", text):
        variables[name.strip().lower()] = value.strip()

    block_re = re.compile(r"([^{}]+)\{([^{}]*)\}", re.DOTALL)
    parsed_any = False

    for selector, body in block_re.findall(text):
        selector = selector.strip()
        if "CustomIDAMemo" not in selector:
            continue

        is_dark = 'os-dark-theme="true"' in selector or "os-dark-theme='true'" in selector
        props = dark_props if is_dark else light_props

        for prop_name, prop_value in re.findall(r"(qproperty-[\w\-]+)\s*:\s*([^;]+);", body):
            prop_name = prop_name.strip().lower()
            prop_value = _substitute_css_value(prop_value.strip(), variables)
            props[prop_name] = _normalize_color_value(prop_value)
            parsed_any = True

    return parsed_any


def _ensure_css_loaded():
    global CSS_LOAD_DONE, CSS_LIGHT_PROPS, CSS_DARK_PROPS, CSS_LOADED_FILES

    if CSS_LOAD_DONE:
        return

    variables = {}
    light_props = {}
    dark_props = {}
    loaded = []

    for path in _find_css_files():
        if _parse_css_file(path, variables, light_props, dark_props):
            loaded.append(path)

    CSS_LIGHT_PROPS = light_props
    CSS_DARK_PROPS = dark_props
    CSS_LOADED_FILES = loaded
    CSS_LOAD_DONE = True


def _css_color_for_scolor_name(scolor_name, dark=False, default="#121212"):
    _ensure_css_loaded()

    if not scolor_name:
        return _normalize_color_value(default)

    primary_table = CSS_DARK_PROPS if dark else CSS_LIGHT_PROPS
    secondary_table = CSS_LIGHT_PROPS if dark else CSS_DARK_PROPS
    candidates = SCOLOR_TO_CSS_PROPS.get(scolor_name, [])

    for prop in candidates:
        color = primary_table.get(prop.lower())
        if color:
            return _normalize_color_value(color)

    for prop in candidates:
        color = secondary_table.get(prop.lower())
        if color:
            return _normalize_color_value(color)

    return _normalize_color_value(default)


def _scolor_name_from_tag(tag_value):
    name = SCOLOR_NAME_MAP.get(tag_value)
    if name:
        return name
    return SCOLOR_NAME_MAP.get(_tag_char(tag_value), "")


def _is_dark_widget(widget):
    if widget is None:
        return False
    try:
        base = widget.palette().color(QtGui.QPalette.Base)
        return base.lightness() < 128
    except Exception:
        return False


def _html_escape_preserve_spaces(s):
    s = html.escape(str(s))
    s = s.replace(" ", "&nbsp;")
    s = s.replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;")
    return s


def _brace_scolor_name_for_index(color_index):
    if not BRACE_SCOLOR_SEQUENCE:
        return "SCOLOR_DEFAULT"
    return BRACE_SCOLOR_SEQUENCE[color_index % len(BRACE_SCOLOR_SEQUENCE)]


def _brace_scolor_value_for_index(color_index):
    return _pick_scolor_value(_brace_scolor_name_for_index(color_index))


def _strip_hexrays_hidden_artifacts_plain(s, keep_spacing=False):
    s = str(s)

    s = re.sub(r"(?<![0-9A-Za-z_])[0-9A-Fa-f]{8,}tag(?![0-9A-Za-z_])", "", s)
    s = re.sub(
        r"(?<![0-9A-Za-z_])[0-9A-Fa-f]{16,}(?=\s*(if|else|for|while|switch|case|default|do|try|catch|return|break|continue|goto)\b)",
        "",
        s,
    )
    s = re.sub(r"(?<=[\s\(\),=+\-*/%&|!<>?:;\[\]])[0-9A-Fa-f]{16,}(?=\s*[A-Za-z_])", "", s)
    s = re.sub(r"\bBtag\b", "", s)

    if keep_spacing:
        return s

    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\s+([,;:\)\]\}])", r"\1", s)
    s = re.sub(r"([\(\[\{])\s+", r"\1", s)
    return s.strip()


def _tag_remove_clean(s, strip=False):
    try:
        plain = ida_lines.tag_remove(str(s))
    except Exception:
        plain = str(s)

    plain = _strip_hexrays_hidden_artifacts_plain(plain, keep_spacing=True)
    if strip:
        return plain.strip()
    return plain


def _looks_like_leaked_anchor_at(s, i):
    m = re.match(r"[0-9A-Fa-f]{8,}tag", s[i:])
    if m:
        return len(m.group(0))

    m = re.match(r"[0-9A-Fa-f]{16,}", s[i:])
    if not m:
        return 0

    token = m.group(0)
    tail = s[i + len(token): i + len(token) + 16]

    if tail.startswith(" ") or tail.startswith("\t") or tail.startswith("(") or tail.startswith(")") or tail.startswith("_") or tail.startswith("Btag"):
        return len(token)

    return 0


def _append_segment(segments, text, tag_name):
    if text == "":
        return
    if segments and segments[-1]["tag"] == tag_name:
        segments[-1]["text"] += text
    else:
        segments.append({"text": text, "tag": tag_name})


def _skip_color_or_hidden(raw, i, out=None):
    s = str(raw)
    n = len(s)

    if i >= n:
        return i

    ch = s[i]

    if COLOR_ADDR_CH and ch == COLOR_ADDR_CH:
        end = min(n, i + 1 + COLOR_ADDR_SIZE)
        if out is not None:
            out.append(s[i:end])
        return end

    if ch in ON_TAGS:
        if i + 1 >= n:
            if out is not None:
                out.append(ch)
            return i + 1

        tag_value = s[i + 1]

        if COLOR_ADDR_CH and tag_value == COLOR_ADDR_CH:
            end = min(n, i + 2 + COLOR_ADDR_SIZE)
            if out is not None:
                out.append(s[i:end])
            return end

        if out is not None:
            out.append(s[i:i + 2])
        return i + 2

    if ch in OFF_TAGS:
        end = min(n, i + 2)
        if out is not None:
            out.append(s[i:end])
        return end

    if ch in INV_TAGS:
        if out is not None:
            out.append(ch)
        return i + 1

    leaked_len = _looks_like_leaked_anchor_at(s, i)
    if leaked_len > 0:
        end = i + leaked_len
        if out is not None:
            out.append(s[i:end])
        return end

    if s.startswith("Btag", i):
        end = i + 4
        if out is not None:
            out.append(s[i:end])
        return end

    return i


def _parse_tagged_line_to_segments(tagged_line, limit_visible=None):
    raw = str(tagged_line)
    segments = []
    tag_stack = []
    visible_count = 0

    def current_tag():
        if tag_stack:
            return tag_stack[-1]
        return None

    i = 0
    n = len(raw)

    while i < n:
        if limit_visible is not None and visible_count >= limit_visible:
            break

        ch = raw[i]

        if COLOR_ADDR_CH and ch == COLOR_ADDR_CH:
            i += 1 + COLOR_ADDR_SIZE
            continue

        if ch in ON_TAGS:
            if i + 1 >= n:
                i += 1
                continue

            tag_value = raw[i + 1]

            if COLOR_ADDR_CH and tag_value == COLOR_ADDR_CH:
                i += 2 + COLOR_ADDR_SIZE
                continue

            tag_name = _scolor_name_from_tag(tag_value)
            if tag_name:
                tag_stack.append(tag_name)

            i += 2
            continue

        if ch in OFF_TAGS:
            off_tag = None
            if i + 1 < n:
                off_tag = _scolor_name_from_tag(raw[i + 1])

            if tag_stack:
                if off_tag and off_tag in tag_stack:
                    for idx in range(len(tag_stack) - 1, -1, -1):
                        if tag_stack[idx] == off_tag:
                            del tag_stack[idx:]
                            break
                else:
                    tag_stack.pop()

            i += 2
            continue

        if ch in ESC_TAGS:
            if i + 1 < n:
                text_ch = raw[i + 1]
                _append_segment(segments, text_ch, current_tag())
                visible_count += 1
                i += 2
            else:
                i += 1
            continue

        if ch in INV_TAGS:
            i += 1
            continue

        leaked_len = _looks_like_leaked_anchor_at(raw, i)
        if leaked_len > 0:
            i += leaked_len
            continue

        if raw.startswith("Btag", i):
            i += 4
            continue

        _append_segment(segments, ch, current_tag())
        visible_count += 1
        i += 1

    cleaned = []
    for seg in segments:
        text = _strip_hexrays_hidden_artifacts_plain(seg["text"], keep_spacing=True)
        if text:
            _append_segment(cleaned, text, seg["tag"])

    return cleaned


def _segments_have_real_color(segments):
    for seg in segments:
        tag = seg.get("tag")
        if tag and tag != "SCOLOR_DEFAULT":
            return True
    return False


def _normalize_name_for_match(name):
    name = str(name or "").strip()
    if not name:
        return ""

    name = re.sub(r"@@.*$", "", name)
    name = re.sub(r"@plt$", "", name)
    name = re.sub(r"\.plt$", "", name)
    name = re.sub(r"_ptr$", "", name)

    while name.startswith("_") and len(name) > 1:
        name = name[1:]

    return name


def _build_import_caches():
    global IMPORT_NAME_CACHE, IMPORT_EA_CACHE

    if IMPORT_NAME_CACHE is not None and IMPORT_EA_CACHE is not None:
        return

    name_cache = {}
    ea_cache = set()

    if ida_nalt is not None:
        try:
            qty = ida_nalt.get_import_module_qty()
        except Exception:
            qty = 0

        for idx in range(qty):
            def cb(ea, name, ordinal):
                try:
                    if name:
                        raw = str(name)
                        norm = _normalize_name_for_match(raw)
                        name_cache[raw] = int(ea)
                        if norm:
                            name_cache[norm] = int(ea)
                    if ea != ida_idaapi.BADADDR:
                        ea_cache.add(int(ea))
                except Exception:
                    pass
                return True

            try:
                ida_nalt.enum_import_names(idx, cb)
            except Exception:
                pass

    IMPORT_NAME_CACHE = name_cache
    IMPORT_EA_CACHE = ea_cache


def _lookup_import_ea_by_name(token):
    _build_import_caches()

    if not IMPORT_NAME_CACHE:
        return ida_idaapi.BADADDR

    token = str(token)
    norm = _normalize_name_for_match(token)

    if token in IMPORT_NAME_CACHE:
        return IMPORT_NAME_CACHE[token]
    if norm in IMPORT_NAME_CACHE:
        return IMPORT_NAME_CACHE[norm]

    return ida_idaapi.BADADDR


def _get_name_ea(token):
    if ida_name is None:
        return ida_idaapi.BADADDR

    token = str(token)
    norm = _normalize_name_for_match(token)

    candidates = []
    if token:
        candidates.append(token)
    if norm and norm not in candidates:
        candidates.append(norm)
    if token and not token.startswith("_"):
        candidates.append("_" + token)
    if norm and not norm.startswith("_"):
        candidates.append("_" + norm)
    if token:
        candidates.append(token + "@plt")
        candidates.append(token + ".plt")
        candidates.append(token + "_ptr")
    if norm:
        candidates.append(norm + "@plt")
        candidates.append(norm + ".plt")
        candidates.append(norm + "_ptr")

    seen = set()
    dedup = []
    for item in candidates:
        if item and item not in seen:
            dedup.append(item)
            seen.add(item)

    for name in dedup:
        try:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
            if ea != ida_idaapi.BADADDR:
                return int(ea)
        except Exception:
            pass

    return ida_idaapi.BADADDR


def _get_tinfo_at_ea(ea):
    if ea is None or ea == ida_idaapi.BADADDR or ida_typeinf is None:
        return None

    try:
        tif = ida_typeinf.tinfo_t()
    except Exception:
        return None

    if ida_nalt is not None:
        try:
            if ida_nalt.get_tinfo(tif, ea):
                return tif
        except Exception:
            pass

    try:
        get_tinfo = getattr(ida_typeinf, "get_tinfo", None)
        if callable(get_tinfo):
            if get_tinfo(tif, ea):
                return tif
    except Exception:
        pass

    return None


def _tinfo_is_function(tif):
    if tif is None:
        return False

    for method_name in ("is_func", "is_funcptr"):
        try:
            method = getattr(tif, method_name, None)
            if callable(method) and method():
                return True
        except Exception:
            pass

    try:
        ftd = ida_typeinf.func_type_data_t()
        if tif.get_func_details(ftd):
            return True
    except Exception:
        pass

    return False


def _ea_segment_name(ea):
    if ida_segment is None or ea is None or ea == ida_idaapi.BADADDR:
        return ""

    try:
        seg = ida_segment.getseg(ea)
        if seg is None:
            return ""
        return (ida_segment.get_segm_name(seg) or "").lower()
    except Exception:
        return ""


def _ea_in_extern_or_import_segment(ea):
    seg_name = _ea_segment_name(ea)
    if not seg_name:
        return False

    if "extern" in seg_name or "import" in seg_name or ".plt" in seg_name or ".got" in seg_name or ".idata" in seg_name or ".dynsym" in seg_name:
        return True

    if ida_segment is not None:
        try:
            seg = ida_segment.getseg(ea)
            if seg is not None and seg.type == ida_segment.SEG_XTRN:
                return True
        except Exception:
            pass

    return False


def _func_flags_scolor(ea):
    if ida_funcs is None or ea is None or ea == ida_idaapi.BADADDR:
        return None

    try:
        func = ida_funcs.get_func(ea)
    except Exception:
        func = None

    if func is None:
        return None

    flags = 0
    try:
        flags = int(func.flags)
    except Exception:
        flags = 0

    try:
        if hasattr(ida_funcs, "FUNC_LIB") and (flags & ida_funcs.FUNC_LIB):
            return "SCOLOR_LIBNAME"
    except Exception:
        pass

    try:
        if hasattr(ida_funcs, "FUNC_THUNK") and (flags & ida_funcs.FUNC_THUNK):
            if _ea_in_extern_or_import_segment(ea):
                return "SCOLOR_IMPNAME"
            return "SCOLOR_CNAME"
    except Exception:
        pass

    return "SCOLOR_CNAME"


def _ida_function_scolor_for_name(token):
    token = str(token)
    if not token:
        return None

    cache_key = token
    if cache_key in FUNCTION_TOKEN_KIND_CACHE:
        return FUNCTION_TOKEN_KIND_CACHE[cache_key]

    import_ea = _lookup_import_ea_by_name(token)
    if import_ea != ida_idaapi.BADADDR:
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = "SCOLOR_IMPNAME"
        return "SCOLOR_IMPNAME"

    ea = _get_name_ea(token)
    if ea == ida_idaapi.BADADDR:
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = None
        return None

    _build_import_caches()
    if IMPORT_EA_CACHE and int(ea) in IMPORT_EA_CACHE:
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = "SCOLOR_IMPNAME"
        return "SCOLOR_IMPNAME"

    if _ea_in_extern_or_import_segment(ea):
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = "SCOLOR_IMPNAME"
        return "SCOLOR_IMPNAME"

    flag_kind = _func_flags_scolor(ea)
    if flag_kind is not None:
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = flag_kind
        return flag_kind

    tif = _get_tinfo_at_ea(ea)
    if _tinfo_is_function(tif):
        FUNCTION_TOKEN_KIND_CACHE[cache_key] = "SCOLOR_CNAME"
        return "SCOLOR_CNAME"

    FUNCTION_TOKEN_KIND_CACHE[cache_key] = None
    return None


TOKEN_RE = re.compile(
    r"""
    (?P<space>\s+)
    |(?P<string>"(?:\\.|[^"\\])*")
    |(?P<char>'(?:\\.|[^'\\])*')
    |(?P<number>\b(?:0x[0-9A-Fa-f]+|\d+)\b)
    |(?P<ident>\b[A-Za-z_][A-Za-z0-9_]*\b)
    |(?P<op>==|!=|<=|>=|&&|\|\||<<|>>|->|\+\+|--)
    |(?P<punct>.)
    """,
    re.VERBOSE,
)


def _fallback_scolor_for_token(kind, token, following_text, lvar_names):
    token = str(token)

    if kind == "space":
        return None
    if kind == "string":
        return "SCOLOR_DSTR"
    if kind == "char":
        return "SCOLOR_DCHAR"
    if kind == "number":
        return "SCOLOR_INSN"
    if kind == "op":
        return "SCOLOR_SYMBOL"
    if kind == "punct":
        if token in "{}":
            return "SCOLOR_CNAME"
        return "SCOLOR_SYMBOL"

    if kind != "ident":
        return None

    if token in C_KEYWORDS:
        return "SCOLOR_KEYWORD"

    if token in lvar_names:
        return "SCOLOR_DREF"

    if re.fullmatch(r"v\d+|a\d+|arg_[0-9A-Fa-f]+|var_[0-9A-Fa-f]+", token):
        return "SCOLOR_DREF"

    if str(following_text).lstrip().startswith("("):
        ida_kind = _ida_function_scolor_for_name(token)
        if ida_kind:
            return ida_kind
        return "SCOLOR_CNAME"

    if re.fullmatch(r"sub_[0-9A-Fa-f]+|loc_[0-9A-Fa-f]+|LABEL_[0-9A-Za-z_]+", token):
        return "SCOLOR_CNAME"

    if re.fullmatch(r"(off|byte|word|dword|qword)_[0-9A-Fa-f]+", token):
        return "SCOLOR_DNAME"

    if re.fullmatch(r"unk_[0-9A-Fa-f]+", token):
        return "SCOLOR_UNKNAME"

    return "SCOLOR_DEFAULT"


def _fallback_colorize_plain_text(text, lvar_names):
    text = str(text)
    segments = []

    for m in TOKEN_RE.finditer(text):
        kind = m.lastgroup
        token = m.group(0)
        following = text[m.end():]
        tag = _fallback_scolor_for_token(kind, token, following, lvar_names)
        _append_segment(segments, token, tag)

    return segments


def _trim_segments(segments, max_len):
    total = 0
    result = []

    for seg in segments:
        text = seg["text"]

        if total + len(text) <= max_len:
            result.append(dict(seg))
            total += len(text)
            continue

        remain = max_len - total
        if remain > 3:
            new_seg = dict(seg)
            new_seg["text"] = text[:remain - 3] + "..."
            result.append(new_seg)
        elif remain > 0:
            new_seg = dict(seg)
            new_seg["text"] = text[:remain]
            result.append(new_seg)
        break

    return result


def _segments_to_html(segments, dark=False, default_color="#121212"):
    parts = []
    for seg in segments:
        text = seg.get("text", "")
        tag = seg.get("tag")
        color = _css_color_for_scolor_name(tag, dark=dark, default=default_color) if tag else default_color
        if not text:
            continue
        parts.append(
            '<span style="color:%s;">%s</span>' % (color, _html_escape_preserve_spaces(text))
        )
    return "".join(parts)


def _get_lvar_names(cfunc):
    names = set()
    try:
        lvars = cfunc.get_lvars()
    except Exception:
        lvars = []

    for lv in lvars:
        try:
            name = str(lv.name)
        except Exception:
            name = ""
        if name:
            names.add(name)
    return names


class ScopeInfo:
    __slots__ = (
        "sid",
        "start",
        "brace_line",
        "end",
        "depth",
        "header",
        "header_segments",
        "indent_cols",
        "kind",
        "color_index",
        "open_line",
        "open_col",
        "close_line",
        "close_col",
    )

    def __init__(self, sid, start, brace_line, depth, header, header_segments, indent_cols, kind, color_index, open_line, open_col):
        self.sid = sid
        self.start = start
        self.brace_line = brace_line
        self.end = -1
        self.depth = depth
        self.header = header
        self.header_segments = header_segments
        self.indent_cols = max(0, min(int(indent_cols or 0), INDENT_MAX_COLS))
        self.kind = kind
        self.color_index = color_index
        self.open_line = open_line
        self.open_col = open_col
        self.close_line = -1
        self.close_col = -1


def _simpleline_to_text(sl):
    try:
        return _tag_remove_clean(sl.line, strip=False)
    except Exception:
        return _tag_remove_clean(sl, strip=False)


def _simpleline_to_tagged(sl):
    try:
        return str(sl.line)
    except Exception:
        return str(sl)


def _compact_text(s):
    s = re.sub(r"\s+", " ", str(s)).strip()
    if len(s) > TEXT_MAX_LEN:
        s = s[:TEXT_MAX_LEN - 3] + "..."
    return s


def _visible_indent_cols(s, tab_size=INDENT_TAB_SIZE):
    cols = 0
    for ch in str(s):
        if ch == " ":
            cols += 1
        elif ch == "\t":
            step = max(1, int(tab_size or 2))
            cols += step - (cols % step)
        else:
            break
    return max(0, min(cols, INDENT_MAX_COLS))


def _line_indent_cols(lines, line_no):
    try:
        line_no = int(line_no)
    except Exception:
        return 0
    if line_no < 0 or line_no >= len(lines):
        return 0
    return _visible_indent_cols(lines[line_no])


def _strip_leading_ws_from_segments(segments):
    result = []
    stripping = True

    for seg in segments or []:
        text = str(seg.get("text", ""))
        tag = seg.get("tag")

        if stripping:
            stripped = text.lstrip(" \t")
            if stripped == "":
                continue
            text = stripped
            stripping = False

        if text:
            _append_segment(result, text, tag)

    return result


def _prepend_indent_segments(segments, indent_cols):
    # Kept for compatibility with the previous internal call site.
    # The sticky text indentation is rendered as a pixel offset in paintEvent,
    # not by inserting artificial whitespace into the displayed text.
    return [dict(seg) for seg in (segments or []) if seg.get("text", "")]


def _strip_line_prefix_noise(s):
    s = str(s).strip()
    s = re.sub(r"^\}+\s*", "", s)
    return s.strip()


def _classify_scope(header):
    h = header.strip().lower()
    m = CONTROL_WORD_RE.search(h)
    if m:
        return re.sub(r"\s+", " ", m.group(1).lower())
    if "(" in h and ")" in h:
        return "function"
    return "block"


def _line_braces(line, state):
    result = []
    quote = None
    escaped = False
    i = 0

    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""

        if state["block_comment"]:
            if ch == "*" and nxt == "/":
                state["block_comment"] = False
                i += 2
                continue
            i += 1
            continue

        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            break
        if ch == "/" and nxt == "*":
            state["block_comment"] = True
            i += 2
            continue
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            continue
        if ch == "{" or ch == "}":
            result.append((i, ch))
        i += 1

    return result


def _tail_starts_branch_continuation(line, close_brace_pos):
    tail = line[close_brace_pos + 1:]
    tail = _strip_line_prefix_noise(tail).lower()

    if not tail:
        return False

    for word in BRANCH_CONTINUATION_WORDS:
        if tail == word or tail.startswith(word + " ") or tail.startswith(word + "{") or tail.startswith(word + "("):
            return True

    return False


def _find_header(lines, line_no, brace_pos):
    cur = lines[line_no][:brace_pos]
    cur = _strip_line_prefix_noise(cur)

    if cur:
        return _compact_text(cur + " {"), line_no

    pieces = []
    header_line = line_no
    j = line_no - 1
    lower_bound = max(-1, line_no - 12)

    while j > lower_bound:
        t = _strip_line_prefix_noise(lines[j])

        if t and t not in ("{", "}"):
            pieces.insert(0, t)
            header_line = j
            joined = " ".join(pieces)

            if CONTROL_WORD_RE.search(joined) or joined.endswith(")") or joined.endswith(":") or len(joined) > 110:
                break
        j -= 1

    if pieces:
        return _compact_text(" ".join(pieces) + " {"), header_line

    return "{", line_no


def _make_header_segments(lines, tagged_lines, line_no, brace_pos, header, header_line, color_index, indent_cols, lvar_names):
    brace_tag_name = _brace_scolor_name_for_index(color_index)
    brace_segment = {"text": "{", "tag": brace_tag_name}

    if tagged_lines and header_line == line_no:
        raw_prefix_text = lines[line_no][:brace_pos]
        segments = _parse_tagged_line_to_segments(tagged_lines[line_no], limit_visible=max(0, brace_pos))

        if not segments:
            segments = _fallback_colorize_plain_text(raw_prefix_text, lvar_names)
        elif not _segments_have_real_color(segments):
            segments = _fallback_colorize_plain_text(raw_prefix_text, lvar_names)
    else:
        plain_texts = []
        j = header_line
        while j <= line_no:
            if 0 <= j < len(lines):
                t = _strip_line_prefix_noise(lines[j])
                if t and t not in ("{", "}"):
                    plain_texts.append(t)
            j += 1

        raw_text = _compact_text(" ".join(plain_texts))
        segments = _fallback_colorize_plain_text(raw_text, lvar_names)

    segments = _strip_leading_ws_from_segments(segments)

    if segments and not segments[-1]["text"].endswith(" "):
        segments.append({"text": " ", "tag": None})
    elif not segments:
        segments.append({"text": " ", "tag": None})

    segments.append(brace_segment)
    segments = _prepend_indent_segments(segments, indent_cols)
    return _trim_segments(segments, TEXT_MAX_LEN)


def _colorize_tagged_line_visible_braces(tagged_line, brace_specs):
    if not brace_specs:
        return str(tagged_line)

    raw = str(tagged_line)
    plain = _tag_remove_clean(raw, strip=False)

    wanted = {}
    for vis_pos, color_index, brace_ch in brace_specs:
        wanted[(vis_pos, brace_ch)] = color_index

    out = []
    plain_idx = 0
    tag_stack = []

    def _push_tag(tag_value):
        tag_name = _scolor_name_from_tag(tag_value)
        if tag_name:
            tag_stack.append(tag_name)

    def _pop_tag(tag_value=None):
        if not tag_stack:
            return
        tag_name = _scolor_name_from_tag(tag_value) if tag_value is not None else ""
        if tag_name and tag_name in tag_stack:
            for idx in range(len(tag_stack) - 1, -1, -1):
                if tag_stack[idx] == tag_name:
                    del tag_stack[idx:]
                    break
        else:
            tag_stack.pop()

    def _current_tag():
        return tag_stack[-1] if tag_stack else ""

    i = 0
    n = len(raw)

    while i < n:
        ch = raw[i]

        if COLOR_ADDR_CH and ch == COLOR_ADDR_CH:
            end = min(n, i + 1 + COLOR_ADDR_SIZE)
            out.append(raw[i:end])
            i = end
            continue

        if ch in ON_TAGS:
            if i + 1 >= n:
                out.append(ch)
                i += 1
                continue

            tag_value = raw[i + 1]

            if COLOR_ADDR_CH and tag_value == COLOR_ADDR_CH:
                end = min(n, i + 2 + COLOR_ADDR_SIZE)
                out.append(raw[i:end])
                i = end
                continue

            out.append(raw[i:i + 2])
            _push_tag(tag_value)
            i += 2
            continue

        if ch in OFF_TAGS:
            end = min(n, i + 2)
            out.append(raw[i:end])
            if i + 1 < n:
                _pop_tag(raw[i + 1])
            else:
                _pop_tag(None)
            i = end
            continue

        if ch in INV_TAGS:
            out.append(ch)
            i += 1
            continue

        leaked_len = _looks_like_leaked_anchor_at(raw, i)
        if leaked_len > 0:
            out.append(raw[i:i + leaked_len])
            i += leaked_len
            continue

        if raw.startswith("Btag", i):
            out.append(raw[i:i + 4])
            i += 4
            continue

        if ch in ESC_TAGS:
            if i + 1 < n:
                esc_ch = raw[i + 1]
                if plain_idx < len(plain) and esc_ch == plain[plain_idx]:
                    key = (plain_idx, esc_ch)
                    if key in wanted:
                        target_color = _brace_scolor_value_for_index(wanted[key])
                        target_tag_name = _scolor_name_from_tag(target_color)
                        # Idempotence guard: if the brace is already inside the
                        # target color, keep the existing tagged text unchanged.
                        if _current_tag() == target_tag_name:
                            out.append(raw[i:i + 2])
                        else:
                            out.append(ida_lines.COLSTR(esc_ch, target_color))
                    else:
                        out.append(raw[i:i + 2])
                    plain_idx += 1
                    i += 2
                    continue

                out.append(raw[i:i + 2])
                i += 2
                continue

            out.append(ch)
            i += 1
            continue

        if plain_idx < len(plain) and ch == plain[plain_idx]:
            key = (plain_idx, ch)
            if key in wanted:
                target_color = _brace_scolor_value_for_index(wanted[key])
                target_tag_name = _scolor_name_from_tag(target_color)
                # Idempotence guard: do not wrap the same visible brace again
                # when Hex-Rays refreshes an already-colored pseudocode line.
                if _current_tag() == target_tag_name:
                    out.append(ch)
                else:
                    out.append(ida_lines.COLSTR(ch, target_color))
            else:
                out.append(ch)
            plain_idx += 1
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _clamp_row_height(h):
    try:
        h = int(h)
    except Exception:
        h = ROW_HEIGHT_DEFAULT

    if h < ROW_HEIGHT_MIN:
        return ROW_HEIGHT_MIN
    if h > ROW_HEIGHT_MAX:
        return ROW_HEIGHT_MAX
    return h


def _estimate_code_line_height(qt_widget):
    if qt_widget is None:
        return ROW_HEIGHT_DEFAULT

    candidates = []
    try:
        fm = qt_widget.fontMetrics()
        candidates.append(fm.height())
    except Exception:
        pass

    try:
        children = qt_widget.findChildren(QtWidgets.QWidget)
    except Exception:
        children = []

    for child in children:
        try:
            if not child.isVisible():
                continue
            fm = child.fontMetrics()
            h = fm.height()
            if ROW_HEIGHT_MIN <= h <= ROW_HEIGHT_MAX:
                candidates.append(h)
        except Exception:
            pass

    if not candidates:
        return ROW_HEIGHT_DEFAULT

    candidates.sort()
    return _clamp_row_height(candidates[-1])


def _estimate_line_no_width(qt_widget, total_lines):
    digits = max(2, len(str(max(1, int(total_lines or 1)))))
    try:
        font = qt_widget.font()
        fm = QtGui.QFontMetrics(font)
        text_w = fm.horizontalAdvance("9" * digits)
    except Exception:
        text_w = 7 * digits

    width = LINE_NO_OVERLAY_LEFT_PAD + text_w + LINE_NO_OVERLAY_RIGHT_PAD
    width = max(LINE_NO_OVERLAY_MIN_WIDTH, width)
    width = min(LINE_NO_OVERLAY_MAX_WIDTH, width)
    return int(width)


class ScopeParser:
    def __init__(self, lines, tagged_lines=None, lvar_names=None):
        self.lines = lines
        self.tagged_lines = tagged_lines or []
        self.lvar_names = lvar_names or set()
        self.all_scopes = []
        self._parse()

    def _make_color_index(self, sid, depth):
        return ((sid - 1) * 5 + depth * 3 + 2) % max(1, len(BRACE_SCOLOR_SEQUENCE))

    def _parse(self):
        stack = []
        sid = 1
        state = {"block_comment": False}
        last_line = max(0, len(self.lines) - 1)

        for line_no, line in enumerate(self.lines):
            braces = _line_braces(line, state)

            for pos, brace in braces:
                if brace == "}":
                    if stack:
                        ended = stack.pop()

                        if _tail_starts_branch_continuation(line, pos):
                            ended.end = max(ended.start, line_no - 1)
                        else:
                            ended.end = line_no

                        ended.close_line = line_no
                        ended.close_col = pos
                    continue

                header, header_line = _find_header(self.lines, line_no, pos)
                indent_cols = _line_indent_cols(self.lines, header_line)
                kind = _classify_scope(header)
                depth = len(stack)
                color_index = self._make_color_index(sid, depth)

                header_segments = _make_header_segments(
                    self.lines, self.tagged_lines, line_no, pos,
                    header, header_line, color_index, indent_cols, self.lvar_names
                )

                scope = ScopeInfo(
                    sid=sid,
                    start=header_line,
                    brace_line=line_no,
                    depth=depth,
                    header=header,
                    header_segments=header_segments,
                    indent_cols=indent_cols,
                    kind=kind,
                    color_index=color_index,
                    open_line=line_no,
                    open_col=pos,
                )

                sid += 1
                stack.append(scope)
                self.all_scopes.append(scope)

        for scope in stack:
            scope.end = last_line
            if scope.close_line < 0:
                scope.close_line = last_line
                close_col = self.lines[last_line].rfind("}")
                scope.close_col = close_col if close_col >= 0 else 0

    def build_brace_map(self):
        per_line = {}

        for scope in self.all_scopes:
            per_line.setdefault(scope.open_line, []).append((scope.open_col, scope.color_index, "{"))
            if scope.close_line >= 0 and scope.close_col >= 0:
                per_line.setdefault(scope.close_line, []).append((scope.close_col, scope.color_index, "}"))

        return per_line

    def _normalize_same_line_branches(self, active):
        if len(active) <= 1:
            return active

        branch_by_depth = {}

        for scope in active:
            kind = (scope.kind or "").strip().lower()
            if kind in BRANCH_KINDS:
                old = branch_by_depth.get(scope.depth)
                if old is None or scope.start > old.start or (scope.start == old.start and scope.sid > old.sid):
                    branch_by_depth[scope.depth] = scope

        result = []
        for scope in active:
            kind = (scope.kind or "").strip().lower()
            if kind in BRANCH_KINDS:
                winner = branch_by_depth.get(scope.depth)
                if winner is not None and winner.sid != scope.sid:
                    continue
            result.append(scope)

        return result

    def active_at(self, line_no, trim=True):
        if not self.lines:
            return ()

        line_no = max(0, min(line_no, len(self.lines) - 1))
        active = []

        for scope in self.all_scopes:
            if scope.start <= line_no <= scope.end:
                active.append(scope)

        active = self._normalize_same_line_branches(active)
        active.sort(key=lambda s: (s.depth, s.start, s.brace_line, s.sid))

        if trim and len(active) > MAX_STICKY_LEVELS:
            active = active[-MAX_STICKY_LEVELS:]

        return tuple(active)


class StickyOverlay(QtWidgets.QWidget):
    def __init__(self, parent, manager=None):
        super().__init__(parent)
        self.manager_ref = weakref.ref(manager) if manager is not None else (lambda: None)
        self.scopes = ()
        self.row_height = ROW_HEIGHT_DEFAULT
        self._last_scope_key = None
        self._last_geometry_key = None
        self._last_row_height = None
        self.integrated_gutter_width = 0
        self.integrated_text_offset = 0
        self.integrated_draw_gutter = False
        self._screen_overlay = False
        self.jump_source_widget_ref = weakref.ref(parent) if parent is not None else (lambda: None)

        self.setWindowFlags(QtCore.Qt.Widget)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, False)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        try:
            self.setAttribute(QtCore.Qt.WA_AlwaysStackOnTop, True)
        except Exception:
            pass
        self.setAutoFillBackground(False)
        try:
            self.setCursor(QtCore.Qt.PointingHandCursor)
        except Exception:
            pass

        self.font = QtGui.QFont("Consolas")
        self.font.setPointSize(9)

        self.hide()

    def make_screen_overlay(self):
        self._screen_overlay = True
        try:
            flags = QtCore.Qt.Tool | QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint
            self.setWindowFlags(flags)
        except Exception:
            try:
                self.setWindowFlags(QtCore.Qt.Tool | QtCore.Qt.FramelessWindowHint)
            except Exception:
                pass
        try:
            self.setAttribute(QtCore.Qt.WA_ShowWithoutActivating, True)
        except Exception:
            pass
        try:
            self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        except Exception:
            pass

    def set_jump_source_widget(self, widget):
        self.jump_source_widget_ref = weakref.ref(widget) if widget is not None else (lambda: None)


    def _row_and_scope_at_pos(self, pos):
        if not self.scopes:
            return -1, None

        try:
            y = int(pos.y()) - PANEL_MARGIN_TOP
        except Exception:
            return -1, None

        if y < 0:
            return -1, None

        row_h = max(1, _clamp_row_height(self.row_height))
        row_index = int(y // row_h)

        if row_index < 0 or row_index >= len(self.scopes):
            return -1, None

        return row_index, self.scopes[row_index]

    def _schedule_jump_from_pos(self, pos):
        row_index, scope = self._row_and_scope_at_pos(pos)
        if scope is None:
            return False

        manager = self.manager_ref()
        if manager is None:
            return False

        try:
            target_line = int(getattr(scope, "start", -1))
        except Exception:
            target_line = -1

        if target_line < 0:
            try:
                target_line = int(getattr(scope, "brace_line", -1))
            except Exception:
                target_line = -1

        if target_line < 0:
            return False

        source_widget = self.jump_source_widget_ref()
        if source_widget is None:
            source_widget = self.parentWidget()
        if source_widget is None:
            return False

        def _do_jump_request(m=manager, w=source_widget, line=target_line, row=row_index):
            try:
                m.jump_to_sticky_target_line(w, line, row)
            except Exception as e:
                try:
                    print("[%s] jump UI request failed: %s" % (PLUGIN_NAME, e))
                except Exception:
                    pass
            return False

        try:
            ida_kernwin.execute_ui_requests((_do_jump_request,))
        except Exception:
            QtCore.QTimer.singleShot(
                0,
                lambda m=manager, w=source_widget, line=target_line, row=row_index: m.jump_to_sticky_target_line(w, line, row),
            )
        return True

    def mousePressEvent(self, event):
        try:
            if event.button() != QtCore.Qt.LeftButton:
                event.ignore()
                return
        except Exception:
            pass

        if self._schedule_jump_from_pos(event.pos()):
            event.accept()
        else:
            event.ignore()

    def mouseReleaseEvent(self, event):
        try:
            event.accept()
        except Exception:
            pass

    def mouseDoubleClickEvent(self, event):
        try:
            if event.button() != QtCore.Qt.LeftButton:
                event.ignore()
                return
        except Exception:
            pass

        if self._schedule_jump_from_pos(event.pos()):
            event.accept()
        else:
            event.ignore()

    def wheelEvent(self, event):
        event.ignore()

    def set_row_height(self, row_height):
        self.row_height = _clamp_row_height(row_height)
        try:
            parent = self.parentWidget()
            if parent is not None:
                self.font = parent.font()
        except Exception:
            pass

    def set_scopes(self, scopes, row_height, geom_rect=None, source_font=None, gutter_width=0, text_offset=0, draw_gutter=False):
        self.set_row_height(row_height)
        self.scopes = scopes
        self.integrated_gutter_width = max(0, int(gutter_width or 0))
        self.integrated_text_offset = max(0, int(text_offset or 0))
        self.integrated_draw_gutter = bool(draw_gutter and self.integrated_gutter_width > 0)

        if source_font is not None:
            try:
                self.font = QtGui.QFont(source_font)
            except Exception:
                pass

        parent = self.parentWidget()
        if not scopes or (parent is None and geom_rect is None):
            if self.isVisible():
                self.hide()
            self._last_scope_key = None
            self._last_geometry_key = None
            self._last_row_height = None
            return

        panel_h = len(scopes) * self.row_height
        total_h = PANEL_MARGIN_TOP + panel_h + PANEL_MARGIN_BOTTOM

        if geom_rect is None:
            w = max(260, parent.width())
            geom_rect = QtCore.QRect(0, 0, w, total_h)
        else:
            geom_rect = QtCore.QRect(geom_rect)
            if geom_rect.height() <= 0:
                geom_rect.setHeight(total_h)
            if geom_rect.width() <= 0:
                geom_rect.setWidth(max(260, parent.width()))

        geometry_key = (int(geom_rect.x()), int(geom_rect.y()), int(geom_rect.width()), int(geom_rect.height()), int(self.integrated_gutter_width), int(self.integrated_text_offset), int(self.integrated_draw_gutter))
        scope_key = tuple((int(getattr(s, "sid", -1)), int(getattr(s, "start", -1)), int(getattr(s, "end", -1))) for s in scopes)
        row_key = int(self.row_height)

        if (
            self.isVisible()
            and self._last_scope_key == scope_key
            and self._last_geometry_key == geometry_key
            and self._last_row_height == row_key
        ):
            return

        self._last_scope_key = scope_key
        self._last_geometry_key = geometry_key
        self._last_row_height = row_key

        current_rect = self.geometry()
        if (current_rect.x(), current_rect.y(), current_rect.width(), current_rect.height()) != (geom_rect.x(), geom_rect.y(), geom_rect.width(), geom_rect.height()):
            self.setGeometry(geom_rect)
        self.raise_()
        if not self.isVisible():
            self.show()
        self.update()

    def _indent_pixel_offset(self, scope):
        if not PRESERVE_HEXRAYS_TEXT_INDENT:
            return 0

        try:
            indent_cols = int(getattr(scope, "indent_cols", 0) or 0)
        except Exception:
            indent_cols = 0

        indent_cols = max(0, min(indent_cols, INDENT_MAX_COLS))
        if indent_cols <= 0:
            return 0

        try:
            fm = QtGui.QFontMetrics(self.font)
            return max(0, int(fm.horizontalAdvance(" ") * indent_cols))
        except Exception:
            return 0

    def _apply_text_indent_rect(self, rect, scope):
        indent_px = self._indent_pixel_offset(scope)
        if indent_px <= 0:
            return QtCore.QRect(rect)

        max_indent = max(0, rect.width() - 8)
        indent_px = min(indent_px, max_indent)
        return QtCore.QRect(
            rect.x() + indent_px,
            rect.y(),
            max(1, rect.width() - indent_px),
            rect.height(),
        )

    def _draw_label_colored(self, p, rect, scope):
        parent = self.parentWidget()
        dark = _is_dark_widget(parent)
        default_color = "#d0d0d0" if dark else "#121212"

        text_rect = self._apply_text_indent_rect(rect, scope)
        body_html = _segments_to_html(scope.header_segments, dark=dark, default_color=default_color)

        point_size = self.font.pointSize()
        if point_size <= 0:
            point_size = 9

        doc = QtGui.QTextDocument()
        doc.setDefaultFont(self.font)
        doc.setDocumentMargin(0)
        doc.setTextWidth(max(1, text_rect.width()))
        doc.setHtml(
            '<div style="white-space:pre; font-family:%s; font-size:%dpt;">%s</div>'
            % (
                html.escape(self.font.family()),
                point_size,
                body_html,
            )
        )

        p.save()
        p.setClipRect(rect)
        y = text_rect.y() + max(0, int((text_rect.height() - doc.size().height()) / 2))
        p.translate(text_rect.x(), y)
        doc.drawContents(p, QtCore.QRectF(0, 0, text_rect.width(), text_rect.height()))
        p.restore()

    def _draw_label_plain(self, p, rect, scope):
        text_color = QtGui.QColor(18, 18, 18)
        text_rect = self._apply_text_indent_rect(rect, scope)
        text = _compact_text(str(scope.header))
        p.setFont(self.font)
        p.setPen(text_color)
        p.drawText(text_rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)

    def paintEvent(self, event):
        if not self.scopes:
            return

        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, False)
        p.setFont(self.font)

        panel_x = PANEL_MARGIN_LEFT
        panel_y = PANEL_MARGIN_TOP
        panel_w = self.width() - PANEL_MARGIN_LEFT - PANEL_MARGIN_RIGHT
        panel_h = len(self.scopes) * self.row_height
        text_start_x = max(panel_x, int(self.integrated_text_offset or 0))
        gutter_w = max(0, min(int(self.integrated_gutter_width or 0), max(0, panel_w - 1)))

        bg = QtGui.QColor(255, 255, 255, 242)
        border = QtGui.QColor(207, 211, 217)
        separator = QtGui.QColor(229, 231, 235)

        panel_rect = QtCore.QRect(panel_x, panel_y, panel_w, panel_h)

        p.setBrush(bg)
        p.setPen(QtGui.QPen(border, 1))
        p.drawRect(panel_rect)

        for idx, scope in enumerate(self.scopes):
            row_x = panel_x
            row_y = panel_y + idx * self.row_height
            row_w = panel_w
            row_h = self.row_height

            if idx > 0:
                p.setPen(QtGui.QPen(separator, 1))
                p.drawLine(row_x, row_y, row_x + row_w - 1, row_y)

            if self.integrated_draw_gutter and gutter_w > 0:
                gutter_rect = QtCore.QRect(
                    row_x + LINE_NO_OVERLAY_LEFT_PAD,
                    row_y,
                    max(1, gutter_w - LINE_NO_OVERLAY_LEFT_PAD - LINE_NO_OVERLAY_RIGHT_PAD),
                    row_h,
                )
                p.setPen(QtGui.QColor(LINE_NO_OVERLAY_COLOR))
                try:
                    p.drawText(gutter_rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight, str(int(scope.start) + 1))
                except Exception:
                    pass
                p.setPen(QtGui.QPen(separator, 1))
                try:
                    p.drawLine(row_x + gutter_w, row_y, row_x + gutter_w, row_y + row_h - 1)
                except Exception:
                    pass

            text_rect = QtCore.QRect(
                text_start_x + TEXT_LEFT_PADDING,
                row_y,
                max(1, row_w - text_start_x - TEXT_LEFT_PADDING - TEXT_RIGHT_PADDING),
                row_h,
            )

            if ENABLE_STICKY_COLORED_TEXT:
                self._draw_label_colored(p, text_rect, scope)
            else:
                self._draw_label_plain(p, text_rect, scope)

        p.end()


class GutterLineOverlay(QtWidgets.QWidget):
    def __init__(self, parent, manager=None, jump_source_widget=None):
        super().__init__(parent)
        self.manager_ref = weakref.ref(manager) if manager is not None else (lambda: None)
        self.jump_source_widget_ref = weakref.ref(jump_source_widget) if jump_source_widget is not None else (lambda: None)
        self.scopes = ()
        self.row_height = ROW_HEIGHT_DEFAULT
        self.total_lines = 0
        self.font = QtGui.QFont("Consolas")
        self.font.setPointSize(9)
        self._last_scope_key = None
        self._last_geometry_key = None
        self._last_row_height = None
        self.integrated_gutter_width = 0
        self.integrated_text_offset = 0
        self.integrated_draw_gutter = False
        self._screen_overlay = False
        self.jump_source_widget_ref = weakref.ref(parent) if parent is not None else (lambda: None)

        self.setWindowFlags(QtCore.Qt.Widget)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, False)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
        self.setAutoFillBackground(False)
        try:
            self.setCursor(QtCore.Qt.PointingHandCursor)
        except Exception:
            pass
        self.hide()

    def set_jump_source_widget(self, jump_source_widget):
        try:
            self.jump_source_widget_ref = weakref.ref(jump_source_widget) if jump_source_widget is not None else (lambda: None)
        except Exception:
            self.jump_source_widget_ref = lambda: None

    def _row_and_scope_at_pos(self, pos):
        if not self.scopes:
            return -1, None
        try:
            y = int(pos.y())
        except Exception:
            return -1, None
        if y < 0:
            return -1, None
        row_h = max(1, _clamp_row_height(self.row_height))
        row_index = int(y // row_h)
        if row_index < 0 or row_index >= len(self.scopes):
            return -1, None
        return row_index, self.scopes[row_index]

    def _schedule_jump_from_pos(self, pos):
        row_index, scope = self._row_and_scope_at_pos(pos)
        if scope is None:
            return False
        manager = self.manager_ref()
        if manager is None:
            return False
        try:
            target_line = int(getattr(scope, "start", -1))
        except Exception:
            target_line = -1
        if target_line < 0:
            try:
                target_line = int(getattr(scope, "brace_line", -1))
            except Exception:
                target_line = -1
        if target_line < 0:
            return False
        try:
            source_widget = self.jump_source_widget_ref()
        except Exception:
            source_widget = None
        if source_widget is None:
            source_widget = self.parentWidget()
        if source_widget is None:
            return False

        def _do_jump_request(m=manager, w=source_widget, line=target_line, row=row_index):
            try:
                m.jump_to_sticky_target_line(w, line, row)
            except Exception as e:
                try:
                    print("[%s] gutter jump UI request failed: %s" % (PLUGIN_NAME, e))
                except Exception:
                    pass
            return False

        try:
            ida_kernwin.execute_ui_requests((_do_jump_request,))
        except Exception:
            try:
                QtCore.QTimer.singleShot(0, lambda m=manager, w=source_widget, line=target_line, row=row_index: m.jump_to_sticky_target_line(w, line, row))
            except Exception:
                pass
        return True

    def mousePressEvent(self, event):
        try:
            if event.button() != QtCore.Qt.LeftButton:
                event.ignore()
                return
        except Exception:
            pass
        if self._schedule_jump_from_pos(event.pos()):
            event.accept()
        else:
            event.ignore()

    def mouseReleaseEvent(self, event):
        try:
            event.accept()
        except Exception:
            pass

    def mouseDoubleClickEvent(self, event):
        try:
            if event.button() != QtCore.Qt.LeftButton:
                event.ignore()
                return
        except Exception:
            pass
        if self._schedule_jump_from_pos(event.pos()):
            event.accept()
        else:
            event.ignore()

    def wheelEvent(self, event):
        event.ignore()

    def set_scopes(self, scopes, row_height, total_lines, geom_rect, source_font=None):
        self.scopes = scopes
        self.row_height = _clamp_row_height(row_height)
        self.total_lines = max(0, int(total_lines or 0))
        if source_font is not None:
            try:
                self.font = QtGui.QFont(source_font)
            except Exception:
                pass
        parent = self.parentWidget()
        if parent is None or not scopes:
            if self.isVisible():
                self.hide()
            self._last_scope_key = None
            self._last_geometry_key = None
            self._last_row_height = None
            return
        geometry_key = (int(geom_rect.x()), int(geom_rect.y()), int(geom_rect.width()), int(geom_rect.height()))
        scope_key = tuple((int(getattr(s, "sid", -1)), int(getattr(s, "start", -1)), int(getattr(s, "end", -1))) for s in scopes)
        row_key = int(self.row_height)
        if self.isVisible() and self._last_scope_key == scope_key and self._last_geometry_key == geometry_key and self._last_row_height == row_key:
            return
        self._last_scope_key = scope_key
        self._last_geometry_key = geometry_key
        self._last_row_height = row_key
        current_rect = self.geometry()
        if (current_rect.x(), current_rect.y(), current_rect.width(), current_rect.height()) != geometry_key:
            self.setGeometry(geom_rect)
        self.raise_()
        if not self.isVisible():
            self.show()
        self.update()

    def paintEvent(self, event):
        if not self.scopes:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, False)
        p.setFont(self.font)
        bg = QtGui.QColor(255, 255, 255, LINE_NO_OVERLAY_BG_ALPHA)
        border = QtGui.QColor(LINE_NO_OVERLAY_BORDER)
        text_color = QtGui.QColor(LINE_NO_OVERLAY_COLOR)
        separator = QtGui.QColor(LINE_NO_OVERLAY_SEPARATOR)
        panel_h = len(self.scopes) * self.row_height
        panel_rect = QtCore.QRect(0, 0, self.width(), panel_h)
        p.fillRect(panel_rect, bg)
        p.setPen(QtGui.QPen(border, 1))
        p.drawRect(panel_rect)
        for idx, scope in enumerate(self.scopes):
            row_y = idx * self.row_height
            row_h = self.row_height
            if idx > 0:
                p.setPen(QtGui.QPen(separator, 1))
                p.drawLine(0, row_y, self.width() - 1, row_y)
            rect = QtCore.QRect(LINE_NO_OVERLAY_LEFT_PAD, row_y, max(1, self.width() - LINE_NO_OVERLAY_LEFT_PAD - LINE_NO_OVERLAY_RIGHT_PAD), row_h)
            p.setPen(text_color)
            p.drawText(rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight, str(int(scope.start) + 1))
        p.end()


class PseudoWidgetEventFilter(QtCore.QObject):
    def __init__(self, manager):
        super().__init__()
        self.manager_ref = weakref.ref(manager)

    def eventFilter(self, obj, event):
        manager = self.manager_ref()
        if manager is None:
            return False

        try:
            if event.type() == QtCore.QEvent.KeyPress:
                if manager.handle_back_key(obj, event):
                    return True
        except Exception as e:
            try:
                print("[%s] back key handler failed: %s" % (PLUGIN_NAME, e))
            except Exception:
                pass

        if IDA92_SAFE_MODE:
            watched_events = {
                QtCore.QEvent.Wheel,
                QtCore.QEvent.Resize,
                QtCore.QEvent.KeyPress,
            }
        else:
            watched_events = {
                QtCore.QEvent.Wheel,
                QtCore.QEvent.Resize,
                QtCore.QEvent.Show,
                QtCore.QEvent.Move,
                QtCore.QEvent.KeyPress,
                QtCore.QEvent.MouseButtonPress,
                QtCore.QEvent.MouseButtonRelease,
            }

        scroll_event = getattr(QtCore.QEvent, "Scroll", None)
        if scroll_event is not None:
            watched_events.add(scroll_event)

        if event.type() in watched_events:
            manager.request_update()

        return False


class ScopeStickyUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, manager):
        ida_kernwin.UI_Hooks.__init__(self)
        self.manager_ref = weakref.ref(manager)

    def current_widget_changed(self, widget, prev_widget):
        manager = self.manager_ref()
        if manager is not None:
            manager.request_update()

    def widget_visible(self, widget):
        manager = self.manager_ref()
        if manager is not None:
            manager.request_update()

    def widget_invisible(self, widget):
        manager = self.manager_ref()
        if manager is not None:
            manager.request_update()


class ScopeStickyHexraysHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, manager):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.manager_ref = weakref.ref(manager)

    def _colorize_vu_once(self, vu, allow_text_rewrite=True):
        manager = self.manager_ref()
        if manager is None or vu is None:
            return

        try:
            cfunc = vu.cfunc
        except Exception:
            cfunc = None

        if cfunc is not None and ENABLE_HEXRAYS_TEXT_REWRITE and allow_text_rewrite:
            try:
                manager.colorize_cfunc_braces(cfunc)
            except Exception:
                pass

        try:
            manager.invalidate_cache()
            manager.request_update()
        except Exception:
            pass

    def func_printed(self, cfunc):
        manager = self.manager_ref()
        if manager is not None and ENABLE_HEXRAYS_TEXT_REWRITE:
            manager.colorize_cfunc_braces(cfunc)
        return 0

    def open_pseudocode(self, vu):
        self._colorize_vu_once(vu)
        return 0

    def refresh_pseudocode(self, vu):
        # On IDA 9.2, avoid rewriting sv.line from the refresh callback itself.
        # func_printed/open/switch still color the pseudocode, and this keeps
        # Qt6/Hex-Rays from entering a refresh-colorize-refresh loop.
        self._colorize_vu_once(vu, allow_text_rewrite=not (IDA92_SAFE_MODE and IDA92_SKIP_TEXT_REWRITE_ON_REFRESH))
        return 0

    def switch_pseudocode(self, vu):
        self._colorize_vu_once(vu)
        return 0

    def close_pseudocode(self, vu):
        manager = self.manager_ref()
        if manager is not None:
            manager.request_update()
        return 0

class ScopeStickyManager:
    def __init__(self):
        self.hexrays_ready = False
        self.cache_key = None
        self.cache_parser = None
        self.cache_total_lines = 0

        self.overlays = {}
        self.gutter_overlays = {}
        self.filters = {}
        self.qt_to_twidget = {}
        self.overlay_to_root = {}
        self.root_to_overlay_parent = {}
        self.jump_in_progress = False
        self.update_pending = False
        self.in_update_active = False

        self.ui_hooks = ScopeStickyUIHooks(self)
        self.ui_hooks.hook()

        self.hex_hooks = None
        self.in_text_coloring = False

        _ensure_css_loaded()
        _build_import_caches()
        self.ensure_hexrays()

        self.timer = QtCore.QTimer()
        self.timer.setInterval(TIMER_UPDATE_INTERVAL_MS)
        self.timer.timeout.connect(self.request_update)
        self.timer.start()

        print("[%s] %s manager initialized" % (PLUGIN_NAME, PLUGIN_VERSION))
        self.request_update()

    def invalidate_cache(self):
        self.cache_key = None
        self.cache_parser = None
        self.cache_total_lines = 0
        FUNCTION_TOKEN_KIND_CACHE.clear()

    def close(self):
        try:
            self.timer.stop()
        except Exception:
            pass

        try:
            self.ui_hooks.unhook()
        except Exception:
            pass

        if self.hex_hooks is not None:
            try:
                self.hex_hooks.unhook()
            except Exception:
                pass
            self.hex_hooks = None

        for overlay in list(self.overlays.values()):
            try:
                overlay.hide()
                overlay.deleteLater()
            except Exception:
                pass

        for overlay in list(self.gutter_overlays.values()):
            try:
                overlay.hide()
                overlay.deleteLater()
            except Exception:
                pass

        self.overlays.clear()
        self.gutter_overlays.clear()
        self.filters.clear()
        self.qt_to_twidget.clear()
        self.root_to_overlay_parent.clear()
        self.overlay_to_root.clear()

    def request_update(self, *args, **kwargs):
        if QtCore is None:
            return
        if self.jump_in_progress or self.in_text_coloring:
            return
        if self.update_pending:
            return

        self.update_pending = True
        delay_ms = UPDATE_DEBOUNCE_MS
        try:
            if "delay_ms" in kwargs and kwargs["delay_ms"] is not None:
                delay_ms = int(kwargs["delay_ms"])
        except Exception:
            delay_ms = UPDATE_DEBOUNCE_MS

        try:
            QtCore.QTimer.singleShot(max(0, delay_ms), self._run_update_active)
        except Exception:
            self.update_pending = False

    def _run_update_active(self):
        self.update_pending = False
        if self.in_update_active or self.jump_in_progress or self.in_text_coloring:
            return
        self.in_update_active = True
        try:
            self.update_active()
        finally:
            self.in_update_active = False

    def ensure_hexrays(self):
        if self.hexrays_ready:
            if self.hex_hooks is None:
                try:
                    self.hex_hooks = ScopeStickyHexraysHooks(self)
                    self.hex_hooks.hook()
                except Exception:
                    self.hex_hooks = None
            return True

        try:
            self.hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            self.hexrays_ready = False

        if self.hexrays_ready and self.hex_hooks is None:
            try:
                self.hex_hooks = ScopeStickyHexraysHooks(self)
                self.hex_hooks.hook()
            except Exception:
                self.hex_hooks = None

        return self.hexrays_ready

    def hide_all(self):
        for overlay in list(self.overlays.values()):
            try:
                overlay.hide()
            except Exception:
                pass

        for overlay in list(self.gutter_overlays.values()):
            try:
                overlay.hide()
            except Exception:
                pass

    def _twidget_to_qwidget(self, twidget):
        # IDA 9.0 is Qt5/PyQt5 based. IDA 9.2 is Qt6/PySide6 based, but
        # some builds still expose PyQt compatibility conversion helpers. Try
        # the binding-native conversion first, then fall back to the other one.
        converters = []
        try:
            if QT_BINDING == "PySide6":
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPySideWidget", None))
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPyQtWidget", None))
            elif QT_BINDING == "PyQt5":
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPyQtWidget", None))
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPySideWidget", None))
            else:
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPySideWidget", None))
                converters.append(getattr(ida_kernwin.PluginForm, "TWidgetToPyQtWidget", None))
        except Exception:
            converters = []

        seen = set()
        for conv in converters:
            if not callable(conv):
                continue
            try:
                if id(conv) in seen:
                    continue
                seen.add(id(conv))
            except Exception:
                pass
            try:
                w = conv(twidget)
                if w is not None:
                    return w
            except Exception:
                pass

        return None

    def _is_child_of(self, child, root):
        if child is None or root is None:
            return False
        w = child
        depth = 0
        while w is not None and depth < 32:
            if w is root:
                return True
            try:
                w = w.parentWidget()
            except Exception:
                return False
            depth += 1
        return False

    def _widget_score_for_overlay_parent(self, w):
        if w is None:
            return -1
        try:
            if isinstance(w, (QtWidgets.QScrollBar, QtWidgets.QMenuBar, QtWidgets.QStatusBar)):
                return -1
        except Exception:
            pass
        try:
            if not w.isVisible():
                return -1
        except Exception:
            pass
        try:
            width = int(w.width())
            height = int(w.height())
        except Exception:
            return -1
        if width < 120 or height < 80:
            return -1

        score = width * height
        try:
            cls = str(w.metaObject().className()).lower()
        except Exception:
            cls = ""
        try:
            obj = str(w.objectName()).lower()
        except Exception:
            obj = ""

        name_blob = cls + " " + obj
        if "customidamemo" in name_blob or "idamemo" in name_blob:
            score += 100000000
        if "pseudocode" in name_blob or "hex" in name_blob:
            score += 50000000
        if "viewer" in name_blob or "view" in name_blob:
            score += 10000000

        try:
            for sb in w.findChildren(QtWidgets.QScrollBar):
                if sb.isVisible() and sb.orientation() == QtCore.Qt.Vertical:
                    score += 5000000
                    break
        except Exception:
            pass

        return score

    def _select_overlay_parent(self, root_widget):
        if root_widget is None:
            return None

        cache_key = id(root_widget)
        cached = self.root_to_overlay_parent.get(cache_key)
        if cached is not None:
            try:
                if cached.isVisible() and self._is_child_of(cached, root_widget):
                    if self._widget_score_for_overlay_parent(cached) > 0:
                        return cached
            except Exception:
                pass
            try:
                del self.root_to_overlay_parent[cache_key]
            except Exception:
                pass

        best = root_widget
        best_score = self._widget_score_for_overlay_parent(root_widget)
        try:
            children = root_widget.findChildren(QtWidgets.QWidget)
        except Exception:
            children = []
        try:
            root_w = int(root_widget.width())
        except Exception:
            root_w = 0
        for child in children:
            try:
                if isinstance(child, (StickyOverlay, GutterLineOverlay, QtWidgets.QScrollBar)):
                    continue
            except Exception:
                pass
            s = self._widget_score_for_overlay_parent(child)
            if s <= 0:
                continue
            try:
                local = root_widget.mapFromGlobal(child.mapToGlobal(QtCore.QPoint(0, 0)))
                child_x = int(local.x())
                child_y = int(local.y())
                child_w = int(child.width())
            except Exception:
                child_x = 0
                child_y = 0
                child_w = 0
            if root_w > 0 and child_x > int(root_w * 0.35):
                s -= 200000000
            if child_y > 80:
                s -= 60000000
            if 20 <= child_x <= max(220, GUTTER_DETECT_MAX_LEFT * 2):
                s += 60000000
            if root_w > 0 and child_w >= int(root_w * 0.45):
                s += 40000000
            if s > best_score:
                best = child
                best_score = s
        if best is None:
            best = root_widget
        try:
            self.root_to_overlay_parent[cache_key] = best
        except Exception:
            pass
        return best

    def _remember_overlay_root(self, overlay_parent, root_widget, twidget):
        if overlay_parent is None:
            return
        try:
            self.overlay_to_root[id(overlay_parent)] = root_widget if root_widget is not None else overlay_parent
        except Exception:
            pass
        if twidget is not None:
            try:
                self.qt_to_twidget[id(overlay_parent)] = twidget
            except Exception:
                pass
            if root_widget is not None:
                try:
                    self.qt_to_twidget[id(root_widget)] = twidget
                except Exception:
                    pass

    def _root_for_overlay_parent(self, qt_widget):
        if qt_widget is None:
            return None
        try:
            root = self.overlay_to_root.get(id(qt_widget))
            if root is not None:
                return root
        except Exception:
            pass
        cur = qt_widget
        last = qt_widget
        depth = 0
        while cur is not None and depth < 12:
            last = cur
            try:
                parent = cur.parentWidget()
            except Exception:
                break
            if parent is None or parent.isWindow():
                break
            cur = parent
            depth += 1
        return last if last is not None else qt_widget

    def _twidget_for_qwidget(self, qt_widget):
        cur = qt_widget
        depth = 0
        while cur is not None and depth < 16:
            try:
                tw = self.qt_to_twidget.get(id(cur))
                if tw:
                    return tw
            except Exception:
                pass
            try:
                cur = cur.parentWidget()
            except Exception:
                break
            depth += 1
        try:
            return ida_kernwin.get_current_widget()
        except Exception:
            return None

    def _install_filter_once(self, widget, key):
        if widget is None:
            return

        pair_key = (id(widget), key)
        if pair_key in self.filters:
            return

        event_filter = PseudoWidgetEventFilter(self)
        widget.installEventFilter(event_filter)
        self.filters[pair_key] = event_filter

    def _get_overlay(self, qt_widget, top_level=False):
        key = ("screen", id(qt_widget)) if top_level else id(qt_widget)
        overlay = self.overlays.get(key)

        recreate = False
        if overlay is None:
            recreate = True
        else:
            try:
                if bool(getattr(overlay, "_screen_overlay", False)) != bool(top_level):
                    recreate = True
            except Exception:
                recreate = True

        if recreate:
            if overlay is not None:
                try:
                    overlay.hide()
                    overlay.deleteLater()
                except Exception:
                    pass
            overlay = StickyOverlay(None if top_level else qt_widget, self)
            if top_level:
                overlay.make_screen_overlay()
                overlay.set_jump_source_widget(qt_widget)
            self.overlays[key] = overlay

        if top_level:
            try:
                overlay.set_jump_source_widget(qt_widget)
            except Exception:
                pass

        self._install_filter_once(qt_widget, ("main", key))
        return overlay

    def _line_gutter_width_for_root_overlay(self, code_widget, total_lines):
        try:
            return max(LINE_NO_OVERLAY_MIN_WIDTH, _estimate_line_no_width(code_widget, total_lines))
        except Exception:
            return LINE_NO_OVERLAY_MIN_WIDTH

    def _widget_global_rect_in_root(self, root_widget, widget):
        try:
            p0 = root_widget.mapFromGlobal(widget.mapToGlobal(QtCore.QPoint(0, 0)))
            return QtCore.QRect(int(p0.x()), int(p0.y()), int(widget.width()), int(widget.height()))
        except Exception:
            return QtCore.QRect()

    def _candidate_name_for_widget(self, widget):
        try:
            cls = str(widget.metaObject().className()).lower()
        except Exception:
            cls = ""
        try:
            obj = str(widget.objectName()).lower()
        except Exception:
            obj = ""
        return cls + " " + obj

    def _find_code_text_anchor_widget(self, root_widget, fallback_widget):
        """Return the stable widget whose left edge is closest to the real code text.

        IDA 9.2 exposes more Qt6 child widgets than IDA 9.0.  Some of those
        children are transient focus/tooltip/scroll-area panels; if one of them
        is used as the geometry anchor, the overlay may jump to the right side
        after a click.  This routine anchors only on visible pseudocode/memo-like
        widgets that live near the left side of the pseudocode view.
        """
        if root_widget is None:
            return fallback_widget

        try:
            root_w = int(root_widget.width())
            root_h = int(root_widget.height())
        except Exception:
            root_w = 0
            root_h = 0

        best = None
        best_score = -10**18

        candidates = []
        if fallback_widget is not None:
            candidates.append(fallback_widget)
        try:
            candidates.extend(root_widget.findChildren(QtWidgets.QWidget))
        except Exception:
            pass

        seen = set()
        for w in candidates:
            if w is None:
                continue
            try:
                wid = id(w)
                if wid in seen:
                    continue
                seen.add(wid)
            except Exception:
                pass

            try:
                if isinstance(w, (StickyOverlay, GutterLineOverlay, QtWidgets.QScrollBar)):
                    continue
            except Exception:
                pass

            try:
                if not w.isVisible():
                    continue
                ww = int(w.width())
                wh = int(w.height())
            except Exception:
                continue

            if ww < 180 or wh < 80:
                continue

            rect = self._widget_global_rect_in_root(root_widget, w)
            if not rect.isValid():
                continue

            x = int(rect.x())
            y = int(rect.y())
            width = int(rect.width())
            height = int(rect.height())

            # The real text area in the pseudocode view should be near the top
            # and not start in the far-right part of the dock.  This is the key
            # guard that prevents the overlay line numbers from drifting right.
            if y < -8 or y > max(80, GUTTER_DETECT_MAX_TOP * 3):
                continue
            if root_w > 0 and x > max(260, int(root_w * 0.35)):
                continue

            score = 0
            name_blob = self._candidate_name_for_widget(w)
            if "customidamemo" in name_blob or "idamemo" in name_blob:
                score += 100000000
            if "pseudocode" in name_blob:
                score += 50000000
            if "viewer" in name_blob or "view" in name_blob:
                score += 10000000

            if root_w > 0:
                if width >= int(root_w * 0.45):
                    score += 20000000
                if width >= int(root_w * 0.65):
                    score += 10000000

            # Prefer a text anchor with a left gutter before it.  In the usual
            # IDA pseudocode view, this x is exactly the end of the line-number
            # column, so line numbers should be drawn at x - gutter_width.
            if LINE_NO_OVERLAY_MIN_WIDTH <= x <= max(220, GUTTER_DETECT_MAX_LEFT * 2):
                score += 80000000
                score -= abs(x - 96) * 1000
            elif 0 <= x < LINE_NO_OVERLAY_MIN_WIDTH:
                score += 1000000
            else:
                score -= 50000000

            if y <= GUTTER_DETECT_MAX_TOP:
                score += 3000000

            if height >= max(100, int(root_h * 0.45)):
                score += 5000000

            if score > best_score:
                best_score = score
                best = w

        if best is not None:
            return best
        return fallback_widget if fallback_widget is not None else root_widget

    def _select_true_gutter_overlay_host(self, root_widget, code_widget):
        """Return (host, code_x, code_y) for the IDA 9.2 integrated overlay.

        In IDA 9.2, PluginForm.TWidgetToPySideWidget may return the inner
        code/memo widget instead of the whole pseudocode memo that contains the
        marker column and the line-number column.  A child overlay cannot cover
        its parent's left siblings, so the overlay must be parented to the first
        stable ancestor that still contains the original line-number gutter.
        """
        if code_widget is None:
            code_widget = root_widget
        if root_widget is None:
            root_widget = code_widget

        best_host = root_widget
        best_x = 0
        best_y = 0
        best_score = -10**18

        try:
            code_global = code_widget.mapToGlobal(QtCore.QPoint(0, 0))
            code_w = int(code_widget.width())
            code_h = int(code_widget.height())
        except Exception:
            code_global = None
            code_w = 0
            code_h = 0

        cur = code_widget
        depth = 0
        while cur is not None and depth < 12:
            try:
                if isinstance(cur, (StickyOverlay, GutterLineOverlay, QtWidgets.QScrollBar)):
                    raise RuntimeError("skip helper widget")
            except Exception:
                pass

            try:
                if code_global is not None:
                    local = cur.mapFromGlobal(code_global)
                    code_x = int(local.x())
                    code_y = int(local.y())
                else:
                    code_x = 0
                    code_y = 0
                host_w = int(cur.width())
                host_h = int(cur.height())
                visible = bool(cur.isVisible())
            except Exception:
                visible = False
                host_w = 0
                host_h = 0
                code_x = 0
                code_y = 0

            if visible and host_w > 120 and host_h > 80:
                score = 0

                # We want an ancestor where the code widget starts after a real
                # left gutter.  This usually falls around 70-130 px in IDA 9.2.
                if LINE_NO_OVERLAY_MIN_WIDTH <= code_x <= max(240, GUTTER_DETECT_MAX_LEFT * 2):
                    score += 200000000
                    score -= abs(code_x - 100) * 10000
                elif 20 <= code_x < LINE_NO_OVERLAY_MIN_WIDTH:
                    score += 20000000
                else:
                    score -= 100000000

                # The host should contain the code area horizontally and should
                # be vertically aligned with it.
                if host_w >= code_x + max(100, min(code_w, 300)):
                    score += 20000000
                if -8 <= code_y <= max(80, GUTTER_DETECT_MAX_TOP * 3):
                    score += 10000000
                else:
                    score -= 20000000
                if code_h > 0 and host_h >= min(code_h, 100):
                    score += 5000000

                name_blob = self._candidate_name_for_widget(cur)
                if "customidamemo" in name_blob or "idamemo" in name_blob:
                    score += 8000000
                if "pseudocode" in name_blob:
                    score += 4000000
                if "viewer" in name_blob or "view" in name_blob:
                    score += 2000000

                # Avoid accidentally choosing the whole IDA main window.  It is
                # much wider/taller and gives unstable coordinates after docking.
                try:
                    if cur.isWindow():
                        score -= 50000000
                except Exception:
                    pass

                if score > best_score:
                    best_score = score
                    best_host = cur
                    best_x = code_x
                    best_y = code_y

            try:
                parent = cur.parentWidget()
            except Exception:
                parent = None
            if parent is None:
                break
            cur = parent
            depth += 1

        if best_host is None:
            best_host = root_widget if root_widget is not None else code_widget
            best_x = 0
            best_y = 0
        return best_host, int(max(0, best_x)), int(max(0, best_y))

    def _make_root_overlay_geometry(self, host_widget, code_widget, row_height, scope_count, total_lines, code_x=None, code_y=None):
        """Return geometry for the IDA 9.2 integrated overlay.

        v19 draws the overlay from the original line-number column instead of
        anchoring it to the inner code widget.  The line-number band is placed
        immediately before the real code left edge, so it covers IDA's original
        line numbers while leaving the blue marker column alone whenever the
        host exposes it separately.
        """
        panel_h = max(1, int(scope_count or 0) * _clamp_row_height(row_height))

        try:
            host_w = int(host_widget.width())
        except Exception:
            host_w = 0

        try:
            code_x = int(code_x if code_x is not None else 0)
        except Exception:
            code_x = 0
        try:
            code_y = int(code_y if code_y is not None else 0)
        except Exception:
            code_y = 0

        estimated_line_no_w = self._line_gutter_width_for_root_overlay(code_widget, total_lines)
        line_no_w = max(
            LINE_NO_OVERLAY_MIN_WIDTH,
            min(int(estimated_line_no_w), LINE_NO_OVERLAY_MAX_WIDTH),
        )

        # The overlay starts at the original line-number column, not at the blue
        # marker column and not at the code text column.
        if code_x > line_no_w:
            overlay_x = max(0, code_x - line_no_w - 2)
        else:
            overlay_x = 0

        overlay_y = max(0, code_y)
        gutter_w = max(1, code_x - overlay_x)
        text_offset = gutter_w + 4

        if host_w <= 0:
            overlay_w = max(260, text_offset + 600)
        else:
            overlay_w = max(260, host_w - overlay_x)

        rect = QtCore.QRect(int(overlay_x), int(overlay_y), int(max(1, overlay_w)), int(panel_h))
        return rect, int(max(0, gutter_w)), int(max(0, text_offset))

    def _make_screen_overlay_geometry(self, code_widget, row_height, scope_count, total_lines):
        """Return global-screen geometry for the IDA 9.2 sticky overlay.

        This deliberately does not use Qt parent-local gutter inference.  In IDA
        9.2 the converted widget is often the inner code viewport, so any child
        overlay drawn at x=0 appears inside the code text area.  A top-level
        overlay can extend left of that viewport and cover the original line
        numbers reliably.
        """
        panel_h = max(1, int(scope_count or 0) * _clamp_row_height(row_height))

        try:
            code_global = code_widget.mapToGlobal(QtCore.QPoint(0, 0))
            code_x = int(code_global.x())
            code_y = int(code_global.y())
            code_w = int(code_widget.width())
        except Exception:
            code_x = 0
            code_y = 0
            code_w = 800

        try:
            estimated = int(_estimate_line_no_width(code_widget, total_lines))
        except Exception:
            estimated = LINE_NO_OVERLAY_MIN_WIDTH

        # IDA 9.2's visible line-number band is wider than the minimum text
        # width because the custom viewer also reserves padding before the code
        # text.  Use a bounded width to cover exactly the original line-number
        # column while keeping the blue marker column mostly untouched.
        line_no_w = max(58, min(LINE_NO_OVERLAY_MAX_WIDTH, estimated + 18))

        overlay_x = max(0, code_x - line_no_w)
        overlay_y = max(0, code_y)
        overlay_w = max(260, code_w + line_no_w)

        rect = QtCore.QRect(int(overlay_x), int(overlay_y), int(overlay_w), int(panel_h))
        return rect, int(line_no_w), int(line_no_w)

    def _hide_non_current_overlays(self, current_key):
        for key, overlay in list(self.overlays.items()):
            if key != current_key:
                try:
                    overlay.hide()
                except Exception:
                    pass

        for key, overlay in list(self.gutter_overlays.items()):
            if key != current_key:
                try:
                    overlay.hide()
                except Exception:
                    pass

    def _find_gutter_host_and_rect(self, qt_widget, row_height, total_lines, scope_count, root_widget=None):
        if qt_widget is None or scope_count <= 0:
            return None, QtCore.QRect()

        panel_h = max(1, int(scope_count) * _clamp_row_height(row_height))
        desired_w = _estimate_line_no_width(qt_widget, total_lines)

        # IDA 9.2 often exposes an inner memo widget for code text. The original
        # line-number gutter belongs to the converted root widget. Prefer placing
        # the gutter overlay on the root and ending it where the code memo begins.
        if root_widget is not None and root_widget is not qt_widget:
            try:
                code_origin_global = qt_widget.mapToGlobal(QtCore.QPoint(0, 0))
                code_origin_in_root = root_widget.mapFromGlobal(code_origin_global)
                code_x = int(code_origin_in_root.x())
                code_y = int(code_origin_in_root.y())
                max_left = max(220, GUTTER_DETECT_MAX_LEFT * 2)
                if code_x > 0 and code_x <= max_left and code_y >= 0 and code_y <= GUTTER_DETECT_MAX_TOP:
                    gutter_w = min(desired_w, code_x)
                    gutter_x = max(0, code_x - gutter_w)
                    rect = QtCore.QRect(gutter_x, code_y, gutter_w, panel_h)
                    if rect.width() > 0 and rect.height() > 0:
                        return root_widget, rect
                return None, QtCore.QRect()
            except Exception:
                return None, QtCore.QRect()

        try:
            viewport_global = qt_widget.mapToGlobal(QtCore.QPoint(0, 0))
        except Exception:
            return None, QtCore.QRect()

        parent = qt_widget.parentWidget()
        depth = 0

        while parent is not None and depth < GUTTER_DETECT_MAX_DEPTH:
            try:
                if parent.isWindow():
                    break

                local = parent.mapFromGlobal(viewport_global)
                left_available = int(local.x())
                top_y = int(local.y())

                if (
                    left_available >= max(10, desired_w // 2)
                    and left_available <= GUTTER_DETECT_MAX_LEFT
                    and top_y >= 0
                    and top_y <= GUTTER_DETECT_MAX_TOP
                    and parent.width() >= left_available + max(32, qt_widget.width() // 2)
                ):
                    gutter_w = min(desired_w, left_available)
                    gutter_x = max(0, left_available - gutter_w)
                    rect = QtCore.QRect(gutter_x, top_y, gutter_w, panel_h)

                    if rect.width() > 0 and rect.height() > 0:
                        return parent, rect
            except Exception:
                pass

            parent = parent.parentWidget()
            depth += 1

        return None, QtCore.QRect()

    def _get_gutter_overlay(self, host_widget, qt_widget):
        key = id(qt_widget)
        overlay = self.gutter_overlays.get(key)

        recreate = False
        if overlay is None:
            recreate = True
        else:
            try:
                if overlay.parentWidget() is not host_widget:
                    recreate = True
            except Exception:
                recreate = True

        if recreate:
            if overlay is not None:
                try:
                    overlay.hide()
                    overlay.deleteLater()
                except Exception:
                    pass

            overlay = GutterLineOverlay(host_widget, self, qt_widget)
            self.gutter_overlays[key] = overlay

        try:
            overlay.set_jump_source_widget(qt_widget)
        except Exception:
            pass

        self._install_filter_once(host_widget, ("gutter-host", key))
        self._install_filter_once(qt_widget, ("gutter-view", key))
        return overlay

    def _hide_gutter_for(self, qt_widget):
        key = id(qt_widget)
        overlay = self.gutter_overlays.get(key)
        if overlay is not None:
            try:
                overlay.hide()
            except Exception:
                pass


    def _find_vertical_scrollbar(self, qt_widget):
        if qt_widget is None:
            return None

        candidates = []
        seen = set()

        def add_scrollbars_from(widget):
            if widget is None:
                return
            try:
                widgets = [widget] + list(widget.findChildren(QtWidgets.QWidget))
            except Exception:
                widgets = [widget]

            for w in widgets:
                try:
                    if id(w) in seen:
                        continue
                    seen.add(id(w))

                    if isinstance(w, QtWidgets.QScrollBar):
                        if w.orientation() == QtCore.Qt.Vertical and w.maximum() > 0:
                            candidates.append(w)
                        continue

                    if isinstance(w, QtWidgets.QAbstractScrollArea):
                        sb = w.verticalScrollBar()
                        if sb is not None and sb.maximum() > 0:
                            candidates.append(sb)
                except Exception:
                    pass

        cur = qt_widget
        depth = 0
        while cur is not None and depth < 8:
            add_scrollbars_from(cur)
            try:
                parent = cur.parentWidget()
            except Exception:
                parent = None
            if parent is None:
                break
            cur = parent
            depth += 1

        unique = []
        seen_sb = set()
        for sb in candidates:
            try:
                key = id(sb)
                if key in seen_sb:
                    continue
                seen_sb.add(key)
                if sb.isVisible() and sb.maximum() > 0:
                    unique.append(sb)
            except Exception:
                pass

        if not unique:
            return None

        try:
            return max(unique, key=lambda x: (x.maximum(), x.height()))
        except Exception:
            return unique[0]

    def _find_all_vertical_scrollbars(self, qt_widget):
        if qt_widget is None:
            return []

        candidates = []
        seen = set()

        def add_scrollbars_from(widget):
            if widget is None:
                return
            try:
                widgets = [widget] + list(widget.findChildren(QtWidgets.QWidget))
            except Exception:
                widgets = [widget]

            for w in widgets:
                try:
                    if id(w) in seen:
                        continue
                    seen.add(id(w))

                    if isinstance(w, QtWidgets.QScrollBar):
                        if w.orientation() == QtCore.Qt.Vertical and w.maximum() > 0:
                            candidates.append(w)
                        continue

                    if isinstance(w, QtWidgets.QAbstractScrollArea):
                        sb = w.verticalScrollBar()
                        if sb is not None and sb.maximum() > 0:
                            candidates.append(sb)
                except Exception:
                    pass

        cur = qt_widget
        depth = 0
        while cur is not None and depth < 12:
            add_scrollbars_from(cur)
            try:
                cur = cur.parentWidget()
            except Exception:
                cur = None
            depth += 1

        unique = []
        seen_sb = set()
        for sb in candidates:
            try:
                key = id(sb)
                if key in seen_sb:
                    continue
                seen_sb.add(key)
                if sb.maximum() > 0:
                    unique.append(sb)
            except Exception:
                pass

        unique.sort(key=lambda x: (int(x.maximum()), int(x.height())), reverse=True)
        return unique

    def _clamp_target_line(self, vu, line_no):
        try:
            total_lines = len(vu.cfunc.get_pseudocode())
        except Exception:
            total_lines = 0

        try:
            line_no = int(line_no)
        except Exception:
            line_no = 0

        if total_lines > 0:
            line_no = max(0, min(line_no, total_lines - 1))
        else:
            line_no = max(0, line_no)

        return line_no, total_lines

    def _jump_custom_viewer_to_line(self, twidget, line_no, visible_y=0):
        if not twidget:
            return False

        try:
            current = ida_kernwin.get_custom_viewer_place(twidget, False)
        except Exception as e:
            try:
                print("[%s] get_custom_viewer_place failed: %s" % (PLUGIN_NAME, e))
            except Exception:
                pass
            return False

        if isinstance(current, tuple):
            if not current:
                return False
            place = current[0]
        else:
            place = current

        if place is None:
            return False

        target_place = None
        try:
            target_place = place.clone()
        except Exception as e:
            try:
                print("[%s] clone place failed: %s" % (PLUGIN_NAME, e))
            except Exception:
                pass

        if target_place is None:
            return False

        simple_place = None
        try:
            simple_place = ida_kernwin.place_t.as_simpleline_place_t(target_place)
        except Exception:
            try:
                simple_place = ida_kernwin.place_t_as_simpleline_place_t(target_place)
            except Exception:
                simple_place = None

        if simple_place is None:
            try:
                print("[%s] current viewer place is not simpleline_place_t" % PLUGIN_NAME)
            except Exception:
                pass
            return False

        try:
            simple_place.n = int(line_no)
        except Exception as e:
            try:
                print("[%s] set target place line failed: %s" % (PLUGIN_NAME, e))
            except Exception:
                pass
            return False

        try:
            visible_y = max(0, int(visible_y or 0))
        except Exception:
            visible_y = 0

        # In some IDA 9.2/PySide6 builds the object returned by
        # as_simpleline_place_t() is the one whose n field is actually updated.
        # Try both the original cloned place and the simpleline wrapper.
        place_args = []
        for p in (simple_place, target_place):
            if p is not None and id(p) not in [id(x) for x in place_args]:
                place_args.append(p)

        tried = set()
        for place_arg in place_args:
            for args in (
                (twidget, place_arg, 0, visible_y),
                (twidget, place_arg, 0, 0),
                (twidget, place_arg, 0, int(line_no)),
            ):
                try:
                    sig = (id(args[1]), args[2], args[3])
                    if sig in tried:
                        continue
                    tried.add(sig)
                except Exception:
                    pass
                try:
                    if ida_kernwin.jumpto(*args):
                        try:
                            ida_kernwin.refresh_custom_viewer(twidget)
                        except Exception:
                            pass
                        try:
                            ida_kernwin.repaint_custom_viewer(twidget)
                        except Exception:
                            pass
                        return True
                except Exception as e:
                    try:
                        print("[%s] jumpto custom viewer failed: %s" % (PLUGIN_NAME, e))
                    except Exception:
                        pass

        return False

    def _sticky_overlay_visible_rows(self, qt_widget, fallback_clicked_row=None):
        rows = 0

        try:
            overlay = self.overlays.get(id(qt_widget))
            if overlay is None:
                overlay = self.overlays.get(("screen", id(qt_widget)))
        except Exception:
            overlay = None

        if overlay is not None:
            try:
                if overlay.isVisible() and overlay.scopes:
                    rows = len(overlay.scopes)
            except Exception:
                try:
                    rows = len(overlay.scopes or ())
                except Exception:
                    rows = 0

        if rows <= 0 and fallback_clicked_row is not None:
            try:
                rows = int(fallback_clicked_row) + 1
            except Exception:
                rows = 0

        return max(0, int(rows or 0))

    def _predict_post_jump_cover_rows(self, vu, target_line, total_lines, fallback_rows=0):
        """Predict sticky overlay row count after the viewport has been moved.

        The old implementation used the current overlay height before jumping.
        That is wrong because after jumping to another line, the active scopes at
        the new viewport top can be different. Here we solve the relation:

            top_line = target_line - cover_after_jump
            cover_after_jump = len(sticky_scopes_at(top_line))

        by a small fixed-point iteration over the already parsed ScopeParser.
        """
        try:
            target_line = int(target_line)
        except Exception:
            target_line = 0

        try:
            total_lines = int(total_lines or 0)
        except Exception:
            total_lines = 0

        if total_lines > 0:
            target_line = max(0, min(target_line, total_lines - 1))
        else:
            target_line = max(0, target_line)

        try:
            fallback_rows = int(fallback_rows or 0)
        except Exception:
            fallback_rows = 0

        fallback_rows = max(0, min(fallback_rows, MAX_STICKY_LEVELS))

        try:
            parser, parser_total = self._get_parser_and_total_lines(vu)
        except Exception:
            parser = None
            parser_total = 0

        if parser is None:
            top_line = max(0, target_line - fallback_rows)
            return fallback_rows, top_line, ()

        if total_lines <= 0:
            total_lines = int(parser_total or 0)

        if total_lines > 0:
            target_line = max(0, min(target_line, total_lines - 1))

        cover = fallback_rows
        best_cover = cover
        best_top_line = max(0, target_line - cover)
        best_scopes = ()
        seen = set()

        for _round in range(MAX_STICKY_LEVELS + 6):
            top_line = max(0, target_line - max(0, cover))
            if total_lines > 0:
                top_line = min(top_line, total_lines - 1)

            try:
                scopes, _touch_line = self._select_scopes_by_bottom_touch(parser, top_line, total_lines)
            except Exception:
                scopes = ()

            next_cover = max(0, min(len(scopes or ()), MAX_STICKY_LEVELS))
            best_cover = next_cover
            best_top_line = top_line
            best_scopes = tuple(scopes or ())

            if next_cover == cover:
                return next_cover, top_line, best_scopes

            state = (cover, next_cover, top_line)
            if state in seen:
                break
            seen.add(state)
            cover = next_cover

        # If there is a small oscillation, choose the largest safe cover near
        # the target line so the target will not be hidden by the overlay.
        chosen_cover = best_cover
        chosen_top_line = best_top_line
        chosen_scopes = best_scopes
        for candidate_cover in range(MAX_STICKY_LEVELS, -1, -1):
            candidate_top = max(0, target_line - candidate_cover)
            if total_lines > 0:
                candidate_top = min(candidate_top, total_lines - 1)
            try:
                candidate_scopes, _ = self._select_scopes_by_bottom_touch(parser, candidate_top, total_lines)
            except Exception:
                candidate_scopes = ()
            candidate_len = max(0, min(len(candidate_scopes or ()), MAX_STICKY_LEVELS))
            if candidate_len <= candidate_cover:
                chosen_cover = candidate_len
                chosen_top_line = candidate_top
                chosen_scopes = tuple(candidate_scopes or ())
                break

        return chosen_cover, chosen_top_line, chosen_scopes

    def _scroll_qt_view_to_line(self, qt_widget, line_no, total_lines, covered_rows=0):
        scrollbars = self._find_all_vertical_scrollbars(qt_widget)
        if not scrollbars or total_lines <= 0:
            try:
                print("[%s] fallback Qt scrollbar not found, candidates=%d, total_lines=%d" % (
                    PLUGIN_NAME, len(scrollbars or []), int(total_lines or 0)
                ))
            except Exception:
                pass
            return False

        try:
            target_line = int(line_no)
        except Exception:
            target_line = 0

        try:
            covered_rows = int(covered_rows or 0)
        except Exception:
            covered_rows = 0

        if TARGET_LINE_BELOW_STICKY_OVERLAY:
            try:
                covered_rows += int(TARGET_LINE_EXTRA_TOP_PADDING_ROWS or 0)
            except Exception:
                pass
            scroll_top_line = max(0, target_line - max(0, covered_rows))
        else:
            scroll_top_line = target_line

        moved_any = False
        reports = []

        for sb in scrollbars:
            try:
                maximum = int(sb.maximum())
                minimum = int(sb.minimum())
                if maximum <= minimum:
                    continue

                if maximum > total_lines * 2:
                    value = int((float(scroll_top_line) / float(max(1, total_lines - 1))) * maximum)
                else:
                    value = int(scroll_top_line)

                value = max(minimum, min(value, maximum))
                old_value = int(sb.value())
                sb.setValue(value)
                try:
                    sb.setSliderPosition(value)
                except Exception:
                    pass
                try:
                    sb.triggerAction(QtWidgets.QAbstractSlider.SliderMove)
                except Exception:
                    pass
                try:
                    sb.parentWidget().update()
                except Exception:
                    pass
                moved_any = True
                reports.append("%d:%d->%d/%d target=%d top=%d cover=%d" % (
                    len(reports), old_value, value, maximum, int(target_line) + 1, int(scroll_top_line) + 1, int(covered_rows)
                ))
            except Exception as e:
                reports.append("err:%s" % e)

        try:
            print("[%s] fallback Qt scrollbars %s" % (PLUGIN_NAME, "; ".join(reports[:6])))
        except Exception:
            pass

        return moved_any

    def _set_vu_cursor_line(self, vu, line_no):
        ok = False

        try:
            cpos = vu.cpos
        except Exception:
            cpos = None

        if cpos is None:
            return False

        for attr_name in ("lnnum", "n", "line"):
            try:
                setattr(cpos, attr_name, int(line_no))
                ok = True
                break
            except Exception:
                pass

        try:
            cpos.x = 0
        except Exception:
            pass

        try:
            vu.cpos = cpos
            ok = True
        except Exception:
            pass

        return ok

    def _resolve_qt_widget_for_jump(self, widget):
        cur = widget
        for _ in range(10):
            if cur is None:
                break
            try:
                if id(cur) in self.qt_to_twidget:
                    return cur
            except Exception:
                pass
            try:
                cur = cur.parentWidget()
            except Exception:
                break

        try:
            current_twidget = ida_kernwin.get_current_widget()
        except Exception:
            current_twidget = None

        if current_twidget is not None:
            try:
                for candidate, twidget in list(self.qt_to_twidget.items()):
                    if twidget == current_twidget:
                        for overlay_key, overlay in list(self.overlays.items()):
                            if overlay_key == candidate:
                                return overlay.parentWidget()
            except Exception:
                pass

        return widget

    def _line_from_place(self, place):
        if place is None:
            return None

        simple_place = None
        try:
            simple_place = ida_kernwin.place_t.as_simpleline_place_t(place)
        except Exception:
            try:
                simple_place = ida_kernwin.place_t_as_simpleline_place_t(place)
            except Exception:
                simple_place = None

        if simple_place is not None:
            for attr_name in ("n", "lnnum", "line"):
                try:
                    return int(getattr(simple_place, attr_name))
                except Exception:
                    pass

        for attr_name in ("n", "lnnum", "line"):
            try:
                return int(getattr(place, attr_name))
            except Exception:
                pass

        return None

    def _current_pseudocode_position(self, twidget=None, vu=None):
        line_no = None

        if twidget is not None:
            try:
                current = ida_kernwin.get_custom_viewer_place(twidget, False)
                place = current[0] if isinstance(current, tuple) and current else current
                line_no = self._line_from_place(place)
            except Exception:
                line_no = None

        if line_no is None and vu is not None:
            try:
                cpos = vu.cpos
            except Exception:
                cpos = None
            if cpos is not None:
                for attr_name in ("lnnum", "n", "line"):
                    try:
                        line_no = int(getattr(cpos, attr_name))
                        break
                    except Exception:
                        pass

        if line_no is None:
            return None

        entry_ea = None
        if vu is not None:
            try:
                entry_ea = int(vu.cfunc.entry_ea)
            except Exception:
                entry_ea = None

        return {"line": max(0, int(line_no)), "entry_ea": entry_ea}

    def _push_back_jump_position(self, twidget, vu, target_line=None):
        global BACK_JUMP_STACK

        pos = self._current_pseudocode_position(twidget, vu)
        if pos is None:
            return False

        try:
            if target_line is not None and int(pos.get("line", -1)) == int(target_line):
                return False
        except Exception:
            pass

        if BACK_JUMP_STACK:
            last = BACK_JUMP_STACK[-1]
            try:
                if int(last.get("line", -1)) == int(pos.get("line", -2)) and last.get("entry_ea") == pos.get("entry_ea"):
                    return False
            except Exception:
                pass

        BACK_JUMP_STACK.append(pos)
        if len(BACK_JUMP_STACK) > BACK_JUMP_STACK_MAX:
            del BACK_JUMP_STACK[:-BACK_JUMP_STACK_MAX]

        try:
            print("[%s] back stack push line %d, size=%d" % (
                PLUGIN_NAME,
                int(pos.get("line", 0)) + 1,
                len(BACK_JUMP_STACK),
            ))
        except Exception:
            pass

        return True

    def _pop_back_jump_position(self):
        global BACK_JUMP_STACK
        if not BACK_JUMP_STACK:
            return None
        try:
            return BACK_JUMP_STACK.pop()
        except Exception:
            return None

    def handle_back_key(self, widget, event):
        try:
            key = event.key()
        except Exception:
            key = None

        try:
            text = str(event.text() or "").lower()
        except Exception:
            text = ""

        is_b = False
        try:
            is_b = key == QtCore.Qt.Key_B
        except Exception:
            is_b = False

        if not is_b and text != "b":
            return False

        try:
            modifiers = event.modifiers()
            blocked_modifiers = QtCore.Qt.ControlModifier | QtCore.Qt.AltModifier | QtCore.Qt.MetaModifier
            if modifiers & blocked_modifiers:
                return False
        except Exception:
            pass

        qt_widget = self._resolve_qt_widget_for_jump(widget)
        pos = self._pop_back_jump_position()
        if pos is None:
            try:
                print("[%s] back stack empty" % PLUGIN_NAME)
            except Exception:
                pass
            return True

        try:
            line_no = int(pos.get("line", 0))
        except Exception:
            line_no = 0

        def _do_back_request(m=self, w=qt_widget, line=line_no):
            try:
                m.jump_to_sticky_target_line(w, line, clicked_row=None, record_back=False, jump_reason="back")
            except Exception as e:
                try:
                    print("[%s] back jump failed: %s" % (PLUGIN_NAME, e))
                except Exception:
                    pass
            return False

        try:
            ida_kernwin.execute_ui_requests((_do_back_request,))
        except Exception:
            try:
                QtCore.QTimer.singleShot(0, lambda m=self, w=qt_widget, line=line_no: m.jump_to_sticky_target_line(w, line, clicked_row=None, record_back=False, jump_reason="back"))
            except Exception:
                pass

        try:
            print("[%s] back stack pop -> pseudocode line %d, size=%d" % (
                PLUGIN_NAME,
                int(line_no) + 1,
                len(BACK_JUMP_STACK),
            ))
        except Exception:
            pass

        return True

    def jump_to_sticky_target_line(self, qt_widget, line_no, clicked_row=None, record_back=True, jump_reason="sticky"):
        if self.jump_in_progress:
            return False

        self.jump_in_progress = True
        timer_was_active = False
        jumped = False
        used_method = "none"

        try:
            if qt_widget is None:
                return False

            twidget = self._twidget_for_qwidget(qt_widget)

            if not twidget:
                return False

            try:
                if ida_kernwin.get_widget_type(twidget) != ida_kernwin.BWN_PSEUDOCODE:
                    return False
            except Exception:
                return False

            try:
                vu = ida_hexrays.get_widget_vdui(twidget)
            except Exception:
                vu = None

            if not vu:
                return False

            try:
                if hasattr(vu, "valid") and not vu.valid():
                    return False
            except Exception:
                pass

            line_no, total_lines = self._clamp_target_line(vu, line_no)

            if record_back:
                try:
                    self._push_back_jump_position(twidget, vu, target_line=line_no)
                except Exception as e:
                    try:
                        print("[%s] push back stack failed: %s" % (PLUGIN_NAME, e))
                    except Exception:
                        pass

            try:
                timer_was_active = self.timer.isActive()
                if timer_was_active:
                    self.timer.stop()
            except Exception:
                timer_was_active = False

            try:
                ida_kernwin.activate_widget(twidget, True)
            except Exception:
                pass

            scroll_widget = self._root_for_overlay_parent(qt_widget) or qt_widget
            current_cover_rows = self._sticky_overlay_visible_rows(qt_widget, clicked_row)
            covered_rows, predicted_top_line, predicted_scopes = self._predict_post_jump_cover_rows(
                vu,
                line_no,
                total_lines,
                current_cover_rows,
            )

            # First move the Hex-Rays cursor to the real target line, then force the
            # Qt viewport top line upward by the sticky row count predicted for the
            # post-jump viewport, not the old pre-jump overlay.
            jump_ok = self._jump_custom_viewer_to_line(twidget, line_no, visible_y=covered_rows)

            try:
                self._set_vu_cursor_line(vu, line_no)
            except Exception:
                pass

            scroll_ok = self._scroll_qt_view_to_line(scroll_widget, line_no, total_lines, covered_rows)

            if jump_ok and scroll_ok:
                jumped = True
                used_method = "custom_viewer_jumpto+qt_scrollbar_under_sticky"
            elif scroll_ok:
                jumped = True
                used_method = "qt_scrollbar_under_sticky"
            elif jump_ok:
                jumped = True
                used_method = "custom_viewer_jumpto"

            try:
                qt_widget.setFocus(QtCore.Qt.OtherFocusReason)
            except Exception:
                pass

            try:
                qt_widget.update()
            except Exception:
                pass

            try:
                print("[%s] %s row %s -> pseudocode line %d, post_cover=%d, predicted_top=%d, method=%s, jumped=%s, back_stack=%d" % (
                    PLUGIN_NAME,
                    str(jump_reason or "sticky"),
                    "" if clicked_row is None else str(int(clicked_row) + 1),
                    int(line_no) + 1,
                    int(covered_rows),
                    int(predicted_top_line) + 1,
                    used_method,
                    str(bool(jumped)),
                    len(BACK_JUMP_STACK),
                ))
            except Exception:
                pass

            try:
                QtCore.QTimer.singleShot(50, lambda w=scroll_widget, ln=line_no, tl=total_lines, cr=covered_rows: self._scroll_qt_view_to_line(w, ln, tl, cr))
            except Exception:
                pass

            try:
                QtCore.QTimer.singleShot(100, self.request_update)
            except Exception:
                pass

            return jumped

        finally:
            try:
                if timer_was_active and not self.timer.isActive():
                    self.timer.start()
            except Exception:
                pass
            self.jump_in_progress = False

    def _make_parser_from_cfunc(self, cfunc):
        try:
            sv = cfunc.get_pseudocode()
            total_lines = len(sv)
            lines = [_simpleline_to_text(sv[i]) for i in range(total_lines)]
            tagged_lines = [_simpleline_to_tagged(sv[i]) for i in range(total_lines)]
            lvar_names = _get_lvar_names(cfunc)
        except Exception:
            return None, 0, None

        scope_parser = ScopeParser(lines, tagged_lines, lvar_names)
        return scope_parser, total_lines, sv

    def _get_parser_and_total_lines(self, vu):
        try:
            entry = int(vu.cfunc.entry_ea)
        except Exception:
            entry = 0

        try:
            sv = vu.cfunc.get_pseudocode()
            total_lines = len(sv)
            lvar_count = len(_get_lvar_names(vu.cfunc))
        except Exception:
            return None, 0

        key = (entry, total_lines, lvar_count)

        if key != self.cache_key:
            try:
                lines = [_simpleline_to_text(sv[i]) for i in range(total_lines)]
                tagged_lines = [_simpleline_to_tagged(sv[i]) for i in range(total_lines)]
                lvar_names = _get_lvar_names(vu.cfunc)
            except Exception:
                return None, 0

            self.cache_key = key
            self.cache_parser = ScopeParser(lines, tagged_lines, lvar_names)
            self.cache_total_lines = len(lines)

        return self.cache_parser, self.cache_total_lines

    def colorize_cfunc_braces(self, cfunc):
        if not ENABLE_HEXRAYS_TEXT_REWRITE:
            return False
        if self.in_text_coloring:
            return False

        self.in_text_coloring = True
        changed_any = False

        try:
            scope_parser, total_lines, sv = self._make_parser_from_cfunc(cfunc)

            if scope_parser is None or total_lines <= 0 or sv is None:
                return False

            brace_map = scope_parser.build_brace_map()
            if not brace_map:
                return False

            for line_no, brace_specs in brace_map.items():
                try:
                    sl = sv[line_no]
                    old_line = str(sl.line)
                    new_line = _colorize_tagged_line_visible_braces(old_line, brace_specs)
                    if new_line != old_line:
                        sl.line = new_line
                        changed_any = True
                except Exception:
                    pass

        finally:
            self.in_text_coloring = False

        if changed_any:
            self.invalidate_cache()

        return changed_any

    def _cursor_line(self, vu):
        try:
            use_keyboard = getattr(ida_hexrays, "USE_KEYBOARD", 0)
            vu.refresh_cpos(use_keyboard)
            line_no = int(vu.cpos.lnnum)
            if line_no >= 0:
                return line_no
        except Exception:
            pass
        return 0

    def _scrollbar_top_line(self, qt_widget, total_lines, fallback):
        if not USE_SCROLLBAR_TOP_LINE:
            return fallback

        try:
            scrollbars = qt_widget.findChildren(QtWidgets.QScrollBar)
        except Exception:
            return fallback

        candidates = []
        for sb in scrollbars:
            try:
                if sb.isVisible() and sb.orientation() == QtCore.Qt.Vertical and sb.maximum() > 0:
                    candidates.append(sb)
            except Exception:
                pass

        if not candidates:
            return fallback

        sb = max(candidates, key=lambda x: x.maximum())

        try:
            value = int(sb.value())
            maximum = int(sb.maximum())
        except Exception:
            return fallback

        if total_lines <= 0:
            return 0

        if maximum > total_lines * 2:
            ratio = value / float(maximum)
            line_no = int(ratio * max(0, total_lines - 1))
        else:
            line_no = value

        return max(0, min(line_no, total_lines - 1))

    def _trim_scopes(self, scopes):
        scopes = list(scopes)
        if len(scopes) > MAX_STICKY_LEVELS:
            scopes = scopes[-MAX_STICKY_LEVELS:]
        return tuple(scopes)

    def _drop_scopes_past_sticky_bottom(self, scopes, top_line):
        selected = list(scopes)

        while selected:
            sticky_bottom_line = int(top_line) + len(selected)

            kept = []
            for scope in selected:
                try:
                    scope_end = int(scope.end)
                except Exception:
                    scope_end = -1

                if scope_end >= sticky_bottom_line:
                    kept.append(scope)

            if len(kept) == len(selected):
                break

            selected = kept

        return tuple(selected)

    def _is_bottom_promotable(self, scope):
        kind = (scope.kind or "").strip().lower()
        return kind in BOTTOM_PROMOTION_KINDS

    def _normalize_selected_against_focus(self, selected, focus_scopes, min_changed_depth):
        if min_changed_depth is None:
            return selected

        focus_ids = set(s.sid for s in focus_scopes)
        normalized = []

        for scope in selected:
            if scope.sid in focus_ids or scope.depth < min_changed_depth:
                normalized.append(scope)

        return normalized

    def _remove_conflicting_branch_siblings(self, selected):
        if len(selected) <= 1:
            return selected

        selected_sorted = sorted(selected, key=lambda s: (s.depth, s.start, s.brace_line, s.sid))
        winners = {}

        for scope in selected_sorted:
            kind = (scope.kind or "").strip().lower()
            if kind not in BRANCH_KINDS:
                continue

            key = scope.depth
            old = winners.get(key)
            if old is None or scope.start > old.start or (scope.start == old.start and scope.sid > old.sid):
                winners[key] = scope

        result = []
        for scope in selected:
            kind = (scope.kind or "").strip().lower()
            if kind in BRANCH_KINDS:
                winner = winners.get(scope.depth)
                if winner is not None and winner.sid != scope.sid:
                    continue
            result.append(scope)

        return result

    def _select_scopes_by_bottom_touch(self, parser, top_line, total_lines):
        base_scopes = list(parser.active_at(top_line, trim=False))

        if not BOTTOM_TOUCH_PROMOTION:
            return self._trim_scopes(base_scopes), top_line

        selected = list(base_scopes)
        max_rounds = MAX_STICKY_LEVELS + 6

        for _ in range(max_rounds):
            visible_rows = min(max(1, len(selected)), MAX_STICKY_LEVELS)
            touch_line = top_line + visible_rows
            touch_line = max(0, min(touch_line, total_lines - 1))
            touch_scopes = list(parser.active_at(touch_line, trim=False))

            seen = set(s.sid for s in selected)
            changed = False
            min_changed_depth = None

            for scope in touch_scopes:
                if scope.sid in seen:
                    continue
                if not self._is_bottom_promotable(scope):
                    continue

                selected.append(scope)
                seen.add(scope.sid)
                changed = True

                if min_changed_depth is None:
                    min_changed_depth = scope.depth
                else:
                    min_changed_depth = min(min_changed_depth, scope.depth)

            if changed:
                selected = self._normalize_selected_against_focus(selected, touch_scopes, min_changed_depth)
                selected = self._remove_conflicting_branch_siblings(selected)

            if not changed or touch_line >= total_lines - 1:
                break

        selected = self._remove_conflicting_branch_siblings(selected)
        selected = self._trim_scopes(selected)
        selected = self._drop_scopes_past_sticky_bottom(selected, top_line)
        return selected, top_line

    def update_active(self):
        if QtWidgets is None:
            return
        if self.jump_in_progress or self.in_text_coloring:
            return

        try:
            twidget = ida_kernwin.get_current_widget()
        except Exception:
            self.hide_all()
            return

        if not twidget:
            self.hide_all()
            return

        try:
            widget_type = ida_kernwin.get_widget_type(twidget)
        except Exception:
            self.hide_all()
            return

        if widget_type != ida_kernwin.BWN_PSEUDOCODE:
            self.hide_all()
            return

        if not self.ensure_hexrays():
            self.hide_all()
            return

        try:
            vu = ida_hexrays.get_widget_vdui(twidget)
        except Exception:
            self.hide_all()
            return

        if not vu:
            self.hide_all()
            return

        try:
            if hasattr(vu, "valid") and not vu.valid():
                self.hide_all()
                return
        except Exception:
            pass

        try:
            if hasattr(vu, "visible") and not vu.visible():
                self.hide_all()
                return
        except Exception:
            pass

        root_qt_widget = self._twidget_to_qwidget(twidget)
        if root_qt_widget is None:
            self.hide_all()
            return

        qt_widget = self._select_overlay_parent(root_qt_widget)
        if qt_widget is None:
            qt_widget = root_qt_widget

        integrated_code_x = None
        integrated_code_y = None
        top_level_overlay = bool(USE_SCREEN_STICKY_OVERLAY)
        if top_level_overlay:
            overlay_parent = qt_widget
            current_key = ("screen", id(qt_widget))
        elif USE_INTEGRATED_ROOT_OVERLAY:
            # IDA 9.2 fallback path: parent the overlay to the stable ancestor
            # that contains the original line-number gutter.
            overlay_parent, integrated_code_x, integrated_code_y = self._select_true_gutter_overlay_host(root_qt_widget, qt_widget)
            current_key = id(overlay_parent)
        else:
            overlay_parent = qt_widget
            current_key = id(overlay_parent)

        self._remember_overlay_root(overlay_parent, root_qt_widget, twidget)
        self._remember_overlay_root(root_qt_widget, root_qt_widget, twidget)
        self._remember_overlay_root(qt_widget, root_qt_widget, twidget)
        self._hide_non_current_overlays(current_key)
        self._install_filter_once(root_qt_widget, ("root", current_key))

        try:
            parser, total_lines = self._get_parser_and_total_lines(vu)
        except Exception:
            self.hide_all()
            return

        if parser is None or total_lines <= 0:
            self.hide_all()
            return

        try:
            row_height = _estimate_code_line_height(qt_widget)
            cursor_line = self._cursor_line(vu)
            top_line = self._scrollbar_top_line(root_qt_widget, total_lines, cursor_line)
            scopes, _touch_line = self._select_scopes_by_bottom_touch(parser, top_line, total_lines)
        except Exception:
            self.hide_all()
            return

        overlay = self._get_overlay(overlay_parent, top_level=top_level_overlay)
        if top_level_overlay:
            geom_rect, gutter_width, text_offset = self._make_screen_overlay_geometry(
                qt_widget,
                row_height,
                len(scopes),
                total_lines,
            )
            overlay.set_scopes(
                scopes,
                row_height,
                geom_rect=geom_rect,
                source_font=qt_widget.font(),
                gutter_width=gutter_width,
                text_offset=text_offset,
                draw_gutter=ENABLE_GUTTER_LINE_OVERLAY,
            )
            self._hide_gutter_for(qt_widget)
            self._hide_gutter_for(overlay_parent)
        elif USE_INTEGRATED_ROOT_OVERLAY:
            geom_rect, gutter_width, text_offset = self._make_root_overlay_geometry(
                overlay_parent,
                qt_widget,
                row_height,
                len(scopes),
                total_lines,
                integrated_code_x,
                integrated_code_y,
            )
            overlay.set_scopes(
                scopes,
                row_height,
                geom_rect=geom_rect,
                source_font=qt_widget.font(),
                gutter_width=gutter_width,
                text_offset=text_offset,
                draw_gutter=ENABLE_GUTTER_LINE_OVERLAY,
            )
            # The integrated overlay already draws line numbers, so the old
            # standalone gutter overlay must be hidden to avoid drifting panels.
            self._hide_gutter_for(qt_widget)
            self._hide_gutter_for(overlay_parent)
        else:
            overlay.set_scopes(scopes, row_height, source_font=qt_widget.font())

            if ENABLE_GUTTER_LINE_OVERLAY:
                host_widget, gutter_rect = self._find_gutter_host_and_rect(
                    qt_widget,
                    row_height,
                    total_lines,
                    len(scopes),
                    root_qt_widget,
                )

                if host_widget is not None and gutter_rect.isValid():
                    gutter_overlay = self._get_gutter_overlay(host_widget, qt_widget)
                    gutter_overlay.set_scopes(
                        scopes,
                        row_height,
                        total_lines,
                        gutter_rect,
                        qt_widget.font(),
                    )
                else:
                    self._hide_gutter_for(qt_widget)
            else:
                self._hide_gutter_for(qt_widget)


class ScopeStickyPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        ida_idaapi.plugmod_t.__init__(self)
        self.manager = ScopeStickyManager()

        if CSS_LOADED_FILES:
            print("[%s] CSS loaded:" % PLUGIN_NAME)
            for path in CSS_LOADED_FILES:
                print("  %s" % path)
            print("[%s] CSS light props: %d, dark props: %d" % (
                PLUGIN_NAME, len(CSS_LIGHT_PROPS), len(CSS_DARK_PROPS),
            ))
        else:
            print("[%s] CSS not found, using fallback color table" % PLUGIN_NAME)

        if IMPORT_NAME_CACHE is not None:
            print("[%s] import names loaded: %d" % (PLUGIN_NAME, len(IMPORT_NAME_CACHE)))

        print("[%s] loaded %s, IDA=%s, Qt=%s, safe_mode=%s, text_rewrite=%s" % (
            PLUGIN_NAME,
            PLUGIN_VERSION,
            IDA_VERSION_TEXT,
            QT_BINDING,
            str(bool(IDA92_SAFE_MODE)),
            str(bool(ENABLE_HEXRAYS_TEXT_REWRITE)),
        ))

    def __del__(self):
        try:
            self.manager.close()
        except Exception:
            pass
        print("[%s] unloaded" % PLUGIN_NAME)

    def run(self, arg):
        try:
            self.manager.invalidate_cache()
            self.manager.request_update()
        except Exception:
            pass


class ScopeStickyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI
    comment = "Sticky pseudocode brace scope overlay"
    help = "Shows nested brace scopes at the top of Hex Rays pseudocode views"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        if QtWidgets is None:
            print("[%s] Qt binding is not available" % PLUGIN_NAME)
            return None
        return ScopeStickyPlugmod()


def PLUGIN_ENTRY():
    return ScopeStickyPlugin()
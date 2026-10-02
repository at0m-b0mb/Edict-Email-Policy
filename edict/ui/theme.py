"""
The design system.

One place for every colour, typeface and measurement, so Herald looks designed
rather than assembled. Nothing here draws anything — a widget asks for a token
and gets a value.

Two rules hold the palette together, carried over from the rest of the
catalogue. Every colour is declared as a ``(light, dark)`` pair at the point of
definition, so there is no way to add one and forget the dark theme. And there
are two golds, not one: a deep brass that stays legible as small text, and a
bright shine used only on marks that carry no words.

Dark mode is true black — ``#000000``, with neutral greys above it and nothing
in the ramp that reads as blue.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass

_IS_MAC = platform.system() == "Darwin"
_IS_WIN = platform.system() == "Windows"

LIGHT = "light"
DARK = "dark"
AUTO = "auto"


# --- typefaces --------------------------------------------------------------
# A serif for identity and figures, a neutral sans for controls, a mono for the
# raw headers the user is reading. That mix is most of the effect.

if _IS_MAC:
    SERIF = "Iowan Old Style"
    SERIF_FALLBACK = "Palatino, Georgia, serif"
    SANS = "SF Pro Text"
    SANS_FALLBACK = "Helvetica Neue, Arial, sans-serif"
    MONO = "SF Mono"
    MONO_FALLBACK = "Menlo, Monaco, monospace"
elif _IS_WIN:
    SERIF = "Georgia"
    SERIF_FALLBACK = "Times New Roman, serif"
    SANS = "Segoe UI"
    SANS_FALLBACK = "Tahoma, Arial, sans-serif"
    MONO = "Cascadia Mono"
    MONO_FALLBACK = "Consolas, Courier New, monospace"
else:
    SERIF = "DejaVu Serif"
    SERIF_FALLBACK = "Liberation Serif, Times New Roman, serif"
    SANS = "Inter"
    SANS_FALLBACK = "DejaVu Sans, Liberation Sans, sans-serif"
    MONO = "DejaVu Sans Mono"
    MONO_FALLBACK = "Liberation Mono, monospace"

SERIF_STACK = f'"{SERIF}", {SERIF_FALLBACK}'
SANS_STACK = f'"{SANS}", {SANS_FALLBACK}'
MONO_STACK = f'"{MONO}", {MONO_FALLBACK}'

TYPE = {
    "wordmark":   (SERIF_STACK, 23, 600),
    "display":    (SERIF_STACK, 32, 400),
    "page_title": (SERIF_STACK, 23, 400),
    "figure":     (SERIF_STACK, 44, 400),
    "grade":      (SERIF_STACK, 60, 500),
    "card_title": (SANS_STACK, 13, 650),
    "subtitle":   (SANS_STACK, 12, 400),
    "body":       (SANS_STACK, 13, 400),
    "body_bold":  (SANS_STACK, 13, 650),
    "small":      (SANS_STACK, 11, 400),
    "label":      (SANS_STACK, 10, 650),
    "mono":       (MONO_STACK, 12, 400),
    "mono_small": (MONO_STACK, 11, 400),
}

SPACE = {"hair": 2, "tight": 4, "snug": 8, "base": 12, "roomy": 16,
         "wide": 24, "gutter": 32, "page": 40}

RADIUS = {"sharp": 0, "small": 3, "card": 6, "pill": 999}


# --- colour -----------------------------------------------------------------

@dataclass(frozen=True)
class Pair:
    light: str
    dark: str

    def get(self, mode: str) -> str:
        return self.dark if mode == DARK else self.light


PALETTE: dict[str, Pair] = {
    # grounds
    "canvas":        Pair("#F3F1EC", "#000000"),
    "surface":       Pair("#FFFFFF", "#131312"),
    "surface_alt":   Pair("#FAF8F4", "#1B1B19"),
    "sunken":        Pair("#EBE7DE", "#0A0A09"),
    "rail":          Pair("#EDEAE2", "#0B0B0A"),

    # lines
    "rule":          Pair("#DCD6C9", "#2B2B28"),
    "rule_strong":   Pair("#C4BCAA", "#3D3C38"),

    # ink
    "ink":           Pair("#1B1813", "#F3F0E9"),
    "ink_muted":     Pair("#575144", "#A29C91"),
    "ink_faint":     Pair("#847D6E", "#6B675F"),
    "ink_inverse":   Pair("#FFFFFF", "#0A0A09"),

    # gold, twice over
    "brass":         Pair("#7A5D18", "#D9B75C"),   # legible as text
    "shine":         Pair("#C39B24", "#F1C84B"),   # marks only, never text
    "brass_wash":    Pair("#F7F0DC", "#221D0E"),
    "brass_edge":    Pair("#E3D4A5", "#463A1A"),

    # selection and focus
    "select":        Pair("#E6DFCB", "#2A2519"),
    "focus":         Pair("#7A5D18", "#D9B75C"),

    # severity — the five voices a finding can speak in
    "sev_good":      Pair("#2C6249", "#67BE94"),
    "sev_good_wash": Pair("#E9F3ED", "#0D1F16"),
    "sev_info":      Pair("#575144", "#A29C91"),
    "sev_info_wash": Pair("#FAF8F4", "#1B1B19"),
    "sev_notice":    Pair("#7A5D18", "#D9B75C"),
    "sev_notice_wash": Pair("#F7F0DC", "#221D0E"),
    "sev_warning":   Pair("#8A5410", "#DDA356"),
    "sev_warning_wash": Pair("#FAF0DF", "#251A0B"),
    "sev_alert":     Pair("#8C1F16", "#EE8B82"),
    "sev_alert_wash": Pair("#FBE9E7", "#2A100E"),

    # the two kinds of hop on the itinerary
    "hop_external":  Pair("#7A5D18", "#D9B75C"),
    "hop_internal":  Pair("#575144", "#A29C91"),
}


def color(name: str, mode: str) -> str:
    return PALETTE[name].get(mode)


def font_css(role: str) -> str:
    family, size, weight = TYPE[role]
    return f"font-family: {family}; font-size: {size}px; font-weight: {weight};"


def resolve(mode: str) -> str:
    """Turn AUTO into a real mode by asking the platform."""
    if mode != AUTO:
        return mode
    try:
        from PyQt6.QtGui import QPalette
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            window = app.palette().color(QPalette.ColorRole.Window)
            return DARK if window.lightness() < 128 else LIGHT
    except Exception:
        pass
    return LIGHT


# Map a finding's severity name (from the model) to its token family.
SEVERITY_TOKEN = {
    "good": "sev_good",
    "info": "sev_info",
    "notice": "sev_notice",
    "warning": "sev_warning",
    "alert": "sev_alert",
}


def grade_token(letter: str) -> str:
    """Which severity colour a letter grade should wear."""
    head = letter[0]
    if head == "A":
        return "sev_good"
    if head == "B":
        return "sev_good"
    if head == "C":
        return "sev_notice"
    if head == "D":
        return "sev_warning"
    return "sev_alert"


# --- stylesheet -------------------------------------------------------------

def stylesheet(mode: str) -> str:
    """The whole application's QSS, built from the tokens above."""
    c = lambda n: color(n, mode)  # noqa: E731
    s = SPACE

    return f"""
QWidget {{
    background: transparent;
    color: {c('ink')};
    {font_css('body')}
}}
QMainWindow, #PageHost {{ background: {c('canvas')}; }}

#Rail {{ background: {c('rail')}; border-right: 1px solid {c('rule')}; }}
#Wordmark {{ {font_css('wordmark')} color: {c('ink')}; letter-spacing: 3px; }}
#WordmarkSub {{ {font_css('label')} color: {c('ink_faint')}; letter-spacing: 1.6px; }}
#NavButton {{
    text-align: left;
    padding: {s['snug']}px {s['base']}px;
    border: none;
    border-left: 2px solid transparent;
    border-radius: 0px;
    color: {c('ink_muted')};
    {font_css('body')}
}}
#NavButton:hover {{ background: {c('surface_alt')}; color: {c('ink')}; }}
#NavButton:checked {{
    background: {c('surface')};
    color: {c('ink')};
    border-left: 2px solid {c('shine')};
    font-weight: 650;
}}
#NavGroup {{
    {font_css('label')}
    color: {c('ink_faint')};
    letter-spacing: 1.4px;
    padding: {s['base']}px {s['base']}px {s['tight']}px {s['base']}px;
}}

#Card {{ background: {c('surface')}; border: 1px solid {c('rule')};
         border-radius: {RADIUS['card']}px; }}
#CardFlat {{ background: {c('surface_alt')}; border: 1px solid {c('rule')};
             border-radius: {RADIUS['card']}px; }}
#CardTitle {{ {font_css('card_title')} color: {c('ink')}; }}
#PageTitle {{ {font_css('page_title')} color: {c('ink')}; }}
#PageIntro {{ {font_css('subtitle')} color: {c('ink_muted')}; }}
#Display   {{ {font_css('display')} color: {c('ink')}; }}
#Figure    {{ {font_css('figure')} color: {c('ink')}; }}
#Muted     {{ color: {c('ink_muted')}; }}
#Faint     {{ color: {c('ink_faint')}; {font_css('small')} }}
#Label     {{ {font_css('label')} color: {c('ink_faint')}; letter-spacing: 1.2px; }}
#Rule      {{ background: {c('rule')}; border: none; max-height: 1px; }}

QPushButton {{
    background: {c('surface')};
    color: {c('ink')};
    border: 1px solid {c('rule_strong')};
    border-radius: {RADIUS['small']}px;
    padding: 6px {s['base']}px;
    {font_css('body')}
}}
QPushButton:hover  {{ background: {c('surface_alt')}; border-color: {c('brass')}; }}
QPushButton:pressed {{ background: {c('select')}; }}
QPushButton:disabled {{ color: {c('ink_faint')}; border-color: {c('rule')}; }}
QPushButton#Primary {{
    background: {c('brass')};
    color: {c('ink_inverse')};
    border: 1px solid {c('brass')};
    font-weight: 650;
}}
QPushButton#Primary:hover {{ background: {c('shine')}; border-color: {c('shine')};
                             color: {'#1B1813' if mode == DARK else '#FFFFFF'}; }}
QPushButton#Quiet {{
    background: transparent;
    border: 1px solid transparent;
    color: {c('ink_muted')};
    padding: 3px {s['snug']}px;
}}
QPushButton#Quiet:hover {{ color: {c('ink')}; border-color: {c('rule')}; }}

QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {{
    background: {c('surface')};
    color: {c('ink')};
    border: 1px solid {c('rule_strong')};
    border-radius: {RADIUS['small']}px;
    padding: 5px {s['snug']}px;
    selection-background-color: {c('select')};
    selection-color: {c('ink')};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus {{
    border: 1px solid {c('focus')};
}}
QPlainTextEdit#Mono, QTextEdit#Mono {{ {font_css('mono')} }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox::down-arrow {{
    image: none; width: 0px; height: 0px;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {c('ink_muted')};
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background: {c('surface')};
    border: 1px solid {c('rule_strong')};
    selection-background-color: {c('select')};
    selection-color: {c('ink')};
    outline: none;
}}

QTabWidget::pane {{ border: none; }}
QTabBar::tab {{
    background: transparent; color: {c('ink_muted')};
    border: none; border-bottom: 2px solid transparent;
    padding: {s['snug']}px {s['base']}px;
    {font_css('body')}
}}
QTabBar::tab:selected {{ color: {c('ink')}; border-bottom: 2px solid {c('shine')};
                         font-weight: 650; }}
QTabBar::tab:hover {{ color: {c('ink')}; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c('rule_strong')}; border-radius: 5px;
                               min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {c('ink_faint')}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {c('rule_strong')}; border-radius: 5px;
                                 min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QSplitter::handle {{ background: {c('rule')}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QToolTip {{
    background: {c('ink')}; color: {c('ink_inverse')};
    border: none; padding: {s['tight']}px {s['snug']}px;
    {font_css('small')}
}}
QMenu {{ background: {c('surface')}; border: 1px solid {c('rule_strong')};
         padding: {s['tight']}px; }}
QMenu::item {{ padding: 5px {s['base']}px; }}
QMenu::item:selected {{ background: {c('select')}; }}
"""


# --- contrast ---------------------------------------------------------------
# Not ceremony. Checking these by eye passes pairings that fail.

def _srgb(channel: float) -> float:
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _srgb(r) + 0.7152 * _srgb(g) + 0.0722 * _srgb(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)

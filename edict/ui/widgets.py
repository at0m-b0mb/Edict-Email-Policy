"""
Small, shared pieces of furniture.

Every card, label and chip the window uses is made here, built from the theme
tokens so the look is one decision made once. Nothing here knows anything about
e-mail — these are generic, and the window fills them with meaning.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme


def _obj(widget: QWidget, name: str) -> QWidget:
    widget.setObjectName(name)
    return widget


class Card(QFrame):
    """A titled panel. The window's basic unit of layout."""

    def __init__(self, title: str = "", flat: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 16)
        outer.setSpacing(theme.SPACE["base"])
        if title:
            outer.addWidget(_obj(QLabel(title), "CardTitle"))
        self.body = QVBoxLayout()
        self.body.setSpacing(theme.SPACE["snug"])
        outer.addLayout(self.body)
        self._outer = outer

    def add(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)


def label(text: str, role: str = "body", muted: bool = False) -> QLabel:
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if role == "body" and muted:
        lab.setObjectName("Muted")
    elif role in ("Muted", "Faint", "Label", "PageTitle", "PageIntro",
                  "Figure", "Display"):
        lab.setObjectName(role)
    return lab


def mini_label(text: str) -> QLabel:
    return _obj(QLabel(text), "Label")


def hrule() -> QFrame:
    line = QFrame()
    line.setObjectName("Rule")
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    return line


class Chip(QLabel):
    """A small pill that carries a verdict word in its own severity colour."""

    def __init__(self, text: str, token: str, mode: str, parent=None):
        super().__init__(text.upper(), parent)
        fg = theme.color(token, mode)
        wash = theme.color(token + "_wash", mode) if token + "_wash" in theme.PALETTE \
            else theme.color("surface_alt", mode)
        edge = theme.color("rule", mode)
        self.setStyleSheet(
            f"color: {fg}; background: {wash}; border: 1px solid {edge};"
            f"border-radius: 3px; padding: 2px 8px;"
            f"{theme.font_css('label')} letter-spacing: 1px;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)


def key_value(key: str, value: str, mode: str, value_token: str | None = None,
              mono: bool = False) -> QWidget:
    """A left-aligned label and its value, for the identity and auth cards."""
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(theme.SPACE["base"])

    k = _obj(QLabel(key), "Label")
    k.setFixedWidth(116)
    k.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
    lay.addWidget(k)

    v = QLabel(value or "—")
    v.setWordWrap(True)
    v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    css = ""
    if mono:
        css += theme.font_css("mono")
    if value_token:
        css += f"color: {theme.color(value_token, mode)};"
    if css:
        v.setStyleSheet(css)
    v.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    lay.addWidget(v, 1)
    return row

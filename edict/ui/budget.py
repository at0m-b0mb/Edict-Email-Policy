"""
The lookup budget — Edict's signature.

SPF has a spending limit almost nobody draws. RFC 7208 allows a receiver ten DNS
lookups to evaluate a record and no more; at the eleventh it stops and returns
``permerror``, which most receivers treat as though the domain published nothing
at all. So a record can be meticulous, accurate, and completely inert, and the
only way to see that coming is to count.

This widget is that count, drawn as what it is: ten cells of a budget, one
filled for each mechanism that spends a lookup, labelled with the mechanism that
spent it, with a hard red line at the tenth and any overflow drawn past the line
in alert colour — because a record that runs over does not get truncated, it
gets discarded.

Two honesty details are built into the picture rather than bolted on. The line
under the gauge always says the count is a *floor*, because Edict never follows
an ``include:`` and each one it counts as a single lookup may really spend five.
And the cells carry the mechanism's own text, so the reader can see which part
of their own record is expensive instead of being told a number.

:class:`PolicyStrength` sits beneath it: the three things a domain declares, as
three chips, each saying how far it actually commits — including ``UNKNOWN``,
which is the honest answer when a selector was never pasted.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from ..core.model import SPF_LOOKUP_LIMIT, Pillar, SpfPolicy
from ..core.spf import budget_line
from . import theme

# --- gauge geometry ---------------------------------------------------------
_MARK_H = 14      # room above the bar for the LIMIT caption
_BAR_H = 30
_NUM_H = 15       # the index number under each spent cell
_LEGEND_ROW = 16
_LEGEND_SPLIT = 6   # a legend longer than this gets a second column
_CAVEAT_H = 34
_GAP = 3          # between cells
_OVERHANG = 5     # how far the limit line reaches past the bar


def _font(role: str) -> QFont:
    family, size, weight = theme.TYPE[role]
    f = QFont()
    f.setFamilies([family.split(",")[0].strip().strip('"')])
    f.setPixelSize(size)
    f.setWeight(QFont.Weight.DemiBold if weight >= 600 else QFont.Weight.Normal)
    return f


def _elide(text: str, width: float, role: str) -> str:
    fm = QFontMetrics(_font(role))
    return fm.elidedText(text, Qt.TextElideMode.ElideMiddle, max(0, int(width)))


class BudgetGauge(QWidget):
    """Ten cells of DNS-lookup budget, and what this record spends them on."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._policy: SpfPolicy | None = None
        self._labels: list[str] = []
        self._mode = theme.LIGHT
        self._limit = SPF_LOOKUP_LIMIT
        self.setMinimumHeight(self._height_for(0))

    # --- data ---------------------------------------------------------------
    def set_data(self, policy: SpfPolicy | None, mode: str,
                 limit: int = SPF_LOOKUP_LIMIT) -> None:
        self._policy = policy
        self._mode = mode
        self._limit = limit
        self._labels = [m.rendered for m in policy.costly] if policy else []
        self.setMinimumHeight(self._height_for(len(self._labels)))
        self.updateGeometry()
        self.update()

    @staticmethod
    def _legend_shape(spent: int) -> tuple[int, int]:
        """``(columns, rows)`` for the legend — one column while it is short."""
        if not spent:
            return 1, 0
        cols = 1 if spent <= _LEGEND_SPLIT else 2
        return cols, math.ceil(spent / cols)

    def _height_for(self, spent: int) -> int:
        _, rows = self._legend_shape(spent)
        return (_MARK_H + _BAR_H + _NUM_H + rows * _LEGEND_ROW + _CAVEAT_H)

    def sizeHint(self):  # noqa: N802  (Qt override)
        return QSize(460, self._height_for(len(self._labels)))

    # --- painting -----------------------------------------------------------
    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        used = self._policy.lookup_cost if self._policy else 0
        inside = max(0, min(used, self._limit))
        over = max(0, used - self._limit)
        cells = max(self._limit, used)

        width = max(1, self.width())
        cell_w = (width - _GAP * (cells - 1)) / cells
        bar_y = _MARK_H

        def cell_x(i: int) -> float:
            return i * (cell_w + _GAP)

        # --- the cells -------------------------------------------------------
        for i in range(cells):
            x = cell_x(i)
            rect = QRectF(x, bar_y, cell_w, _BAR_H)
            if i < inside:
                token = "sev_alert" if over else (
                    "sev_warning" if used >= 8 else "brass")
                p.setPen(QPen(c(token), 1))
                p.setBrush(QBrush(c(token)))
            elif i >= self._limit:
                # past the line: the lookups a receiver will never spend
                p.setPen(QPen(c("sev_alert"), 1))
                p.setBrush(QBrush(c("sev_alert_wash")))
            else:
                p.setPen(QPen(c("rule_strong"), 1))
                p.setBrush(QBrush(c("sunken")))
            p.drawRoundedRect(rect, 2, 2)

            if i >= self._limit:
                # hatch the overflow so it reads as refused, not merely spent
                p.setPen(QPen(c("sev_alert"), 1))
                step = 4
                off = 0.0
                while off < cell_w + _BAR_H:
                    x1 = x + off
                    y1 = bar_y + _BAR_H
                    x2 = x + off - _BAR_H
                    y2 = bar_y
                    if x1 > x + cell_w:
                        y1 = bar_y + _BAR_H - (x1 - (x + cell_w))
                        x1 = x + cell_w
                    if x2 < x:
                        y2 = bar_y + (x - x2)
                        x2 = x
                    if y1 > y2:
                        p.drawLine(int(x1), int(y1), int(x2), int(y2))
                    off += step

        # --- the index number under each spent cell --------------------------
        p.setFont(_font("label"))
        for i in range(min(used, cells)):
            p.setPen(c("sev_alert") if i >= self._limit else c("ink_muted"))
            p.drawText(QRectF(cell_x(i), bar_y + _BAR_H + 1, cell_w, _NUM_H),
                       Qt.AlignmentFlag.AlignCenter, str(i + 1))

        # --- the hard limit at ten -------------------------------------------
        line_x = cell_x(self._limit - 1) + cell_w + _GAP / 2
        p.setPen(QPen(c("sev_alert"), 2))
        p.drawLine(int(line_x), bar_y - _OVERHANG,
                   int(line_x), bar_y + _BAR_H + _OVERHANG)
        p.setFont(_font("label"))
        p.setPen(c("sev_alert"))
        cap = QRectF(line_x - 80, 0, 78, _MARK_H - 1)
        p.drawText(cap, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   f"LIMIT {self._limit}")

        # --- which mechanism spent which lookup ------------------------------
        legend_y = bar_y + _BAR_H + _NUM_H
        cols, rows = self._legend_shape(len(self._labels))
        col_w = (width - 12 * (cols - 1)) / cols
        p.setFont(_font("mono_small"))
        for i, text in enumerate(self._labels):
            col, row = divmod(i, rows) if rows else (0, 0)
            x = col * (col_w + 12)
            y = legend_y + row * _LEGEND_ROW
            p.setPen(c("sev_alert") if i >= self._limit else c("ink_faint"))
            p.drawText(QRectF(x, y, 16, _LEGEND_ROW),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                       f"{i + 1}")
            p.setPen(c("sev_alert") if i >= self._limit else c("ink_muted"))
            p.drawText(QRectF(x + 22, y, col_w - 26, _LEGEND_ROW),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       _elide(text, col_w - 26, "mono_small"))

        # --- the caveat, which is the point ----------------------------------
        caveat_y = legend_y + rows * _LEGEND_ROW + 4
        p.setFont(_font("small"))
        p.setPen(c("sev_alert") if over else c("ink_muted"))
        p.drawText(QRectF(0, caveat_y, width, _CAVEAT_H - 4),
                   int(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                   | int(Qt.TextFlag.TextWordWrap),
                   budget_line(self._policy, self._limit))
        p.end()


# --- the three pillars -------------------------------------------------------

_TILE_H = 66
_TILE_GAP = 10


class PolicyStrength(QWidget):
    """SPF, DKIM and DMARC as three chips: how far each one commits."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pillars: list[Pillar] = []
        self._mode = theme.LIGHT
        self.setMinimumHeight(_TILE_H)
        self.setMaximumHeight(_TILE_H)

    def set_data(self, pillars: list[Pillar], mode: str) -> None:
        self._pillars = pillars
        self._mode = mode
        self.update()

    def sizeHint(self):  # noqa: N802
        return QSize(460, _TILE_H)

    def paintEvent(self, event):  # noqa: N802
        if not self._pillars:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        n = len(self._pillars)
        tile_w = (max(1, self.width()) - _TILE_GAP * (n - 1)) / n
        for i, pillar in enumerate(self._pillars):
            x = i * (tile_w + _TILE_GAP)
            token = pillar.stance.token
            wash = (c(token + "_wash") if token + "_wash" in theme.PALETTE
                    else c("surface_alt"))
            accent = c(token)

            p.setPen(QPen(c("rule"), 1))
            p.setBrush(QBrush(wash))
            p.drawRoundedRect(QRectF(x, 0, tile_w, _TILE_H), 6, 6)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(accent))
            p.drawRoundedRect(QRectF(x, 0, 4, _TILE_H), 2, 2)

            tx = x + 16
            inner = tile_w - 26

            p.setPen(c("ink"))
            p.setFont(_font("body_bold"))
            p.drawText(QRectF(tx, 9, inner, 18),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       pillar.label)

            p.setPen(accent)
            p.setFont(_font("label"))
            p.drawText(QRectF(tx, 29, inner, 14),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       pillar.stance.word)

            if pillar.note:
                p.setPen(c("ink_faint"))
                p.setFont(_font("mono_small"))
                p.drawText(QRectF(tx, 45, inner, 14),
                           Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                           _elide(pillar.note, inner, "mono_small"))
        p.end()

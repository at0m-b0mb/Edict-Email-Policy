#!/usr/bin/env python3
"""
Render the window off-screen and save PNGs — proof the interface works, and the
source of the README's contact sheet.

Runs headless (``QT_QPA_PLATFORM=offscreen``), so it needs no display. It grabs
each sample in both themes, writing ``images/shot-<sample>-<mode>.png``.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from edict.ui import theme  # noqa: E402
from edict.ui.main_window import MainWindow  # noqa: E402

SIZE = (1220, 900)
SHOTS = [
    ("wide-open.dns", theme.LIGHT),
    ("wide-open.dns", theme.DARK),
    ("hardened.dns", theme.LIGHT),
    ("hardened.dns", theme.DARK),
    ("over-budget.dns", theme.LIGHT),
    ("over-budget.dns", theme.DARK),
    ("monitoring-only.dns", theme.LIGHT),
    ("monitoring-only.dns", theme.DARK),
    ("subdomain-gap.dns", theme.LIGHT),
    ("subdomain-gap.dns", theme.DARK),
]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out_dir = os.path.join(ROOT, "images")
    os.makedirs(out_dir, exist_ok=True)
    samples = os.path.join(ROOT, "samples")

    for name, mode in SHOTS:
        win = MainWindow(mode=mode)
        win.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as fh:
            win.source.setPlainText(fh.read())
        win._on_grade()
        win.show()
        app.processEvents()
        app.processEvents()
        base = name[:-4]
        path = os.path.join(out_dir, f"shot-{base}-{mode}.png")
        win.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}  ({mode})")
        win.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Repository art — the social card, the README banner, and the contact sheet.

Three surfaces, three sets of rules, all drawn from the same palette as the
application so the repo and the app read as one thing:

* **social-preview.png** — 1280x640, with GitHub's 40pt (80px) safe border.
  Every piece of information is registered with a :class:`SafeBox` as it is
  drawn, and ``check()`` refuses to write a file that crosses the border.
* **banner.png / banner-dark.png** — 2560x800, a light/dark pair for a README
  ``<picture>``. A banner is never cropped, so its gold band may bleed.
* **screens.png / screens-dark.png** — a contact sheet of real, off-screen
  captures, one sheet per theme so neither README background gets a glaring
  slab.

The signature motif on both the card and the banner is the SPF lookup-budget
gauge, and it is not an illustration of one: this script imports the engine,
grades ``samples/over-budget.dns``, and draws the cells, the labels, the stances
and the caveat sentence the tool itself produced. If the grader changes its
mind, the art changes with it.

Run ``python tools/capture_screenshots.py`` first; the contact sheet needs those
PNGs.
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "images")
sys.path.insert(0, ROOT)

from edict.core.grade import analyze  # noqa: E402
from edict.core.model import SPF_LOOKUP_LIMIT  # noqa: E402
from edict.core.spf import budget_line  # noqa: E402

SERIF = "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc"
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"

# palette, straight from edict.ui.theme
PAPER = "#F3F1EC"
SURFACE = "#FFFFFF"
SUNKEN = "#EBE7DE"
INK = "#1B1813"
INK_MUTED = "#575144"
INK_FAINT = "#847D6E"
RULE = "#DCD6C9"
RULE_STRONG = "#C4BCAA"
BRASS = "#7A5D18"
SHINE = "#C39B24"
GREEN = "#2C6249"
GREEN_WASH = "#E9F3ED"
RED = "#8C1F16"
RED_WASH = "#FBE9E7"

BLACK = "#000000"
D_SURFACE = "#131312"
D_SUNKEN = "#0A0A09"
D_INK = "#F3F0E9"
D_MUTED = "#A29C91"
D_FAINT = "#6B675F"
D_RULE = "#2B2B28"
D_BRASS = "#D9B75C"
D_SHINE = "#F1C84B"
D_GREEN = "#67BE94"
D_GREEN_WASH = "#0D1F16"
D_RED = "#EE8B82"
D_RED_WASH = "#2A100E"


def font(path: str, size: int, index: int = 0) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size, index=index)


def _pal(dark: bool) -> dict:
    if dark:
        return dict(bg=BLACK, surface=D_SURFACE, sunken=D_SUNKEN, ink=D_INK,
                    muted=D_MUTED, faint=D_FAINT, rule=D_RULE,
                    rule_strong="#3D3C38", brass=D_BRASS, shine=D_SHINE,
                    green=D_GREEN, green_wash=D_GREEN_WASH, red=D_RED,
                    red_wash=D_RED_WASH)
    return dict(bg=PAPER, surface=SURFACE, sunken=SUNKEN, ink=INK,
                muted=INK_MUTED, faint=INK_FAINT, rule=RULE,
                rule_strong=RULE_STRONG, brass=BRASS, shine=SHINE, green=GREEN,
                green_wash=GREEN_WASH, red=RED, red_wash=RED_WASH)


class SafeBox:
    """Registers every meaningful rectangle and reports the tightest margin.

    Background art is simply never registered, so it is free to bleed; only the
    things a crop must not eat — wordmark, tagline, pitch, URL, the gauge panel
    — are handed to :meth:`add`.
    """

    def __init__(self, w: int, h: int, safe: int):
        self.w, self.h, self.safe = w, h, safe
        self.rects: list[tuple[str, tuple[int, int, int, int]]] = []

    def add(self, name: str, box: tuple[float, float, float, float]) -> None:
        self.rects.append((name, tuple(int(round(v)) for v in box)))

    def check(self) -> None:
        worst = None
        for name, (l, t, r, b) in self.rects:
            m = min(l, t, self.w - r, self.h - b)
            if worst is None or m < worst[0]:
                worst = (m, name, (l, t, r, b))
        if worst is None:
            return
        m, name, box = worst
        assert m >= self.safe, (
            f"{name} at {box} leaves a {m}px margin on a {self.w}x{self.h} "
            f"canvas; the safe border needs {self.safe}px.")
        print(f"  safe border ok — tightest: {name} at {m}px (need {self.safe})")


def _text(draw, xy, s, fnt, fill, ls=0, anchor="la"):
    """Draw text, optionally letter-spaced, and return its pixel width."""
    if ls == 0:
        draw.text(xy, s, font=fnt, fill=fill, anchor=anchor)
        l, t, r, b = draw.textbbox(xy, s, font=fnt, anchor=anchor)
        return r - l
    x, y = xy
    for ch in s:
        draw.text((x, y), ch, font=fnt, fill=fill, anchor="la")
        w = draw.textbbox((0, 0), ch, font=fnt)[2]
        x += w + ls
    return x - xy[0] - ls


def _wrap(draw, text, fnt, width):
    """Greedy word wrap against a measured pixel width."""
    words, lines, line = text.split(), [], ""
    for word in words:
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=fnt) <= width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def _round_rect(draw, box, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline,
                           width=width)


# --- the motif, taken from the engine ----------------------------------------

def _motif():
    """Grade a real sample and hand back exactly what the tool said.

    The card shows an over-budget record because that is the picture only this
    tool draws: ten cells spent, a hard red line, and an eleventh lookup a
    receiver will never make.
    """
    with open(os.path.join(ROOT, "samples", "over-budget.dns"),
              encoding="utf-8") as fh:
        zone = analyze(fh.read())
    policy = zone.primary_spf
    return {
        "used": policy.lookup_cost,
        "labels": [m.rendered for m in policy.costly],
        "caveat": budget_line(policy, SPF_LOOKUP_LIMIT),
        "pillars": [(p.label, p.stance.word, p.note) for p in zone.pillars],
    }


_STANCE_COLOUR = {
    "ENFORCING": ("green", "green_wash"),
    "PARTIAL": ("brass", "sunken"),
    "PERMISSIVE": ("brass", "sunken"),
    "BROKEN": ("red", "red_wash"),
    "NOT PUBLISHED": ("red", "red_wash"),
    "UNKNOWN": ("muted", "sunken"),
}


def _draw_gauge(d, box, pal, ss, motif, legend_rows=4):
    """Draw the lookup-budget gauge and the three stance chips inside *box*."""
    x0, y0, x1, y1 = box
    _round_rect(d, box, 10 * ss, fill=pal["surface"], outline=pal["rule"],
                width=max(1, ss))
    pad = 26 * ss
    inner_w = (x1 - x0) - pad * 2

    f_cap = font(SANS, 11 * ss)
    f_num = font(SANS, 10 * ss)
    f_mono = font(MONO, 12 * ss)
    f_note = font(SANS, 13 * ss)
    f_name = font(SANS, 14 * ss)
    f_word = font(SANS, 10 * ss)

    _text(d, (x0 + pad, y0 + 18 * ss), "SPF LOOKUP BUDGET", f_cap, pal["faint"],
          ls=2 * ss)

    used = motif["used"]
    cells = max(SPF_LOOKUP_LIMIT, used)
    gap = 3 * ss
    cell_w = (inner_w - gap * (cells - 1)) / cells
    bar_y = y0 + 48 * ss
    bar_h = 30 * ss

    for i in range(cells):
        cx = x0 + pad + i * (cell_w + gap)
        rect = (cx, bar_y, cx + cell_w, bar_y + bar_h)
        if i < min(used, SPF_LOOKUP_LIMIT):
            _round_rect(d, rect, 2 * ss, fill=pal["red"])
        elif i >= SPF_LOOKUP_LIMIT:
            _round_rect(d, rect, 2 * ss, fill=pal["red_wash"],
                        outline=pal["red"], width=max(1, ss))
            step = 4 * ss
            off = 0
            while off < cell_w + bar_h:
                ax, ay = cx + off, bar_y + bar_h
                bx, by = cx + off - bar_h, bar_y
                if ax > cx + cell_w:
                    ay = bar_y + bar_h - (ax - (cx + cell_w))
                    ax = cx + cell_w
                if bx < cx:
                    by = bar_y + (cx - bx)
                    bx = cx
                if ay > by:
                    d.line([(ax, ay), (bx, by)], fill=pal["red"], width=ss)
                off += step
        else:
            _round_rect(d, rect, 2 * ss, fill=pal["sunken"],
                        outline=pal["rule_strong"], width=max(1, ss))
        if i < used:
            _text(d, (cx + cell_w / 2, bar_y + bar_h + 4 * ss), str(i + 1),
                  f_num, pal["red"] if i >= SPF_LOOKUP_LIMIT else pal["muted"],
                  anchor="ma")

    # the hard limit, drawn as a line because that is what it is
    line_x = x0 + pad + SPF_LOOKUP_LIMIT * (cell_w + gap) - gap / 2
    d.line([(line_x, bar_y - 6 * ss), (line_x, bar_y + bar_h + 6 * ss)],
           fill=pal["red"], width=2 * ss)
    _text(d, (line_x - 4 * ss, bar_y - 20 * ss), f"LIMIT {SPF_LOOKUP_LIMIT}",
          f_cap, pal["red"], anchor="ra")

    # a few of the terms that spent the budget
    ly = bar_y + bar_h + 22 * ss
    col_w = inner_w / 2
    shown = motif["labels"][:legend_rows * 2]
    for i, lab in enumerate(shown):
        col, row = divmod(i, legend_rows)
        lx = x0 + pad + col * col_w
        over = i >= SPF_LOOKUP_LIMIT
        colour = pal["red"] if over else pal["faint"]
        _text(d, (lx + 14 * ss, ly + row * 17 * ss), f"{i + 1}", f_mono, colour,
              anchor="ra")
        _text(d, (lx + 22 * ss, ly + row * 17 * ss), lab, f_mono,
              pal["red"] if over else pal["muted"])
    rows = min(legend_rows, max(1, (len(shown) + 1) // 2))

    cy = ly + rows * 17 * ss + 10 * ss
    for line in _wrap(d, motif["caveat"], f_note, inner_w)[:2]:
        _text(d, (x0 + pad, cy), line, f_note, pal["red"])
        cy += 19 * ss

    # the three stances, as chips
    cy += 8 * ss
    chip_gap = 10 * ss
    chip_w = (inner_w - chip_gap * 2) / 3
    chip_h = 52 * ss
    for i, (name, word, note) in enumerate(motif["pillars"]):
        cx = x0 + pad + i * (chip_w + chip_gap)
        fg, bg = _STANCE_COLOUR.get(word, ("muted", "sunken"))
        _round_rect(d, (cx, cy, cx + chip_w, cy + chip_h), 6 * ss,
                    fill=pal[bg], outline=pal["rule"], width=max(1, ss))
        _round_rect(d, (cx, cy, cx + 4 * ss, cy + chip_h), 2 * ss, fill=pal[fg])
        _text(d, (cx + 14 * ss, cy + 7 * ss), name, f_name, pal["ink"])
        _text(d, (cx + 14 * ss, cy + 28 * ss), word, f_word, pal[fg], ls=ss)
    return cy + chip_h


# --- social card --------------------------------------------------------------

def render_card(path: str, dark: bool = False) -> None:
    W, H, SS, SAFE = 1280, 640, 2, 80
    pal = _pal(dark)
    motif = _motif()
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)
    box = SafeBox(W * SS, H * SS, SAFE * SS)
    margin = 96 * SS  # author at 96, assert at 80

    lx = margin
    f_mark = font(SERIF, 86 * SS)
    wmw = _text(d, (lx, 142 * SS), "EDICT", f_mark, pal["ink"])
    box.add("wordmark", (lx, 142 * SS, lx + wmw, 142 * SS + 86 * SS))
    d.line([(lx, 250 * SS), (lx + wmw, 250 * SS)], fill=pal["brass"],
           width=3 * SS)

    f_tag = font(SANS, 19 * SS)
    tgw = _text(d, (lx, 270 * SS), "WHAT YOUR DOMAIN DECLARES", f_tag,
                pal["faint"], ls=3 * SS)
    box.add("tagline", (lx, 270 * SS, lx + tgw, 270 * SS + 24 * SS))

    f_pitch = font(SERIF, 36 * SS)
    d.text((lx, 322 * SS), "Grade the rules", font=f_pitch, fill=pal["ink"])
    d.text((lx, 366 * SS), "you publish.", font=f_pitch, fill=pal["ink"])
    box.add("pitch", (lx, 322 * SS, lx + 320 * SS, 366 * SS + 40 * SS))

    f_sub = font(SANS, 17 * SS)
    subs = ["SPF, DMARC, DKIM, MX and CAA, read offline —",
            "with the lookup budget counted and the DKIM",
            "key size read from the key itself."]
    for i, line in enumerate(subs):
        d.text((lx, (430 + i * 25) * SS), line, font=f_sub, fill=pal["muted"])
    box.add("sub", (lx, 430 * SS, lx + 420 * SS, (430 + 3 * 25) * SS))

    f_url = font(MONO, 16 * SS)
    urlw = _text(d, (lx, 520 * SS), "github.com/at0m-b0mb/Edict", f_url,
                 pal["brass"])
    box.add("url", (lx, 520 * SS, lx + urlw, 520 * SS + 20 * SS))

    # The panel is sized to the motif, not the canvas: a tall box with the
    # gauge floating in the top of it reads as a mistake.
    panel = (612 * SS, 172 * SS, (W - 96) * SS, 468 * SS)
    _draw_gauge(d, panel, pal, SS, motif, legend_rows=4)
    box.add("gauge", panel)

    box.check()
    im = im.resize((W, H), Image.LANCZOS)
    im.save(path)
    _assert_safe_border(path, SAFE, pal["bg"])
    print(f"wrote {os.path.relpath(path, ROOT)}")


def _assert_safe_border(path: str, margin: int, bg_hex: str) -> None:
    """Measure the rendered PNG: no non-background ink inside the border."""
    im = Image.open(path).convert("RGB")
    W, H = im.size
    px = im.load()
    bg = tuple(int(bg_hex.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))

    def near(c):
        return all(abs(c[i] - bg[i]) <= 6 for i in range(3))

    pts = [(x, y) for y in range(0, H, 2) for x in range(0, W, 2)
           if not near(px[x, y])]
    if not pts:
        return
    l = min(p[0] for p in pts)
    r = max(p[0] for p in pts)
    t = min(p[1] for p in pts)
    b = max(p[1] for p in pts)
    m = min(l, W - 1 - r, t, H - 1 - b)
    assert m >= margin, f"content reaches {m}px from the edge (need {margin})"
    print(f"  measured card margins: L{l} R{W-1-r} T{t} B{H-1-b} — ok")


# --- banner -------------------------------------------------------------------

def render_banner(path: str, dark: bool = False) -> None:
    W, H, SS = 1280, 400, 2
    pal = _pal(dark)
    motif = _motif()
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)

    # a gold band that may bleed to the right edge
    d.rectangle([(W - 150) * SS, 0, W * SS, H * SS], fill=pal["brass"])
    d.rectangle([(W - 156) * SS, 0, (W - 150) * SS, H * SS], fill=pal["shine"])

    lx = 80 * SS
    f_mark = font(SERIF, 96 * SS)
    _text(d, (lx, 118 * SS), "EDICT", f_mark, pal["ink"])
    d.line([(lx, 238 * SS), (lx + 268 * SS, 238 * SS)], fill=pal["brass"],
           width=3 * SS)
    f_tag = font(SANS, 20 * SS)
    _text(d, (lx, 258 * SS), "WHAT YOUR DOMAIN DECLARES", f_tag, pal["faint"],
          ls=4 * SS)
    f_sub = font(SANS, 20 * SS)
    d.text((lx, 300 * SS), "An offline grader for the mail policy",
           font=f_sub, fill=pal["muted"])
    d.text((lx, 328 * SS), "a domain publishes about itself.",
           font=f_sub, fill=pal["muted"])

    panel = (560 * SS, 48 * SS, (W - 172) * SS, (H - 48) * SS)
    _draw_gauge(d, panel, pal, SS, motif, legend_rows=3)

    im.save(path)   # authored at 2x: the file is 2560x800
    print(f"wrote {os.path.relpath(path, ROOT)}  ({im.size[0]}x{im.size[1]})")


# --- contact sheet ------------------------------------------------------------

def render_contact_sheet(path: str, shots: list[str], dark: bool = False) -> None:
    pal = _pal(dark)
    loaded = []
    for name in shots:
        p = os.path.join(IMG, name)
        if os.path.exists(p):
            loaded.append(Image.open(p).convert("RGB"))
    if not loaded:
        print(f"  (no screenshots for {os.path.basename(path)} — run capture first)")
        return

    gap, pad = 28, 40
    scale_w = 560
    thumbs = []
    for im in loaded:
        h = int(im.height * scale_w / im.width)
        thumbs.append(im.resize((scale_w, h), Image.LANCZOS))
    sheet_w = pad * 2 + scale_w * len(thumbs) + gap * (len(thumbs) - 1)
    sheet_h = pad * 2 + max(t.height for t in thumbs)
    sheet = Image.new("RGB", (sheet_w, sheet_h), pal["bg"])
    d = ImageDraw.Draw(sheet)
    x = pad
    for t in thumbs:
        sheet.paste(t, (x, pad))
        d.rectangle([x, pad, x + t.width - 1, pad + t.height - 1],
                    outline=pal["rule"], width=1)
        x += t.width + gap
    sheet.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({sheet_w}x{sheet_h})")


def main() -> int:
    os.makedirs(IMG, exist_ok=True)
    print("social card:")
    render_card(os.path.join(IMG, "social-preview.png"), dark=False)
    print("banner (light + dark):")
    render_banner(os.path.join(IMG, "banner.png"), dark=False)
    render_banner(os.path.join(IMG, "banner-dark.png"), dark=True)
    print("contact sheet (light + dark):")
    render_contact_sheet(os.path.join(IMG, "screens.png"),
                         ["shot-wide-open-light.png",
                          "shot-hardened-light.png"], dark=False)
    render_contact_sheet(os.path.join(IMG, "screens-dark.png"),
                         ["shot-wide-open-dark.png",
                          "shot-hardened-dark.png"], dark=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
The brand kit for the seven readers.

One file draws every piece of repository art for every tool, so the family reads
as a family: the same paper, the same two golds, the same Didone wordmark, the
same safe border. What changes per tool is a mark, a line of copy, and one panel
showing that tool's own signature element with its own real data.

    python3 brandkit.py              # every tool
    python3 brandkit.py herald       # one

Produces, per tool, into images/:
    mark.png              512x512 master, plus 180 / 64 downscales
    mark-32.png mark-16.png   drawn natively at size, not resampled
    social-preview.png    1280x640, inside GitHub's 80px safe border (asserted)
    banner.png / -dark    2560x800 light+dark pair for the README <picture>
    screens.png / -dark   contact sheet of the real off-screen captures

Everything is deterministic: no clock is read, so re-running produces identical
bytes and a repository does not churn.
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

SERIF = "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc"
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"

# ---------------------------------------------------------------- palette ----
# Straight from the shared ui/theme.py. Light first, dark second.
PAPER, SURFACE = "#F3F1EC", "#FFFFFF"
INK, MUTED, FAINT = "#1B1813", "#575144", "#6B6554"
RULE, RULE_STRONG = "#DCD6C9", "#C4BCAA"
BRASS, SHINE = "#7A5D18", "#C39B24"
GOOD, GOOD_WASH = "#2C6249", "#E9F3ED"
WARN, WARN_WASH = "#8A5410", "#FAF0DF"
ALERT, ALERT_WASH = "#8C1F16", "#FBE9E7"

D_BG, D_SURFACE = "#000000", "#131312"
D_INK, D_MUTED, D_FAINT = "#F3F0E9", "#A29C91", "#8C877C"
D_RULE, D_RULE_STRONG = "#2B2B28", "#3D3C38"
D_BRASS, D_SHINE = "#D9B75C", "#F1C84B"
D_GOOD, D_GOOD_WASH = "#67BE94", "#0D1F16"
D_WARN, D_WARN_WASH = "#DDA356", "#251A0B"
D_ALERT, D_ALERT_WASH = "#EE8B82", "#2A100E"


def pal(dark: bool) -> dict:
    if dark:
        return dict(bg=D_BG, surface=D_SURFACE, ink=D_INK, muted=D_MUTED,
                    faint=D_FAINT, rule=D_RULE, rule_strong=D_RULE_STRONG,
                    brass=D_BRASS, shine=D_SHINE, good=D_GOOD,
                    good_wash=D_GOOD_WASH, warn=D_WARN, warn_wash=D_WARN_WASH,
                    alert=D_ALERT, alert_wash=D_ALERT_WASH)
    return dict(bg=PAPER, surface=SURFACE, ink=INK, muted=MUTED, faint=FAINT,
                rule=RULE, rule_strong=RULE_STRONG, brass=BRASS, shine=SHINE,
                good=GOOD, good_wash=GOOD_WASH, warn=WARN, warn_wash=WARN_WASH,
                alert=ALERT, alert_wash=ALERT_WASH)


def font(path: str, size: int, index: int = 0) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size, index=index)


def text(draw, xy, s, fnt, fill, ls=0, anchor="la") -> float:
    """Draw a string, optionally letter-spaced; return the width drawn."""
    if ls == 0:
        draw.text(xy, s, font=fnt, fill=fill, anchor=anchor)
        l, _, r, _ = draw.textbbox(xy, s, font=fnt, anchor=anchor)
        return r - l
    x, y = xy
    for ch in s:
        draw.text((x, y), ch, font=fnt, fill=fill, anchor="la")
        x += draw.textbbox((0, 0), ch, font=fnt)[2] + ls
    return x - xy[0] - ls


class SafeBox:
    """Registers every meaningful rectangle; refuses a card that crops badly.

    Background art is never registered, so it stays free to bleed. Only the
    things a crop must not eat are handed to add().
    """

    def __init__(self, w: int, h: int, safe: int):
        self.w, self.h, self.safe, self.rects = w, h, safe, []

    def add(self, name: str, box) -> None:
        self.rects.append((name, tuple(int(round(v)) for v in box)))

    def check(self) -> None:
        worst = None
        for name, (l, t, r, b) in self.rects:
            m = min(l, t, self.w - r, self.h - b)
            if worst is None or m < worst[0]:
                worst = (m, name, (l, t, r, b))
        if worst:
            m, name, box = worst
            assert m >= self.safe, (
                f"{name} at {box} leaves a {m}px margin on {self.w}x{self.h}; "
                f"the safe border needs {self.safe}px.")


# ------------------------------------------------------------------ marks ----
# Each glyph is plain geometry on a brass tile: a stamp, not an illustration.
# They are drawn from a 0..1 coordinate space so the same code serves 512px and
# 16px, with stroke weights that thicken as the tile shrinks.

def _g(frac: float, size: int) -> int:
    return int(round(frac * size))


def draw_glyph(d: ImageDraw.ImageDraw, kind: str, size: int, fg: str) -> None:
    """Draw one tool's glyph, centred, sized to the tile."""
    s = size
    w = max(2, _g(0.055, s))        # stroke weight
    cx = s / 2

    if kind == "spine":             # Herald: the itinerary — nodes on a spine
        x = _g(0.38, s)
        ys = [_g(0.26, s), _g(0.5, s), _g(0.74, s)]
        d.line([(x, ys[0]), (x, ys[-1])], fill=fg, width=w)
        r = _g(0.075, s)
        for i, y in enumerate(ys):
            if i == 0:
                d.ellipse([x - r, y - r, x + r, y + r], outline=fg, width=w)
            else:
                d.ellipse([x - r, y - r, x + r, y + r], fill=fg)
            d.line([(x + _g(0.14, s), y), (_g(0.74, s), y)], fill=fg, width=w)

    elif kind == "ring":            # Signet: the band, and the stone above it
        cy = _g(0.58, s)
        r = _g(0.235, s)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=fg,
                  width=max(2, _g(0.09, s)))
        # the stone clears the band rather than merging into it, or the whole
        # thing reads as one blob once it is 16px tall
        st = _g(0.095, s)
        sy = _g(0.205, s)
        d.polygon([(cx, sy - st), (cx + st, sy), (cx, sy + st), (cx - st, sy)],
                  fill=fg)

    elif kind == "beam":            # Lintel: a beam carried on two posts
        d.rectangle([_g(0.18, s), _g(0.28, s), _g(0.82, s), _g(0.41, s)], fill=fg)
        d.rectangle([_g(0.26, s), _g(0.41, s), _g(0.26, s) + w * 2, _g(0.80, s)], fill=fg)
        d.rectangle([_g(0.74, s) - w * 2, _g(0.41, s), _g(0.74, s), _g(0.80, s)], fill=fg)

    elif kind == "rungs":           # Attest: the chain ladder
        x0 = _g(0.28, s)
        d.rectangle([x0, _g(0.22, s), x0 + w, _g(0.78, s)], fill=fg)
        for y in (_g(0.26, s), _g(0.46, s), _g(0.66, s)):
            d.rectangle([x0, y, _g(0.76, s), y + max(2, _g(0.085, s))], fill=fg)

    elif kind == "gauge":           # Edict: the lookup budget, mostly spent
        # Four chunky segments, not ten thin ones: at 16px a fine comb is a
        # smear, and the point is only "a budget, partly used".
        seg_w, gap = _g(0.15, s), _g(0.055, s)
        h = _g(0.22, s)
        x, y = _g(0.1175, s), _g(0.39, s)
        for i in range(4):
            box_i = [x, y, x + seg_w, y + h]
            if i < 3:
                d.rectangle(box_i, fill=fg)
            else:
                d.rectangle(box_i, outline=fg, width=max(2, _g(0.045, s)))
            x += seg_w + gap

    elif kind == "keyhole":         # Vigil: the secret, found
        r = _g(0.17, s)
        cy = _g(0.40, s)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fg)
        d.polygon([(cx - _g(0.105, s), _g(0.78, s)),
                   (cx - _g(0.055, s), cy + _g(0.04, s)),
                   (cx + _g(0.055, s), cy + _g(0.04, s)),
                   (cx + _g(0.105, s), _g(0.78, s))], fill=fg)

    elif kind == "prompt":          # Caveat: the shell prompt and its cursor
        th = max(3, _g(0.085, s))
        d.line([(_g(0.24, s), _g(0.32, s)), (_g(0.46, s), _g(0.50, s))],
               fill=fg, width=th)
        d.line([(_g(0.46, s), _g(0.50, s)), (_g(0.24, s), _g(0.68, s))],
               fill=fg, width=th)
        d.rectangle([_g(0.54, s), _g(0.62, s), _g(0.78, s), _g(0.62, s) + th], fill=fg)
    else:
        raise ValueError(f"unknown glyph {kind}")


def render_mark(path: str, glyph: str, size: int, dark: bool = False) -> None:
    """A brass tile with the tool's glyph punched out of it."""
    ss = 4 if size >= 64 else 8          # supersample; tiny marks need more
    s = size * ss
    p = pal(dark)
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    radius = int(s * 0.22)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=p["brass"])
    # a hairline of the brighter gold, so the tile has an edge at small sizes
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius,
                        outline=p["shine"], width=max(1, int(s * 0.012)))
    draw_glyph(d, glyph, s, p["bg"] if dark else PAPER)
    im = im.resize((size, size), Image.LANCZOS)
    im.save(path)


# ----------------------------------------------------------------- panels ----
# One per tool: a small, honest picture of that tool's signature element, drawn
# with values taken from its own sample set.

def panel_itinerary(d, box, p, ss):
    x0, y0, x1, y1 = box
    rows = [("app1.internal", "10.0.3.14  ·  internal", "ORIGIN", False, ""),
            ("relay.shop-updates.com", "198.51.100.10  ·  external", "", True, "+1s"),
            ("mail.shop-updates.com", "198.51.100.24  ·  external", "DELIVERED", True, "+4s")]
    pad = 26 * ss
    nx = x0 + pad + 10 * ss
    top = y0 + 56 * ss
    rh = (y1 - top - pad) / len(rows)
    cys = [top + rh * (i + 0.5) for i in range(len(rows))]
    d.line([(nx, cys[0]), (nx, cys[-1])], fill=p["rule_strong"], width=2 * ss)
    r = 7 * ss
    for i, (host, meta, mark, solid, delay) in enumerate(rows):
        cy = cys[i]
        col = p["brass"] if solid else p["muted"]
        if solid:
            d.ellipse([nx - r, cy - r, nx + r, cy + r], fill=col)
        else:
            d.ellipse([nx - r, cy - r, nx + r, cy + r], outline=col, width=2 * ss)
        text(d, (nx + 22 * ss, cy - 20 * ss), host, font(SANS, 19 * ss), p["ink"])
        text(d, (nx + 22 * ss, cy + 4 * ss), meta, font(MONO, 13 * ss), p["muted"])
        if mark:
            text(d, (x1 - pad, cy - 20 * ss), mark, font(SANS, 11 * ss), col, anchor="ra")
        if delay:
            text(d, (nx + 12 * ss, cy - rh / 2 - 6 * ss), delay, font(MONO, 13 * ss),
                 p["faint"])


def panel_validity(d, box, p, ss):
    x0, y0, x1, y1 = box
    pad = 30 * ss
    ay = int((y0 + y1) / 2) + 10 * ss
    ax0, ax1 = x0 + pad + 10 * ss, x1 - pad - 10 * ss
    xi, xn, xe = ax0, ax0 + int((ax1 - ax0) * 0.34), ax1
    d.rectangle([xi, ay - 9 * ss, xe, ay + 9 * ss], fill=p["good_wash"])
    d.line([(ax0, ay), (ax1, ay)], fill=p["rule_strong"], width=2 * ss)
    for x, lab, when, col in ((xi, "ISSUED", "12:00", p["brass"]),
                              (xn, "NOW", "12:05", p["good"]),
                              (xe, "EXPIRES", "12:15", p["brass"])):
        d.line([(x, ay - 12 * ss), (x, ay + 12 * ss)], fill=col, width=2 * ss)
        if lab == "NOW":
            d.ellipse([x - 5 * ss, ay - 5 * ss, x + 5 * ss, ay + 5 * ss], fill=col)
        text(d, (x, ay - 34 * ss), lab, font(SANS, 12 * ss), col, anchor="ma")
        text(d, (x, ay + 20 * ss), when, font(MONO, 12 * ss), p["muted"], anchor="ma")


def panel_coverage(d, box, p, ss):
    tiles = [("HSTS", "IN PLACE", "good"), ("Content Security Policy", "WEAK", "warn"),
             ("MIME sniffing", "IN PLACE", "good"), ("Clickjacking", "MISSING", "alert"),
             ("Referrer policy", "IN PLACE", "good"), ("Cookie flags", "WEAK", "warn")]
    _tilegrid(d, box, p, ss, tiles)


def panel_rungs(d, box, p, ss):
    x0, y0, x1, y1 = box
    rows = [("GlobalSign Root CA", "self-signed  ·  RSA-4096", "ROOT", "brass"),
            ("Mallard Issuing CA", "RSA-3072  ·  SHA-256", "", "brass"),
            ("nas01.mallard.example", "RSA-1024  ·  SHA-1", "LEAF", "alert")]
    pad = 26 * ss
    nx = x0 + pad + 10 * ss
    top = y0 + 56 * ss
    rh = (y1 - top - pad) / len(rows)
    cys = [top + rh * (i + 0.5) for i in range(len(rows))]
    d.line([(nx, cys[0]), (nx, cys[-1])], fill=p["rule_strong"], width=2 * ss)
    for i, (subj, meta, mark, tone) in enumerate(rows):
        cy = cys[i]
        col = p[tone]
        d.rectangle([nx - 3 * ss, cy - 20 * ss, nx + 3 * ss, cy + 16 * ss], fill=col)
        text(d, (nx + 22 * ss, cy - 20 * ss), subj, font(SANS, 18 * ss), p["ink"])
        text(d, (nx + 22 * ss, cy + 4 * ss), meta, font(MONO, 13 * ss), col)
        if mark:
            text(d, (x1 - pad, cy - 20 * ss), mark, font(SANS, 11 * ss), col, anchor="ra")


def panel_budget(d, box, p, ss):
    x0, y0, x1, y1 = box
    pad = 30 * ss
    y = int((y0 + y1) / 2) - 8 * ss
    h = 26 * ss
    n = 10
    gap = 6 * ss
    w = (x1 - pad - (x0 + pad) - gap * (n - 1)) / n
    x = x0 + pad
    for i in range(n):
        box_i = [x, y, x + w, y + h]
        if i < 7:
            d.rectangle(box_i, fill=p["brass"])
        else:
            d.rectangle(box_i, outline=p["rule_strong"], width=2 * ss)
        x += w + gap
    d.line([(x - gap, y - 10 * ss), (x - gap, y + h + 10 * ss)], fill=p["alert"],
           width=3 * ss)
    text(d, (x0 + pad, y + h + 22 * ss), "7 of 10 DNS lookups used — at least",
         font(SANS, 15 * ss), p["muted"])


def panel_exposure(d, box, p, ss):
    x0, y0, x1, y1 = box
    pad = 30 * ss
    bands = ["", "", "alert", "", "", "warn", "warn", "", "", "", "alert", "",
             "", "", "warn", "", "", "", "", ""]
    bw = (x1 - pad - (x0 + pad)) / len(bands)
    h = (y1 - y0) * 0.42
    top = (y0 + y1) / 2 - h / 2 + 14 * ss      # centred under the panel title
    for i, tone in enumerate(bands):
        x = x0 + pad + i * bw
        col = p[tone] if tone else p["rule"]
        d.rectangle([x, top, x + bw - 2 * ss, top + h], fill=col)
    text(d, (x0 + pad, top + h + 20 * ss), "4 findings across 20 lines",
         font(SANS, 15 * ss), p["muted"])


def panel_pipeline(d, box, p, ss):
    x0, y0, x1, y1 = box
    pad = 30 * ss
    cy = int((y0 + y1) / 2) + 6 * ss
    bw, bh = (x1 - x0 - pad * 2 - 70 * ss) / 2, 92 * ss
    for i, (name, role, tone, badge) in enumerate(
            [("curl", "download a URL", "alert", ""),
             ("bash", "run shell commands", "alert", "ROOT")]):
        bx = x0 + pad + i * (bw + 70 * ss)
        d.rounded_rectangle([bx, cy - bh / 2, bx + bw, cy + bh / 2], radius=8 * ss,
                            fill=p[tone + "_wash"], outline=p[tone], width=2 * ss)
        text(d, (bx + 16 * ss, cy - bh / 2 + 14 * ss), f"STAGE {i + 1}",
             font(SANS, 11 * ss), p["faint"], ls=ss)
        text(d, (bx + 16 * ss, cy - 10 * ss), name, font(SANS, 22 * ss), p["ink"])
        text(d, (bx + 16 * ss, cy + 22 * ss), role, font(SANS, 14 * ss), p["muted"])
        if badge:
            text(d, (bx + bw - 16 * ss, cy - bh / 2 + 14 * ss), badge,
                 font(SANS, 11 * ss), p[tone], anchor="ra", ls=ss)
        if i == 0:
            ax0, ax1 = bx + bw + 14 * ss, bx + bw + 56 * ss
            d.line([(ax0, cy), (ax1, cy)], fill=p["rule_strong"], width=2 * ss)
            d.polygon([(ax1, cy), (ax1 - 9 * ss, cy - 6 * ss),
                       (ax1 - 9 * ss, cy + 6 * ss)], fill=p["rule_strong"])
            text(d, ((ax0 + ax1) / 2, cy - 24 * ss), "STDOUT", font(SANS, 11 * ss),
                 p["faint"], anchor="ma")


def _tilegrid(d, box, p, ss, tiles, cols=2):
    x0, y0, x1, y1 = box
    pad = 24 * ss
    gx0, gy0 = x0 + pad, y0 + 54 * ss
    gw = (x1 - pad) - gx0
    gap = 10 * ss
    tw = (gw - gap * (cols - 1)) / cols
    rows = (len(tiles) + cols - 1) // cols
    th = ((y1 - pad) - gy0 - gap * (rows - 1)) / rows
    for i, (name, state, tone) in enumerate(tiles):
        r, c = divmod(i, cols)
        x, y = gx0 + c * (tw + gap), gy0 + r * (th + gap)
        d.rounded_rectangle([x, y, x + tw, y + th], radius=6 * ss,
                            fill=p[tone + "_wash"], outline=p["rule"], width=max(1, ss))
        d.rounded_rectangle([x, y, x + 4 * ss, y + th], radius=2 * ss, fill=p[tone])
        text(d, (x + 16 * ss, y + th / 2 - 16 * ss), name, font(SANS, 16 * ss), p["ink"])
        text(d, (x + 16 * ss, y + th / 2 + 4 * ss), state, font(SANS, 11 * ss),
             p[tone], ls=ss)


PANELS = {"itinerary": panel_itinerary, "validity": panel_validity,
          "coverage": panel_coverage, "rungs": panel_rungs,
          "budget": panel_budget, "exposure": panel_exposure,
          "pipeline": panel_pipeline}


# ------------------------------------------------------------------ brand ----
BRAND = {
    "herald": dict(
        dir="Herald", word="HERALD", tag="READ THE HEADERS",
        repo="Herald-Email-Headers", glyph="spine", panel="itinerary",
        panel_title="THE PATH IT TOOK",
        pitch=["See where an email", "really came from."],
        sub=["Reconstructs the route, reads SPF / DKIM / DMARC,",
             "grades A+ to F — and never calls a message safe."],
        shots=["shot-spoofed-invoice", "shot-clean-newsletter"]),
    "signet": dict(
        dir="Signet", word="SIGNET", tag="READ THE SEAL",
        repo="Signet-JWT-Inspector", glyph="ring", panel="validity",
        panel_title="THE VALIDITY WINDOW",
        pitch=["Decode a token.", "See what it reveals."],
        sub=["A JWT is not encrypted. Signet reads every claim,",
             "draws its lifetime, and grades what it exposes."],
        shots=["shot-secret-in-claims", "shot-good-access-token"]),
    "lintel": dict(
        dir="Lintel", word="LINTEL", tag="MIND THE HEADERS",
        repo="Lintel-HTTP-Headers", glyph="beam", panel="coverage",
        panel_title="PROTECTION COVERAGE",
        pitch=["Grade a site's", "security headers."],
        sub=["HSTS, CSP, cookies, clickjacking — which",
             "protections hold, and which are missing."],
        shots=["shot-moderate", "shot-hardened"]),
    "attest": dict(
        dir="Attest", word="ATTEST", tag="READ THE CERTIFICATE",
        repo="Attest-X509", glyph="rungs", panel="rungs",
        panel_title="THE CHAIN, AS IT WAS GIVEN",
        pitch=["Read a certificate", "before you trust it."],
        sub=["Parses the chain, grades the key, the hash and the",
             "dates — and verifies no signature, which it says."],
        shots=["shot-self-signed-sha1", "shot-modern-chain"]),
    "edict": dict(
        dir="Edict", word="EDICT", tag="WHAT YOUR DOMAIN DECLARES",
        repo="Edict-Email-Policy", glyph="gauge", panel="budget",
        panel_title="THE SPF LOOKUP BUDGET",
        pitch=["Who is allowed", "to send as you?"],
        sub=["Grades the SPF, DKIM, DMARC and CAA your domain",
             "publishes — and resolves no DNS to do it."],
        shots=["shot-monitoring-only", "shot-hardened"]),
    "vigil": dict(
        dir="Vigil", word="VIGIL", tag="FIND IT BEFORE THEY DO",
        repo="Vigil-Secret-Scanner", glyph="keyhole", panel="exposure",
        panel_title="THE EXPOSURE MAP",
        pitch=["Find the secret", "before you commit it."],
        sub=["Scans a config, a log or a file for credentials —",
             "and shows a redacted preview, never the secret."],
        shots=["shot-leaky", "shot-tidy-config"]),
    "caveat": dict(
        dir="Caveat", word="CAVEAT", tag="READ BEFORE YOU RUN",
        repo="Caveat-Shell-Reader", glyph="prompt", panel="pipeline",
        panel_title="THE PIPELINE",
        pitch=["Read the command", "before you run it."],
        sub=["Explains every stage in plain English and flags what",
             "it will do — and never runs, fetches or simulates."],
        shots=["shot-install-script", "shot-benign-pipeline"]),
}


def tool_root(cfg: dict) -> str:
    """Where this tool's repository lives.

    The same file serves two homes: beside all seven projects while they are
    developed together, and inside a single published repository as
    ``tools/brandkit.py``. Resolve whichever applies instead of hard-coding a
    layout, so a cloned repo can rebuild its own art unchanged.
    """
    side_by_side = os.path.join(HERE, cfg["dir"])
    if os.path.isdir(side_by_side):
        return side_by_side
    return os.path.dirname(HERE) if os.path.basename(HERE) == "tools" else HERE


def _panel(d, box, p, ss, cfg):
    d.rounded_rectangle(box, radius=10 * ss, fill=p["surface"], outline=p["rule"],
                        width=max(1, ss))
    text(d, (box[0] + 26 * ss, box[1] + 18 * ss), cfg["panel_title"],
         font(SANS, 13 * ss), p["faint"], ls=2 * ss)
    PANELS[cfg["panel"]](d, box, p, ss)


def render_card(path: str, cfg: dict, dark: bool = False) -> None:
    W, H, SS, SAFE = 1280, 640, 2, 80
    p = pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), p["bg"])
    d = ImageDraw.Draw(im)
    box = SafeBox(W * SS, H * SS, SAFE * SS)
    lx = 96 * SS

    # The column is authored to a 96px cushion, not to the 80px border, because
    # a glyph's bearing and a line's end cap both put ink outside their anchor.
    mark_px = 72
    mk = Image.open(os.path.join(tool_root(cfg), "images", "mark.png")).convert("RGBA")
    mk = mk.resize((mark_px * SS, mark_px * SS), Image.LANCZOS)
    im.paste(mk, (lx, 104 * SS), mk)
    box.add("mark", (lx, 104 * SS, lx + mark_px * SS, (104 + mark_px) * SS))

    ww = text(d, (lx, 196 * SS), cfg["word"], font(SERIF, 72 * SS), p["ink"])
    box.add("wordmark", (lx, 196 * SS, lx + ww, 268 * SS))
    d.line([(lx, 286 * SS), (lx + ww, 286 * SS)], fill=p["brass"], width=3 * SS)
    tw = text(d, (lx, 302 * SS), cfg["tag"], font(SANS, 18 * SS), p["faint"], ls=4 * SS)
    box.add("tagline", (lx, 302 * SS, lx + tw, 324 * SS))

    fp = font(SERIF, 33 * SS)
    for i, line in enumerate(cfg["pitch"]):
        d.text((lx, (352 + i * 42) * SS), line, font=fp, fill=p["ink"])
    box.add("pitch", (lx, 352 * SS, lx + 400 * SS, (352 + len(cfg["pitch"]) * 42) * SS))

    fs = font(SANS, 17 * SS)
    for i, line in enumerate(cfg["sub"]):
        d.text((lx, (456 + i * 25) * SS), line, font=fs, fill=p["muted"])
    box.add("sub", (lx, 456 * SS, lx + 430 * SS, (456 + len(cfg["sub"]) * 25) * SS))

    uw = text(d, (lx, 518 * SS), f"github.com/at0m-b0mb/{cfg['repo']}",
              font(MONO, 16 * SS), p["brass"])
    box.add("url", (lx, 518 * SS, lx + uw, 540 * SS))

    pnl = (690 * SS, 104 * SS, (W - 96) * SS, (H - 104) * SS)
    _panel(d, pnl, p, SS, cfg)
    box.add("panel", pnl)

    box.check()
    im.resize((W, H), Image.LANCZOS).save(path)


def render_banner(path: str, cfg: dict, dark: bool = False) -> None:
    W, H, SS = 1280, 400, 2
    p = pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), p["bg"])
    d = ImageDraw.Draw(im)
    d.rectangle([(W - 150) * SS, 0, W * SS, H * SS], fill=p["brass"])
    d.rectangle([(W - 156) * SS, 0, (W - 150) * SS, H * SS], fill=p["shine"])

    lx = 80 * SS
    mk = Image.open(os.path.join(tool_root(cfg), "images", "mark.png")).convert("RGBA")
    mk = mk.resize((64 * SS, 64 * SS), Image.LANCZOS)
    im.paste(mk, (lx, 86 * SS), mk)

    ww = text(d, (lx + 84 * SS, 92 * SS), cfg["word"], font(SERIF, 62 * SS), p["ink"])
    d.line([(lx, 186 * SS), (lx + 84 * SS + ww, 186 * SS)], fill=p["brass"], width=3 * SS)
    text(d, (lx, 204 * SS), cfg["tag"], font(SANS, 19 * SS), p["faint"], ls=5 * SS)
    fs = font(SANS, 20 * SS)
    for i, line in enumerate(cfg["sub"]):
        d.text((lx, (252 + i * 30) * SS), line, font=fs, fill=p["muted"])

    pnl = (740 * SS, 54 * SS, (W - 176) * SS, (H - 54) * SS)
    _panel(d, pnl, p, SS, cfg)
    im.save(path)


def render_sheet(path: str, cfg: dict, images_dir: str, dark: bool = False) -> None:
    p = pal(dark)
    suffix = "-dark" if dark else "-light"
    files = [os.path.join(images_dir, n + suffix + ".png") for n in cfg["shots"]]
    loaded = [Image.open(f).convert("RGB") for f in files if os.path.exists(f)]
    if not loaded:
        print(f"    (no captures for {cfg['word']} sheet)")
        return
    gap, pad, sw = 28, 40, 560
    thumbs = [im.resize((sw, int(im.height * sw / im.width)), Image.LANCZOS)
              for im in loaded]
    W = pad * 2 + sw * len(thumbs) + gap * (len(thumbs) - 1)
    H = pad * 2 + max(t.height for t in thumbs)
    sheet = Image.new("RGB", (W, H), p["bg"])
    d = ImageDraw.Draw(sheet)
    x = pad
    for t in thumbs:
        sheet.paste(t, (x, pad))
        d.rectangle([x, pad, x + t.width - 1, pad + t.height - 1],
                    outline=p["rule"], width=1)
        x += t.width + gap
    sheet.save(path)


def build(key: str) -> None:
    cfg = BRAND[key]
    img = os.path.join(tool_root(cfg), "images")
    os.makedirs(img, exist_ok=True)
    print(f"  {cfg['word']}  ->  {cfg['dir']}/images/")

    render_mark(os.path.join(img, "mark.png"), cfg["glyph"], 512)
    for n in (180, 64):
        render_mark(os.path.join(img, f"mark-{n}.png"), cfg["glyph"], n)
    for n in (32, 16):                     # drawn natively, never resampled
        render_mark(os.path.join(img, f"mark-{n}.png"), cfg["glyph"], n)
    print("    marks 512 / 180 / 64 / 32 / 16")

    render_card(os.path.join(img, "social-preview.png"), cfg)
    print("    social-preview.png 1280x640 (safe border ok)")
    render_banner(os.path.join(img, "banner.png"), cfg, dark=False)
    render_banner(os.path.join(img, "banner-dark.png"), cfg, dark=True)
    print("    banner.png + banner-dark.png 2560x800")
    render_sheet(os.path.join(img, "screens.png"), cfg, img, dark=False)
    render_sheet(os.path.join(img, "screens-dark.png"), cfg, img, dark=True)
    print("    screens.png + screens-dark.png")


def main() -> int:
    here_name = os.path.basename(os.path.dirname(HERE)) if os.path.basename(HERE) == "tools" else None
    mine = [k for k, c in BRAND.items() if c["dir"] == here_name]
    keys = [a.lower() for a in sys.argv[1:] if not a.startswith("-")] or mine or list(BRAND)
    unknown = [k for k in keys if k not in BRAND]
    if unknown:
        print(f"unknown tool(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    print(f"\n  Brand kit — {len(keys)} tool(s)\n")
    for k in keys:
        build(k)
    print("\n  done\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

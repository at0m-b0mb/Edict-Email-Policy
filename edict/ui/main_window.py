"""
The window.

Left: the records a domain publishes — pasted, opened from a file, or loaded
from a sample. Right: the reading — a grade, the three things the domain
declares, the SPF lookup budget drawn as a budget, every mechanism in
evaluation order, the DMARC tags, each DKIM selector with the key size read out
of the key itself, the rest of the zone, and every finding in plain words.

The window holds the current zone and re-renders the whole right side on a
theme change, so the chips and the painted gauge always match the active
palette.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core import dkim as dkim_mod
from ..core.grade import analyze
from ..core.model import SPF_LOOKUP_LIMIT, Severity, Zone
from ..core.spf import modifier_note
from . import theme
from .budget import BudgetGauge, PolicyStrength
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}

_PLACEHOLDER = (
    "example.com.            300 IN TXT  \"v=spf1 mx include:_spf.provider.net -all\"\n"
    "_dmarc.example.com.     300 IN TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"\n"
    "sel._domainkey.example.com. IN TXT  \"v=DKIM1; k=rsa; p=MIIBIjANBgkq...\"\n"
    "example.com.            300 IN MX   10 mail.example.com.\n"
    "example.com.            300 IN CAA  0 issue \"letsencrypt.org\"\n"
    "\n"
    "Zone lines, dig output, or bare policy strings — mixed freely."
)


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._zone: Zone | None = None

        self.setWindowTitle("Edict")
        self.resize(1180, 780)
        self._build()
        self._apply_theme()

    # --- construction -------------------------------------------------------
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 6)
        split.setSizes([460, 700])
        host = QWidget()
        host.setObjectName("PageHost")
        host_lay = QVBoxLayout(host)
        host_lay.setContentsMargins(16, 12, 16, 16)
        host_lay.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)

        mark = QLabel("EDICT")
        mark.setObjectName("Wordmark")
        sub = QLabel("what your domain declares")
        sub.setObjectName("WordmarkSub")
        wm = QVBoxLayout()
        wm.setSpacing(0)
        wm.addWidget(mark)
        wm.addWidget(sub)
        lay.addLayout(wm)
        lay.addStretch(1)

        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(label("Paste the records you publish", "PageTitle"))
        lay.addWidget(label(
            "Your SPF, DMARC and DKIM records, your MX and your CAA — in "
            "whatever shape they arrived. Zone-file lines, dig output and bare "
            "policy strings can all go in together; Edict strips the quotes and "
            "joins split strings itself.", "PageIntro"))

        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText(_PLACEHOLDER)
        lay.addWidget(self.source, 1)

        row = QHBoxLayout()
        grade_btn = QPushButton("Grade")
        grade_btn.setObjectName("Primary")
        grade_btn.clicked.connect(self._on_grade)
        row.addWidget(grade_btn)

        open_btn = QPushButton("Open file…")
        open_btn.clicked.connect(self._on_open)
        row.addWidget(open_btn)

        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("Quiet")
        clear_btn.clicked.connect(self._on_clear)
        row.addWidget(clear_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(f for f in os.listdir(_SAMPLES_DIR)
                           if f.endswith(".dns"))
        except OSError:
            names = []
        if not names:
            act = QAction("(no samples found)", self)
            act.setEnabled(False)
            menu.addAction(act)
        for name in names:
            pretty = name[:-4].replace("-", " ").title()
            act = QAction(pretty, self)
            act.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(act)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._zone is not None:
            self._render_report(self._zone)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_grade(self) -> None:
        src = self.source.toPlainText()
        if not src.strip():
            self._set_placeholder("Paste some records, or load a sample, to begin.")
            return
        self._zone = analyze(src)
        self._render_report(self._zone)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a file of DNS records", "",
            "Records (*.dns *.txt *.zone);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        self._on_grade()

    def _load_sample(self, name: str) -> None:
        path = os.path.join(_SAMPLES_DIR, name)
        try:
            with open(path, encoding="utf-8") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_grade()

    def _on_clear(self) -> None:
        self.source.clear()
        self._zone = None
        self._set_placeholder()

    # --- report rendering ---------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing declared yet", "Figure"))
        lay.addWidget(label(
            text or "Herald judges a message that arrived. Edict judges the "
            "rules you publish about who may send as you — the SPF record's "
            "ending and what it costs a receiver to read, the DMARC policy and "
            "whether it covers your subdomains, the real size of your DKIM key. "
            "It resolves nothing and sends nothing, so it grades the policy you "
            "paste and says plainly what it cannot know.", "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render_report(self, zone: Zone) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(self._grade_card(zone))
        lay.addWidget(self._strength_card(zone))
        lay.addWidget(self._spf_card(zone))
        lay.addWidget(self._dmarc_card(zone))
        lay.addWidget(self._dkim_card(zone))
        lay.addWidget(self._zone_card(zone))
        lay.addWidget(self._findings_card(zone))
        if zone.notes:
            notes = Card("Read, but not graded", flat=True)
            for note in zone.notes:
                notes.add(label(note, muted=True))
            lay.addWidget(notes)
        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _grade_card(self, zone: Zone) -> QWidget:
        g = zone.grade
        card = Card()
        top = QHBoxLayout()

        letter = QLabel(g.letter)
        letter.setStyleSheet(
            f"{theme.font_css('grade')} "
            f"color: {theme.color(theme.grade_token(g.letter), self._mode)};")
        top.addWidget(letter)

        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(mini_label(f"POLICY GRADE  ·  SCORE {g.score}/100"))
        col.addWidget(label(g.headline, "PageTitle"))
        col.addStretch(1)
        top.addLayout(col, 1)
        card.add_layout(top)
        card.add(hrule())
        card.add(label(g.ceiling_note, "Faint"))
        return card

    def _strength_card(self, zone: Zone) -> QWidget:
        card = Card("What this domain declares")
        card.add(key_value("Domain", zone.domain
                           or "not named in the records given",
                           self._mode, mono=bool(zone.domain)))
        card.add(key_value("Records read", str(len(zone.records)), self._mode))
        strength = PolicyStrength()
        strength.set_data(zone.pillars, self._mode)
        card.add(strength)
        return card

    def _spf_card(self, zone: Zone) -> QWidget:
        policy = zone.primary_spf
        card = Card("SPF — who may send, and what it costs to find out")
        if policy is None:
            card.add(label(
                "No v=spf1 record was among the records given, so nothing "
                "published says which servers may send using this domain.",
                muted=True))
            gauge = BudgetGauge()
            gauge.set_data(None, self._mode, SPF_LOOKUP_LIMIT)
            card.add(gauge)
            return card

        if len(zone.spf) > 1:
            card.add(label(
                f"{len(zone.spf)} SPF records were given. A domain may publish "
                f"one; with more, a receiver uses none of them. The first is "
                f"shown.", muted=True))

        raw = QLabel(policy.raw)
        raw.setWordWrap(True)
        raw.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        raw.setStyleSheet(
            f"{theme.font_css('mono')} "
            f"color: {theme.color('ink', self._mode)}; "
            f"background: {theme.color('sunken', self._mode)}; "
            f"border: 1px solid {theme.color('rule', self._mode)}; "
            f"border-radius: 3px; padding: 8px;")
        card.add(raw)

        gauge = BudgetGauge()
        gauge.set_data(policy, self._mode, SPF_LOOKUP_LIMIT)
        card.add(gauge)

        card.add(hrule())
        card.add(mini_label("EVALUATION ORDER  ·  FIRST MATCH WINS"))
        for mech in policy.mechanisms:
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(theme.SPACE["snug"])
            term = QLabel(mech.rendered)
            term.setStyleSheet(
                f"{theme.font_css('mono')} "
                f"color: {theme.color(self._mech_token(mech), self._mode)};")
            lay.addWidget(term)
            lay.addStretch(1)
            lay.addWidget(label("1 lookup" if mech.cost else "free", "Faint"))
            card.add(row)
        # A modifier sits in the same table as the mechanisms and is annotated
        # the same way, because the gauge above and this table have to agree
        # about whether a redirect= spends one of the ten lookups.
        for name, value in policy.modifiers.items():
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(theme.SPACE["snug"])
            term = QLabel(f"{name}={value}")
            term.setStyleSheet(
                f"{theme.font_css('mono')} "
                f"color: {theme.color('ink_muted', self._mode)};")
            lay.addWidget(term)
            lay.addStretch(1)
            note = label(modifier_note(policy, name), "Faint")
            note.setWordWrap(False)   # one line, like the mechanism rows above
            lay.addWidget(note)
            card.add(row)
        return card

    def _mech_token(self, mech) -> str:
        from ..core.spf import covers_everything

        if covers_everything(mech):
            return "sev_alert"
        if mech.is_all:
            return {"-": "sev_good", "~": "sev_notice",
                    "?": "sev_warning", "+": "sev_alert"}[mech.qualifier]
        if mech.kind == "ptr":
            return "sev_notice"
        return "ink"

    def _dmarc_card(self, zone: Zone) -> QWidget:
        policy = zone.primary_dmarc
        card = Card("DMARC — what a receiver is asked to do")
        if policy is None:
            card.add(label(
                "No DMARC record was among the records given. Without one, SPF "
                "and DKIM are never tied to the From address a person reads, "
                "and no receiver is told what to do when they fail.",
                muted=True))
            return card

        where = {
            True: ("at _dmarc, where a receiver looks", None),
            False: (f"at {policy.owner.rstrip('.')} — not at _dmarc, "
                    f"where a receiver looks", "sev_alert"),
            None: ("location unknown — the line carried no owner name",
                   "sev_info"),
        }[policy.at_dmarc]
        card.add(key_value("Published", where[0], self._mode,
                           value_token=where[1]))

        card.add(key_value("Policy", policy.p or "—", self._mode,
                           value_token=self._policy_token(policy.p), mono=True))
        card.add(key_value("Subdomains",
                           policy.sp or f"{policy.p or '—'} (inherited)",
                           self._mode,
                           value_token=self._policy_token(policy.effective_sp),
                           mono=True))
        card.add(key_value("Applied to", f"{policy.pct}% of mail", self._mode,
                           value_token=None if policy.pct == 100
                           else "sev_notice"))
        card.add(key_value("Alignment",
                           f"SPF {policy.aspf}, DKIM {policy.adkim}",
                           self._mode, mono=True))
        card.add(key_value("Aggregate reports",
                           ", ".join(policy.rua) or "none requested",
                           self._mode,
                           value_token=None if policy.rua else "sev_notice",
                           mono=bool(policy.rua)))
        if policy.ruf:
            card.add(key_value("Failure reports", ", ".join(policy.ruf),
                               self._mode, mono=True))
        return card

    def _policy_token(self, name: str) -> str | None:
        return {"reject": "sev_good", "quarantine": "sev_notice",
                "none": "sev_warning"}.get((name or "").lower())

    def _dkim_card(self, zone: Zone) -> QWidget:
        card = Card("DKIM — the key, and how big it really is")
        if not zone.dkim:
            card.add(label(
                "No <selector>._domainkey record was among the records given, "
                "so Edict cannot tell whether this domain signs its mail — and "
                "it will not guess. Paste the selector your provider gave you "
                "to have the key size read.", muted=True))
            return card

        for i, key in enumerate(zone.dkim):
            if i:
                card.add(hrule())
            head = QHBoxLayout()
            head.setSpacing(theme.SPACE["snug"])
            name = QLabel(key.selector or "(unnamed selector)")
            name.setStyleSheet(
                f"{theme.font_css('mono')} "
                f"color: {theme.color('ink', self._mode)};")
            head.addWidget(name)
            head.addWidget(Chip(dkim_mod.size_verdict(key),
                                self._key_token(key), self._mode))
            if key.testing:
                head.addWidget(Chip("t=y", "sev_notice", self._mode))
            head.addStretch(1)
            card.add_layout(head)

            card.add(key_value("Algorithm", key.key_type, self._mode, mono=True))
            if key.bits:
                card.add(key_value("Key size", f"{key.bits} bits — read from "
                                               f"the key material itself",
                                   self._mode))
            if key.key_error:
                card.add(key_value("Key", key.key_error, self._mode,
                                   value_token="sev_warning"))
            if key.hashes:
                card.add(key_value("Hashes", "/".join(key.hashes), self._mode,
                                   mono=True))
            if key.flags:
                card.add(key_value("Flags", ":".join(key.flags), self._mode,
                                   mono=True))
        return card

    def _key_token(self, key) -> str:
        if key.revoked or key.key_error:
            return "sev_warning"
        if key.strong:
            return "sev_good"
        if key.bits and key.bits < dkim_mod.RSA_WEAK:
            return "sev_alert"
        return "sev_warning"

    def _zone_card(self, zone: Zone) -> QWidget:
        card = Card("The rest of the zone")
        if zone.mx:
            for mx in zone.mx:
                card.add(key_value(
                    "MX", f"{mx.preference}  {mx.host}"
                          + ("   (null MX — handles no mail)" if mx.is_null else ""),
                    self._mode, mono=True))
        else:
            card.add(key_value("MX", "none given — this domain may not receive "
                                     "mail", self._mode,
                               value_token="sev_notice"))
        if zone.caa:
            for caa in zone.caa:
                card.add(key_value("CAA", f"{caa.flags}  {caa.tag}  {caa.value}",
                                   self._mode, mono=True))
        else:
            card.add(key_value("CAA", "none given — any authority may issue a "
                                      "certificate for this name", self._mode,
                               value_token="sev_notice"))
        return card

    def _findings_card(self, zone: Zone) -> QWidget:
        card = Card(f"Findings ({len(zone.findings)})")
        for i, finding in enumerate(zone.findings):
            if i:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(finding.severity.value, _SEV_TOKEN[finding.severity],
                        self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)

            col = QVBoxLayout()
            col.setSpacing(2)
            head = QHBoxLayout()
            head.addWidget(label(finding.title, "body"))
            head.addStretch(1)
            if finding.points:
                head.addWidget(label(f"−{finding.points}", "Faint"))
            col.addLayout(head)
            col.addWidget(label(finding.detail, muted=True))
            row.addLayout(col, 1)
            card.add_layout(row)
        return card

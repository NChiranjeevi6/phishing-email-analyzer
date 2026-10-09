"""Parse .eml files into a flat structure. Nothing is executed, rendered or fetched."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path


@dataclass
class ParsedEmail:
    path: str
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    return_path: str = ""
    reply_to: str = ""
    date: str = ""
    message_id: str = ""
    auth_headers: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    html: str = ""
    text: str = ""
    attachments: list[tuple[str, str, bytes]] = field(default_factory=list)  # (filename, type, data)


class LinkParser(HTMLParser):
    """Collects (href, visible text) pairs and the visible text of the whole message."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.chunks: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.chunks.append(data)
        if self._href is not None:
            self._text.append(data)


def parse_eml(path: str | Path) -> ParsedEmail:
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    p = ParsedEmail(path=str(path))
    p.subject = str(msg.get("Subject", ""))
    p.from_display, p.from_addr = parseaddr(str(msg.get("From", "")))
    p.from_addr = p.from_addr.lower()
    p.return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    p.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1].lower()
    p.date = str(msg.get("Date", ""))
    p.message_id = str(msg.get("Message-ID", ""))
    p.auth_headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    spf = msg.get_all("Received-SPF") or []
    p.auth_headers += [f"received-spf: spf={str(h).split()[0].lower()}" for h in spf if str(h).split()]
    p.received = [" ".join(str(h).split()) for h in (msg.get_all("Received") or [])]

    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        ctype = part.get_content_type()
        if name or part.get_content_disposition() == "attachment":
            p.attachments.append((name or "(unnamed)", ctype, part.get_payload(decode=True) or b""))
        elif ctype == "text/html" and not p.html:
            p.html = _content(part)
        elif ctype == "text/plain" and not p.text:
            p.text = _content(part)
    return p


def _content(part) -> str:
    try:
        return part.get_content()
    except Exception:  # unknown charset etc. - degrade, never crash
        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def extract_links(p: ParsedEmail) -> tuple[list[tuple[str, str]], str]:
    """Return ([(href, anchor_text)], visible_text)."""
    lp = LinkParser()
    if p.html:
        lp.feed(p.html)
    links = [(h, t) for h, t in lp.links if h.lower().startswith(("http://", "https://"))]
    seen = {h for h, _ in links}
    visible = " ".join(" ".join(lp.chunks).split())
    for u in URL_RE.findall(p.text + " " + visible):
        u = u.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            links.append((u, ""))
    return links, f"{p.subject} {p.text} {visible}".strip()

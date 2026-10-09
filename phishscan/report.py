"""Terminal, Markdown, JSON and self-contained HTML reports. All untrusted text is escaped."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from html import escape

from .analyzer import defang

ORDER = ["HIGH", "MEDIUM", "LOW"]
ANSI = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def to_terminal(reports) -> str:
    c = Counter(r.verdict for r in reports)
    out = [f"{BOLD}PHISHING EMAIL ANALYZER{RESET} {DIM}// static analysis // {len(reports)} emails{RESET}", "",
           "  ".join(f"{ANSI[v]}{v} {c[v]}{RESET}" for v in ORDER), ""]
    for r in sorted(reports, key=lambda r: -r.score):
        bar = "█" * (r.score // 5) + "░" * (20 - r.score // 5)
        out.append(f"{ANSI[r.verdict]}{r.verdict:<6}{RESET} {bar} {r.score:>3}  {r.label:<22} {r.subject[:46]}")
    return "\n".join(out)


def to_json(reports) -> str:
    return json.dumps([asdict(r) for r in reports], indent=2)


def to_markdown(reports) -> str:
    out = ["# Phishing Analysis Report", "", "| Verdict | Score | Subject | From |", "|---|---|---|---|"]
    for r in sorted(reports, key=lambda r: -r.score):
        out.append(f"| {r.verdict} | {r.score} | {r.subject} | {defang(r.from_addr)} |")
    for r in sorted(reports, key=lambda r: -r.score):
        out += ["", f"## {r.subject}", "", f"**{r.verdict} ({r.score}/100) - {r.label}**", "",
                f"- From: {r.from_display} <{defang(r.from_addr)}>", f"- Return-Path: {defang(r.return_path) or '-'}",
                f"- Reply-To: {defang(r.reply_to) or '-'}", f"- Origin IP: {defang(r.origin_ip) or '-'} ({r.hops} hops)",
                f"- SPF `{r.auth['spf']}` | DKIM `{r.auth['dkim']}` | DMARC `{r.auth['dmarc']}`", "",
                "**Findings**", ""]
        out += [f"- `{f.points:+d}` {f.title}: {f.detail}" for f in r.findings] or ["- none"]
        if r.urls:
            out += ["", "**URLs (defanged)**", ""] + [f"- `{defang(u.url)}` {', '.join(u.flags)}" for u in r.urls]
        if r.attachments:
            out += ["", "**Attachments**", ""] + [f"- {a.filename} sha256 `{a.sha256}` {', '.join(a.flags)}" for a in r.attachments]
        out += ["", "**Recommended actions**", ""] + [f"- [ ] {a}" for a in r.actions]
    return "\n".join(out) + "\n"


CSS = """
:root{--bg:#080b12;--panel:#0e131e;--line:#1d2840;--text:#d4e4ff;--dim:#6f84a8;--cyan:#22e0ff;
--HIGH:#ff3b5c;--MEDIUM:#ffb020;--LOW:#35d98a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "JetBrains Mono","Fira Code",
"SFMono-Regular",Consolas,"Liberation Mono",monospace;padding-bottom:60px}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
header{border-bottom:1px solid var(--line);padding:34px 0 26px;background:linear-gradient(180deg,#0c1527,var(--bg))}
h1{margin:0;font-size:26px}.sub{color:var(--dim);margin-top:6px}.p{color:var(--cyan)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0 8px}
.stat{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);padding:12px 14px}
.stat b{display:block;font-size:30px;color:var(--c);line-height:1.1}.stat span{color:var(--dim);font-size:12px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0 14px}
button{background:var(--panel);color:var(--text);border:1px solid var(--line);padding:6px 12px;font:inherit;cursor:pointer}
button[aria-pressed=true]{border-color:var(--cyan);color:var(--cyan)}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
details{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);margin-bottom:10px}
summary{cursor:pointer;list-style:none;padding:12px 14px;display:grid;grid-template-columns:auto 1fr auto;gap:6px 14px;align-items:center}
summary::-webkit-details-marker{display:none}
.tag{color:#07090f;background:var(--c);padding:1px 8px;font-weight:700}.title{font-weight:600;overflow-wrap:anywhere}
.meta{color:var(--dim);font-size:12px;grid-column:2/4;overflow-wrap:anywhere}
.bar{color:var(--c);letter-spacing:-1px;white-space:nowrap}.bar i{color:var(--line);font-style:normal}
.body{padding:4px 16px 18px;border-top:1px solid var(--line)}
.body h3{margin:18px 0 8px;font-size:13px;color:var(--cyan);font-weight:600}
.verdict{border-left:2px solid var(--c);padding-left:10px}
table{width:100%;border-collapse:collapse;font-size:12.5px;display:block;overflow-x:auto}
th,td{text-align:left;padding:5px 12px 5px 0;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--dim);font-weight:500}.pos{color:var(--HIGH)}.neg{color:var(--LOW)}
.chips span{display:inline-block;border:1px solid var(--line);padding:0 8px;margin:0 6px 6px 0}
.ok{color:var(--LOW);border-color:var(--LOW)!important}.bad{color:var(--HIGH);border-color:var(--HIGH)!important}
.warn{color:var(--MEDIUM);border-color:var(--MEDIUM)!important}.mitre span{color:var(--cyan)}
ul{margin:0;padding-left:20px}li{margin:3px 0}code{color:var(--cyan)}
footer{color:var(--dim);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}
@media(max-width:640px){summary{grid-template-columns:1fr}.meta{grid-column:1}}
"""


def _chip(mech, val):
    cls = "ok" if val == "pass" else "bad" if val in ("fail", "permerror") else "warn"
    return f"<span class='{cls}'>{mech.upper()} {escape(val)}</span>"


def _card(r) -> str:
    bar = "█" * (r.score // 5) + f"<i>{'░' * (20 - r.score // 5)}</i>"
    auth = "".join(_chip(m, v) for m, v in r.auth.items())
    hdr = "".join(f"<tr><td>{k}</td><td>{escape(v) or '-'}</td></tr>" for k, v in (
        ("from", f"{r.from_display} <{defang(r.from_addr)}>"), ("return-path", defang(r.return_path)),
        ("reply-to", defang(r.reply_to)), ("date", r.date),
        ("origin ip", f"{defang(r.origin_ip)} ({r.hops} hops)" if r.origin_ip else f"{r.hops} hops")))
    fnd = "".join(f"<tr><td class='{'neg' if f.points < 0 else 'pos'}'>{f.points:+d}</td><td>{escape(f.title)}</td>"
                  f"<td>{escape(f.detail)}</td></tr>" for f in r.findings) or "<tr><td colspan=3>No findings</td></tr>"
    urls = "".join(f"<tr><td>{escape(defang(u.url))}</td><td>{escape(', '.join(u.flags)) or 'clean'}</td></tr>"
                   for u in r.urls) or "<tr><td colspan=2>No links</td></tr>"
    atts = "".join(f"<tr><td>{escape(a.filename)}</td><td>{a.size} B</td><td>{a.sha256[:16]}...</td>"
                   f"<td>{escape(', '.join(a.flags)) or 'none'}</td></tr>" for a in r.attachments) \
        or "<tr><td colspan=4>No attachments</td></tr>"
    mitre = "".join(f"<span>{escape(m)}</span>" for m in r.mitre) or "<span>none</span>"
    acts = "".join(f"<li>{escape(a)}</li>" for a in r.actions)
    return f"""<details style="--c:var(--{r.verdict})" data-v="{r.verdict}">
<summary><span class="tag">{r.verdict}</span><span class="title">{escape(r.subject)}</span>
<span class="bar" aria-label="score {r.score} of 100">{bar} {r.score}</span>
<span class="meta">{escape(r.from_display)} &lt;{escape(defang(r.from_addr))}&gt; | {escape(r.label)}</span></summary>
<div class="body"><p class="verdict">{escape(r.label)} - {r.score}/100</p>
<h3>$ authentication</h3><div class="chips">{auth}</div>
<h3>$ headers</h3><table>{hdr}</table>
<h3>$ findings --explain</h3><table><tr><th>pts</th><th>finding</th><th>why</th></tr>{fnd}</table>
<h3>$ urls (defanged)</h3><table><tr><th>url</th><th>flags</th></tr>{urls}</table>
<h3>$ attachments (never opened)</h3><table><tr><th>name</th><th>size</th><th>sha256</th><th>flags</th></tr>{atts}</table>
<h3>$ mitre</h3><div class="chips mitre">{mitre}</div>
<h3>$ next-actions</h3><ul>{acts}</ul></div></details>"""


def to_html_classic(reports, generated: str) -> str:
    reports = sorted(reports, key=lambda r: -r.score)
    c = Counter(r.verdict for r in reports)
    stats = "".join(f'<div class="stat" style="--c:var(--{v})"><b>{c[v]}</b><span>{v.lower()}</span></div>' for v in ORDER)
    filt = '<button aria-pressed="true" data-f="ALL">all</button>' + "".join(
        f'<button aria-pressed="false" data-f="{v}">{v.lower()}</button>' for v in ORDER)
    js = ("document.querySelectorAll('button[data-f]').forEach(b=>b.onclick=()=>{"
          "document.querySelectorAll('button[data-f]').forEach(x=>x.setAttribute('aria-pressed',x===b));"
          "document.querySelectorAll('details[data-v]').forEach(d=>d.hidden=b.dataset.f!=='ALL'&&d.dataset.v!==b.dataset.f)})")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phishing Email Analyzer - Report</title>
<style>{CSS}</style></head><body>
<header><div class="wrap"><h1>Phishing Email Analyzer</h1>
<div class="sub"><span class="p">$</span> phishscan analyze | {len(reports)} emails | static analysis | {escape(generated)}</div></div></header>
<main class="wrap"><div class="stats">{stats}</div><div class="filters">{filt}</div>
{''.join(_card(r) for r in reports)}
<footer>Static analysis only: attachments are hashed, never opened; links are never visited. All indicators are
defanged. Samples are synthetic. Authentication passing does not prove an email is safe.</footer></main>
<script>{js}</script></body></html>"""


from .dashboard import to_html  # noqa: E402  (radar dashboard is the default HTML report)

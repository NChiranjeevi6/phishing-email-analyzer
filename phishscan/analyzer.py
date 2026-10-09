"""Detection logic. Every finding carries points and a reason, so the verdict is explainable."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from .models import AttachmentInfo, EmailReport, Finding, UrlInfo
from .parser import ParsedEmail, extract_links

BRANDS = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com",
                  "office365.com", "windows.com", "sharepoint.com"},
    "google": {"google.com", "gmail.com", "youtube.com"}, "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazonaws.com"}, "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"}, "linkedin": {"linkedin.com"}, "github": {"github.com"},
    "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"}, "facebook": {"facebook.com", "fb.com"}, "adobe": {"adobe.com"},
    "zoom": {"zoom.us"}, "slack": {"slack.com"},
}
FREEMAIL = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me", "aol.com", "freemail.example"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
BAD_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "rest", "icu", "cyou"}
SECOND_LEVEL = {"co.uk", "org.uk", "com.au", "co.in", "com.br", "co.jp", "co.nz", "co.za"}
RISKY_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "iso", "img", "bat", "cmd",
             "ps1", "jar", "msi", "com", "pif", "reg", "cpl", "dll", "one"}
SMUGGLE_EXT = {"html", "htm", "svg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|com|pif|lnk|hta)$", re.I)
EXEC_TITLE = re.compile(r"\b(ceo|cfo|cto|coo|president|chairman|managing director|director)\b", re.I)
LANGUAGE = {
    "urgency": (5, ["urgent", "immediately", "within 24 hours", "expires today", "will expire", "suspended",
                    "final notice", "act now", "verify now", "last warning", "overdue", "penalt"]),
    "credential lure": (5, ["password", "verify your account", "sign in", "confirm your identity",
                            "security alert", "unusual activity"]),
    "payment lure": (5, ["wire transfer", "invoice", "payment is required", "bank details", "gift card",
                         "purchase"]),
    "BEC pattern": (10, ["are you available", "confidential", "do not call", "keep this between us",
                         "handle a task", "i'm in a meeting"]),
}
SPF_PTS = {"fail": 15, "softfail": 8, "permerror": 8, "neutral": 3, "none": 3, "temperror": 3}
DKIM_PTS = {"fail": 10, "none": 3, "neutral": 3, "permerror": 5, "temperror": 3}
DMARC_PTS = {"fail": 15, "none": 3, "permerror": 5, "temperror": 3}
MAX_URL_POINTS, MAX_LANG_POINTS = 45, 20


# ---------- helpers ----------
def reg_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")


def _norm(s: str) -> str:
    s = s.lower().replace("rn", "m").replace("vv", "w")
    return s.translate(str.maketrans("013457@$", "oleastas"))


def is_legit(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for ds in BRANDS.values() for d in ds)


def lookalike(host: str):
    """Return (brand, reason) if host imitates a known brand it does not belong to, else None."""
    host = host.lower().strip(".")
    if not host or is_legit(host) or re.fullmatch(r"[\d.]+", host):
        return None
    if any(l.startswith("xn--") for l in host.split(".")):
        try:
            host_u = host.encode().decode("idna")
        except UnicodeError:
            host_u = host
        for brand in BRANDS:
            if brand in _norm(host_u.encode("ascii", "ignore").decode()):
                return brand, "internationalised (punycode) look-alike"
    rd = reg_domain(host)
    label = rd.split(".")[0]
    sub_labels = host[: -len(rd)].strip(".").split(".") if host != rd else []
    for brand in BRANDS:
        if brand in sub_labels:
            return brand, "brand name used as a subdomain of an unrelated domain"
        for tok in re.split(r"[-_]", label):
            n = _norm(tok)
            if tok == brand:
                return brand, "brand name used in an unrelated domain"
            if n == brand:
                return brand, "character substitution (e.g. 0 for o, 1 for l)"
            thr = 0.82 if len(brand) >= 6 else 0.9
            if n != brand and SequenceMatcher(None, n, brand).ratio() >= thr:
                return brand, "typosquat of brand name"
        if len(brand) >= 6 and brand in _norm(label.replace("-", "")):
            return brand, "brand name embedded in domain"
    return None


# ---------- analysers ----------
def parse_auth(headers: list[str]) -> dict:
    res = {"spf": "none", "dkim": "none", "dmarc": "none"}
    found = set()
    for h in headers:
        for mech, val in re.findall(r"\b(spf|dkim|dmarc)=([a-z]+)", h.lower()):
            if mech not in found:
                res[mech] = val
                found.add(mech)
    return res


def auth_findings(auth: dict) -> list[Finding]:
    out = []
    for mech, table in (("spf", SPF_PTS), ("dkim", DKIM_PTS), ("dmarc", DMARC_PTS)):
        pts = table.get(auth[mech], 0)
        if pts:
            out.append(Finding("auth", f"{mech.upper()} {auth[mech]}", pts,
                               f"{mech.upper()} result was '{auth[mech]}'", "T1566"))
    return out


def sender_findings(p: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    fd = addr_domain(p.from_addr)
    frd = reg_domain(fd) if fd else ""
    for label, addr, pts in (("Return-Path", p.return_path, 8), ("Reply-To", p.reply_to, 10)):
        d = addr_domain(addr)
        if d and frd and reg_domain(d) != frd:
            out.append(Finding("sender", f"{label} domain mismatch", pts,
                               f"From is {defang(fd)} but {label} is {defang(addr)}", "T1656"))
    name = p.from_display
    m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
    if m and reg_domain(m.group(1)) != frd:
        out.append(Finding("sender", "Display name embeds a different address", 15,
                           f"Display name shows {defang(m.group(0))}, real sender is {defang(p.from_addr)}", "T1656"))
    for brand, domains in BRANDS.items():
        if re.search(rf"\b{brand}\b", name, re.I) and not is_legit(fd):
            out.append(Finding("sender", f"Display-name spoof of {brand.title()}", 20,
                               f"Display name '{name}' but sender domain is {defang(fd)}", "T1656"))
            break
    if EXEC_TITLE.search(name) and frd in FREEMAIL:
        out.append(Finding("sender", "Executive title on a free-mail account", 25,
                           f"'{name}' writing from {defang(fd)} (classic BEC impersonation)", "T1656"))
    la = lookalike(fd) if fd else None
    if la:
        out.append(Finding("sender", f"Look-alike sender domain ({la[0]})", 25,
                           f"{defang(fd)}: {la[1]}", "T1583.001"))
    return out


def analyze_url(url: str, text: str) -> UrlInfo:
    pu = urlparse(url)
    host = (pu.hostname or "").lower()
    info = UrlInfo(url, host, text)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        try:
            ipaddress.ip_address(host)
            info.flags.append("ip_literal")
        except ValueError:
            pass
    if host in SHORTENERS:
        info.flags.append("shortener")
    if any(l.startswith("xn--") for l in host.split(".")):
        info.flags.append("punycode")
    if "@" in pu.netloc:
        info.flags.append("at_symbol")
    if host.rsplit(".", 1)[-1] in BAD_TLDS:
        info.flags.append("suspicious_tld")
    if len(host.split(".")) - len(reg_domain(host).split(".")) >= 3:
        info.flags.append("deep_subdomain")
    if pu.scheme == "http":
        info.flags.append("not_https")
    t = text.strip().lower()
    if re.match(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", t):
        th = urlparse(t if "://" in t else "http://" + t).hostname or ""
        if reg_domain(th) != reg_domain(host):
            info.flags.append("text_mismatch")
    if lookalike(host):
        info.flags.append("lookalike")
    return info


URL_RULES = {
    "text_mismatch": (20, "Link text shows one domain, href goes to another", "T1566.002"),
    "lookalike": (25, "Link points to a brand look-alike domain", "T1566.002"),
    "ip_literal": (15, "Link uses a raw IP address instead of a domain", "T1566.002"),
    "punycode": (12, "Link uses an internationalised (punycode) domain", "T1566.002"),
    "at_symbol": (10, "Link hides the real host behind an '@'", "T1566.002"),
    "shortener": (8, "Link uses a URL shortener that hides the destination", "T1566.002"),
    "suspicious_tld": (6, "Link uses a TLD common in abuse", "T1566.002"),
    "deep_subdomain": (5, "Link has an unusually deep subdomain chain", "T1566.002"),
    "not_https": (4, "Link is not HTTPS", "T1566.002"),
}


def url_findings(urls: list[UrlInfo]) -> list[Finding]:
    out: list[Finding] = []
    for flag, (pts, title, mitre) in URL_RULES.items():
        hits = [u for u in urls if flag in u.flags]
        if hits:
            ex = defang(hits[0].url)
            more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
            out.append(Finding("link", title, pts, f"e.g. {ex}{more}", mitre))
    total = sum(f.points for f in out)
    if total > MAX_URL_POINTS:  # cap so one noisy email cannot dominate on links alone
        out.append(Finding("link", "Link score capped", MAX_URL_POINTS - total, f"link points capped at {MAX_URL_POINTS}"))
    return out


def attachment_info(name: str, ctype: str, data: bytes) -> AttachmentInfo:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    a = AttachmentInfo(name, ctype, len(data), hashlib.sha256(data).hexdigest())
    if DOUBLE_EXT.search(name):
        a.flags.append("double_extension")
    if ext in RISKY_EXT:
        a.flags.append("risky_extension")
    if ext in SMUGGLE_EXT:
        a.flags.append("html_smuggling")
    if ext in MACRO_EXT:
        a.flags.append("macro_enabled")
    if ext in ARCHIVE_EXT:
        a.flags.append("archive")
    return a


ATT_RULES = {
    "risky_extension": (25, "Executable / script attachment"),
    "double_extension": (15, "Double file extension disguises the real type"),
    "html_smuggling": (15, "HTML/SVG attachment (credential harvest or HTML smuggling)"),
    "macro_enabled": (15, "Macro-enabled Office document"),
    "archive": (8, "Archive attachment (can hide payloads from scanners)"),
}


def attachment_findings(atts: list[AttachmentInfo]) -> list[Finding]:
    out = []
    for flag, (pts, title) in ATT_RULES.items():
        hits = [a for a in atts if flag in a.flags]
        if hits:
            out.append(Finding("attachment", title, pts, ", ".join(a.filename for a in hits), "T1566.001"))
    return out


def language_findings(text: str) -> list[Finding]:
    low = text.lower()
    out, total = [], 0
    for cat, (pts, phrases) in LANGUAGE.items():
        hits = [p for p in phrases if p in low]
        if hits and total < MAX_LANG_POINTS:
            pts = min(pts, MAX_LANG_POINTS - total)
            total += pts
            out.append(Finding("language", f"{cat} language", pts, "matched: " + ", ".join(hits[:4])))
    return out


def dns_findings(domain: str) -> list[Finding]:
    """Optional (--dns): does the sender domain publish SPF and DMARC? Requires dnspython."""
    try:
        import dns.resolver
    except ImportError:
        return []
    out = []
    for name, token, label in ((domain, "v=spf1", "SPF"), (f"_dmarc.{domain}", "v=DMARC1", "DMARC")):
        try:
            txt = " ".join(r.to_text() for r in dns.resolver.resolve(name, "TXT", lifetime=4))
            ok = token.lower() in txt.lower()
        except Exception:
            ok = False
        if not ok:
            out.append(Finding("auth", f"No {label} record published", 3, f"{defang(domain)} has no {label} policy"))
    return out


def origin_ip(received: list[str]) -> str:
    for hdr in reversed(received):  # bottom-most Received header = closest to the sender
        for ip in re.findall(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?", hdr):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_global or str(a).startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
                return ip
    return ""


def actions_for(verdict: str, findings: list[Finding], domains: list[str]) -> list[str]:
    cats = {f.title for f in findings}
    acts = []
    if verdict == "HIGH":
        acts += ["Quarantine and purge this message from all mailboxes (search by sender, subject, Message-ID)",
                 "Block the sender and link domains at the email gateway and web proxy: " + ", ".join(domains[:4]),
                 "Pull proxy/EDR logs to find recipients who clicked or opened it",
                 "If anyone entered credentials: reset password, revoke sessions, review mailbox rules and MFA",
                 "Record indicators in the case ticket and share with threat-intel / abuse contacts"]
    elif verdict == "MEDIUM":
        acts += ["Hold delivery or warn the recipient; do not click links or open attachments",
                 "Verify the request out-of-band using a known phone number or chat, never contact details in the email",
                 "Re-score after checking sender history and any additional recipients"]
    else:
        acts += ["No action required; deliver normally",
                 "If the user still doubts it, ask them to report via the phishing button for a second look"]
    if any("Executive title" in t for t in cats):
        acts.append("Alert finance/assistants to the impersonation attempt; no gift cards or wire changes without verbal approval")
    if any("attachment" in f.category for f in findings):
        acts.append("Do not open the attachment; detonate it in a sandbox and search for its SHA-256 fleet-wide")
    return acts


VERDICTS = [(55, "HIGH", "Likely phishing"), (25, "MEDIUM", "Suspicious - verify"), (0, "LOW", "Likely benign")]


def analyze(p: ParsedEmail, dns: bool = False) -> EmailReport:
    auth = parse_auth(p.auth_headers)
    links, visible = extract_links(p)
    urls = [analyze_url(h, t) for h, t in links]
    atts = [attachment_info(*a) for a in p.attachments]

    findings = (auth_findings(auth) + sender_findings(p) + url_findings(urls)
                + attachment_findings(atts) + language_findings(visible))
    fd = addr_domain(p.from_addr)
    if dns and fd:
        findings += dns_findings(fd)
    spoof = any(f.title.startswith(("Look-alike", "Display-name spoof")) for f in findings)
    if all(auth[m] == "pass" for m in auth) and not spoof:
        findings.append(Finding("auth", "SPF, DKIM and DMARC all pass", -10,
                                "authentication passed (note: attackers can authenticate their own look-alike domains)"))

    score = max(0, min(100, sum(f.points for f in findings)))
    verdict, label = next((v, l) for floor, v, l in VERDICTS if score >= floor)

    hosts = sorted({u.host for u in urls if u.host})
    iocs = {
        "sender": [defang(p.from_addr)] if p.from_addr else [],
        "domains": sorted({defang(h) for h in hosts if not re.fullmatch(r"[\d.]+", h)} | ({defang(fd)} if fd else set())),
        "urls": sorted({defang(u.url) for u in urls}),
        "ips": sorted({defang(h) for h in hosts if re.fullmatch(r"[\d.]+", h)}
                      | ({defang(origin_ip(p.received))} if origin_ip(p.received) else set())),
        "sha256": [a.sha256 for a in atts if a.size],
    }
    domains = [d for d in iocs["domains"] if d != defang(fd) or spoof or verdict == "HIGH"]
    mitre = sorted({f.mitre for f in findings if f.mitre})
    return EmailReport(
        file=p.path, subject=p.subject, from_display=p.from_display, from_addr=p.from_addr,
        return_path=p.return_path, reply_to=p.reply_to, date=p.date, message_id=p.message_id, auth=auth,
        hops=len(p.received), origin_ip=origin_ip(p.received), urls=urls, attachments=atts,
        findings=findings, score=score, verdict=verdict, label=label,
        actions=actions_for(verdict, findings, domains), mitre=mitre, iocs=iocs)

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    category: str       # auth | sender | link | attachment | language
    title: str
    points: int
    detail: str
    mitre: str = ""


@dataclass
class UrlInfo:
    url: str
    host: str
    text: str
    flags: list[str] = field(default_factory=list)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    flags: list[str] = field(default_factory=list)


@dataclass
class EmailReport:
    file: str
    subject: str
    from_display: str
    from_addr: str
    return_path: str
    reply_to: str
    date: str
    message_id: str
    auth: dict
    hops: int
    origin_ip: str
    urls: list[UrlInfo]
    attachments: list[AttachmentInfo]
    findings: list[Finding]
    score: int
    verdict: str            # HIGH | MEDIUM | LOW
    label: str              # human verdict
    actions: list[str]
    mitre: list[str]
    iocs: dict

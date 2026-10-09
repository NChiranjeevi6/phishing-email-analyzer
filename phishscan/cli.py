from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .parser import parse_eml
from .report import to_html, to_json, to_markdown, to_terminal


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phishscan", description="Phishing Email Analyzer (static, defensive)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze one .eml file or a folder of them")
    a.add_argument("path", nargs="?", default="samples")
    a.add_argument("-o", "--out", default="reports")
    a.add_argument("--dns", action="store_true", help="also check the sender domain publishes SPF/DMARC (needs dnspython)")
    args = p.parse_args(argv)

    target = Path(args.path)
    files = sorted(target.glob("*.eml")) if target.is_dir() else [target]
    if not files:
        print(f"no .eml files found in {target}", file=sys.stderr)
        return 1
    reports = []
    for f in files:
        try:
            reports.append(analyze(parse_eml(f), dns=args.dns))
        except Exception as e:  # one bad file must not stop a batch
            print(f"skipped {f}: {e}", file=sys.stderr)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    (out / "phish_report.html").write_text(to_html(reports, stamp), encoding="utf-8")
    (out / "phish_report.md").write_text(to_markdown(reports), encoding="utf-8")
    (out / "phish_report.json").write_text(to_json(reports), encoding="utf-8")
    print(to_terminal(reports))
    print(f"\nreports written to {out}/ (open phish_report.html)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

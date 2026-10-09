# Security & Responsible Use

**Phishing Email Analyzer is a defensive, static-analysis tool.**

## Safety design
- **Nothing is executed or fetched.** Attachments are hashed (SHA-256), never opened. Links are never visited.
- **All indicators are defanged** (`hxxp://evil[.]example`) in every report so nobody clicks one by accident.
- **Untrusted email content is HTML-escaped** in the dashboard (covered by a test with script/img payloads).
- **A malformed email never crashes a batch.** (Known limitation: an unparseable file is currently scored LOW with blank fields rather than skipped. See the README.)
- **Samples are synthetic**: RFC 5737 IPs, reserved `.example` domains, and a harmless text file named like an executable.

## Handling real emails
- Real `.eml` files may contain personal data. `.gitignore` blocks `*.eml` outside `samples/`; keep it that way.
- Only analyze mail you are authorised to inspect, and follow your organisation's phishing-response policy.
- The optional `--dns` flag makes DNS lookups for the sender domain only.

## Reporting a vulnerability
Open a private security advisory on GitHub. Please do not file public issues for vulnerabilities.

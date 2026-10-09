# Phishing Analysis Report

| Verdict | Score | Subject | From |
|---|---|---|---|
| HIGH | 100 | URGENT: Your password expires today - verify now | security[@]micros0ft-support[.]example |
| HIGH | 72 | Overdue invoice 8841 - action required | ap[@]supplier-billing[.]example |
| HIGH | 58 | Quick task | priya[.]ceo[@]freemail[.]example |
| LOW | 0 | [alert-triage-copilot] Pull request #4 opened | noreply[@]github[.]com |

## URGENT: Your password expires today - verify now

**HIGH (100/100) - Likely phishing**

- From: Microsoft Account Team <security[@]micros0ft-support[.]example>
- Return-Path: bounce[@]mailer-relay[.]example
- Reply-To: helpdesk[.]reply[@]freemail[.]example
- Origin IP: 203[.]0[.]113[.]50 (2 hops)
- SPF `fail` | DKIM `none` | DMARC `fail`

**Findings**

- `+15` SPF fail: SPF result was 'fail'
- `+3` DKIM none: DKIM result was 'none'
- `+15` DMARC fail: DMARC result was 'fail'
- `+8` Return-Path domain mismatch: From is micros0ft-support[.]example but Return-Path is bounce[@]mailer-relay[.]example
- `+10` Reply-To domain mismatch: From is micros0ft-support[.]example but Reply-To is helpdesk[.]reply[@]freemail[.]example
- `+20` Display-name spoof of Microsoft: Display name 'Microsoft Account Team' but sender domain is micros0ft-support[.]example
- `+25` Look-alike sender domain (microsoft): micros0ft-support[.]example: character substitution (e.g. 0 for o, 1 for l)
- `+20` Link text shows one domain, href goes to another: e.g. hxxp://203[.]0[.]113[.]50/verify
- `+25` Link points to a brand look-alike domain: e.g. hxxp://login-micros0ft[.]example/signin
- `+15` Link uses a raw IP address instead of a domain: e.g. hxxp://203[.]0[.]113[.]50/verify
- `+4` Link is not HTTPS: e.g. hxxp://203[.]0[.]113[.]50/verify (+1 more)
- `-19` Link score capped: link points capped at 45
- `+5` urgency language: matched: urgent, within 24 hours, expires today, will expire
- `+5` credential lure language: matched: password, verify your account, security alert

**URLs (defanged)**

- `hxxp://203[.]0[.]113[.]50/verify` ip_literal, not_https, text_mismatch
- `hxxp://login-micros0ft[.]example/signin` not_https, lookalike
- `hxxps://account[.]microsoft[.]com/security` 

**Recommended actions**

- [ ] Quarantine and purge this message from all mailboxes (search by sender, subject, Message-ID)
- [ ] Block the sender and link domains at the email gateway and web proxy: account[.]microsoft[.]com, login-micros0ft[.]example, micros0ft-support[.]example
- [ ] Pull proxy/EDR logs to find recipients who clicked or opened it
- [ ] If anyone entered credentials: reset password, revoke sessions, review mailbox rules and MFA
- [ ] Record indicators in the case ticket and share with threat-intel / abuse contacts

## Overdue invoice 8841 - action required

**HIGH (72/100) - Likely phishing**

- From: Accounts Payable <ap[@]supplier-billing[.]example>
- Return-Path: noreply[@]bulk-sender[.]example
- Reply-To: -
- Origin IP: 198[.]51[.]100[.]77 (1 hops)
- SPF `softfail` | DKIM `none` | DMARC `none`

**Findings**

- `+8` SPF softfail: SPF result was 'softfail'
- `+3` DKIM none: DKIM result was 'none'
- `+3` DMARC none: DMARC result was 'none'
- `+8` Return-Path domain mismatch: From is supplier-billing[.]example but Return-Path is noreply[@]bulk-sender[.]example
- `+25` Executable / script attachment: Invoice_8841.pdf.exe
- `+15` Double file extension disguises the real type: Invoice_8841.pdf.exe
- `+5` urgency language: matched: immediately, overdue, penalt
- `+5` payment lure language: matched: invoice, payment is required

**Attachments**

- Invoice_8841.pdf.exe sha256 `6db1d25a637656bd0c48eaf286a5cb836dbfd346e55b350619fbbf93663fd9b0` double_extension, risky_extension

**Recommended actions**

- [ ] Quarantine and purge this message from all mailboxes (search by sender, subject, Message-ID)
- [ ] Block the sender and link domains at the email gateway and web proxy: supplier-billing[.]example
- [ ] Pull proxy/EDR logs to find recipients who clicked or opened it
- [ ] If anyone entered credentials: reset password, revoke sessions, review mailbox rules and MFA
- [ ] Record indicators in the case ticket and share with threat-intel / abuse contacts
- [ ] Do not open the attachment; detonate it in a sandbox and search for its SHA-256 fleet-wide

## Quick task

**HIGH (58/100) - Likely phishing**

- From: Priya Sharma, CEO <priya[.]ceo[@]freemail[.]example>
- Return-Path: -
- Reply-To: p[.]sharma[.]private[@]othermail[.]example
- Origin IP: 198[.]51[.]100[.]9 (1 hops)
- SPF `pass` | DKIM `pass` | DMARC `none`

**Findings**

- `+3` DMARC none: DMARC result was 'none'
- `+10` Reply-To domain mismatch: From is freemail[.]example but Reply-To is p[.]sharma[.]private[@]othermail[.]example
- `+25` Executive title on a free-mail account: 'Priya Sharma, CEO' writing from freemail[.]example (classic BEC impersonation)
- `+5` urgency language: matched: urgent
- `+5` payment lure language: matched: gift card, purchase
- `+10` BEC pattern language: matched: are you available, confidential, do not call, handle a task

**Recommended actions**

- [ ] Quarantine and purge this message from all mailboxes (search by sender, subject, Message-ID)
- [ ] Block the sender and link domains at the email gateway and web proxy: freemail[.]example
- [ ] Pull proxy/EDR logs to find recipients who clicked or opened it
- [ ] If anyone entered credentials: reset password, revoke sessions, review mailbox rules and MFA
- [ ] Record indicators in the case ticket and share with threat-intel / abuse contacts
- [ ] Alert finance/assistants to the impersonation attempt; no gift cards or wire changes without verbal approval

## [alert-triage-copilot] Pull request #4 opened

**LOW (0/100) - Likely benign**

- From: GitHub <noreply[@]github[.]com>
- Return-Path: noreply[@]github[.]com
- Reply-To: -
- Origin IP: 192[.]0[.]2[.]10 (1 hops)
- SPF `pass` | DKIM `pass` | DMARC `pass`

**Findings**

- `-10` SPF, DKIM and DMARC all pass: authentication passed (note: attackers can authenticate their own look-alike domains)

**URLs (defanged)**

- `hxxps://github[.]com/notifications` 

**Recommended actions**

- [ ] No action required; deliver normally
- [ ] If the user still doubts it, ask them to report via the phishing button for a second look

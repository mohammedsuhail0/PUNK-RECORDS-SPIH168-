# ShieldSense Upgrade Plan

## Product position
**ShieldSense Mail Guardian** is an always-on, opt-in Gmail security companion. It scans incoming email metadata and content for phishing/risky-file indicators, explains the evidence in Hinglish, and gives the owner a safe review action through Telegram.

## Target flow
```text
New Gmail message
  -> existing polling agent
  -> deterministic security scan
  -> optional AI summary constrained to scan findings
  -> verdict: low / suspicious / dangerous
  -> Telegram alert for suspicious or dangerous mail
  -> dangerous: prominent escalation + confirmed simulated quarantine
  -> redacted audit entry
```

## Risk evidence
| Area | Examples |
|---|---|
| Sender | display-name/domain mismatch, reply-to mismatch, newly observed sender |
| URL | raw IP host, punycode, HTTP, lookalike brand domain, redirect chain text, credential language |
| Message | urgency/threats, OTP/password requests, payment pressure, impersonation language |
| Attachment | double extension, executable/script type, macro-enabled document, encrypted archive warning |

## Verdicts and actions
| Score | Verdict | Default action |
|---:|---|---|
| 0–29 | Low risk | record quietly; no safety guarantee |
| 30–59 | Suspicious | send Telegram warning; ask user to verify |
| 60–100 | Dangerous | immediate Telegram alert; offer confirmed label/move-to-review action |

## Hinglish alert example
```text
⚠️ ShieldSense Alert — Dangerous (82/100)

Yeh mail bank jaisa pretend kar raha hai. Link official domain se match nahi karta aur “abhi verify karo” pressure use karta hai.

Kya ho sakta hai: password ya OTP theft.
Abhi kya karo: link mat kholo. Review/Quarantine choose karke mail ko safe label mein move karo.
```

## Phased delivery
1. **Foundation:** `security_scan` module, fixture corpus, score model, unit tests.
2. **Gmail integration:** parse headers, URLs, attachment metadata; record redacted scan results.
3. **Telegram experience:** evidence-rich Hinglish alerts and confirmation buttons.
4. **Audit/dashboard:** scan history and review actions; a web dashboard can follow after the agent is reliable.
5. **Escalation:** add an opt-in phone-call provider only for confirmed high-risk events, with cooldowns and an owner allowlist.

## Non-negotiable safety boundaries
- Never execute attachments, download remote payloads, or browse submitted URLs from the app.
- No automatic deletion; confirmation is mandatory.
- A malicious email can contain prompt injection. Treat its text as untrusted data, never instructions.
- Keep raw email content out of logs and Telegram where it is unnecessary.
- Rate-limit escalations to prevent alert abuse.

# Project Map

## What exists now
Personal Gmail agent for an Indian student. It polls Gmail, classifies unread mail with Groq, sends urgent alerts to Telegram, and sends an approved draft reply through a Vercel webhook.

## Runtime map
```text
GitHub Actions (every 15 min)
  -> check_emails.py
  -> Gmail API: unread mail not labelled AI-Scanned
  -> Google Calendar API: optional availability context
  -> Groq Llama 3.1 8B: URGENT / INFO / SPAM + draft
  -> Telegram alert

Telegram callback or command
  -> api/telegram_webhook.py (Vercel Python)
  -> Gmail API: send reply / labels / cleanup
```

## Code ownership map
| Path | Responsibility |
|---|---|
| `check_emails.py` | Gmail scan loop, labels, Groq calls, Telegram alerts/digest, promotional cleanup |
| `api/telegram_webhook.py` | Telegram commands/callbacks, webhook authorization, Gmail reply sending |
| `auth_helper.py` | One-time OAuth refresh-token helper |
| `clean_promotions.py` | Standalone bulk promotion-to-trash utility |
| `.github/workflows/scan.yml` | Scheduled GitHub Actions invocation and secrets |
| `vercel.json` | Vercel Python function route |
| `README.md` + existing `*.md` | Legacy product/deployment documentation |

## Current interfaces
- Scheduler: `python check_emails.py` or `python check_emails.py --digest`
- Telegram webhook: `POST /api/telegram_webhook`
- Telegram commands: `/start`, `/status`, `/scan`, `/clean`, `/summary`
- Required secrets: Google OAuth client ID/secret/refresh token, Telegram bot token/chat ID, Groq API key, student profile.

## Current gaps before ShieldSense
- Classification is opportunity triage, not phishing/risk analysis.
- No deterministic URL, sender, attachment, or language risk rules.
- No persistent scan history or evidence model.
- Existing cleanup paths can move bulk email to Trash; they must remain separate from security decisions.
- Documentation references Gemini in places while active code calls Groq. Standardize this before upgrade.

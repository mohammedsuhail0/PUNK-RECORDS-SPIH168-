# Project Agent Rules

## Mission
Evolve this personal Gmail agent into **ShieldSense Mail Guardian**: an opt-in, 24x7 email security triage agent that detects phishing and risky attachments, explains evidence in Hinglish when appropriate, and escalates through Telegram without taking destructive action silently.

## Read first
1. `PROJECT_MAP.md` — codebase map and current runtime path.
2. `HANDOFF.md` — current state, decisions, and immediate next actions.
3. `SHIELDSENSE_UPGRADE.md` — target architecture and delivery phases.

## Working rules
- Preserve the existing Gmail → Telegram reply workflow unless an approved change replaces it.
- Never execute attachments or fetch arbitrary URLs. Analyse headers, text, filenames, MIME types, and URLs only.
- Do not delete, trash, block, or quarantine email automatically. High-risk findings require user confirmation; “quarantine” is a label/move simulation until explicitly approved.
- Do not log raw mail bodies, API tokens, refresh tokens, or Telegram bot tokens.
- Keep all AI output structured and evidence-bound. “No high-risk indicators found” is not “safe.”
- User-facing alerts use concise Hinglish by default: clear Hindi-English mix, no slang that obscures risk.
- Before deployment, run tests and verify the workflow against a dedicated test Gmail account.

## Handoff rule
At the end of every meaningful change, update `HANDOFF.md` with: completed work, files changed, validation run, known risks, and the single next action.

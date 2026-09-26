# ShieldSense AI — Master Handover & Context for New Chat Sessions

> **Purpose:** This file is the primary context bridge for any new AI coding session or developer joining the project. It provides an immediate, complete overview of the architecture, features, live deployments, test status, and design decisions.

---

## 1. Project Overview & Identity
- **Project Name:** ShieldSense AI
- **Problem Statement:** PS 02 — Autonomous AI Cyber Guardian / Threat Analyst
- **Mission:** Moving beyond passive, static signature-based virus scanners. ShieldSense is an autonomous, always-on AI security sentinel that inspects links, SMS, emails, QR codes, and live speaker audio, explains scams in human language (bilingual English + Hinglish), and executes simulated protective guardrails (Inline DNS sinkholing, auto-hangup, and 1930 reporting).
- **Primary Workspace Path:** `C:\Users\Lenovo\Downloads\ShieldSense`

---

## 2. Live Production URLs & Repositories

| Asset | URL | Purpose |
| :--- | :--- | :--- |
| 🛡️ **In-App MVP Hub** | **`https://shieldsense-security-agent.vercel.app/hub`** | Main Sentinel Workspace (No-scroll, multi-device, live call guardian, quishing scanner) |
| 🌟 **Landing Page** | **`https://shieldsense-landing-page.vercel.app`** | Marketing & 1-click Sign Up flow redirecting to MVP |
| 📊 **Security Dashboard** | **`https://shieldsense-security-agent.vercel.app/dashboard`** | Threat telemetry & immunity metrics |
| 🐙 **Primary Git Remote** | `https://github.com/mohammedsuhail0/PUNK-RECORDS-SPIH168-.git` (`origin`) | Main development branch |
| 🐙 **Landing Git Remote** | `https://github.com/mohammedsuhail0/PUNK-_RECORDS-SPIH168-.git` (`landing`) | Production sync remote |

---

## 3. Technology Stack & Key Libraries
- **Backend:** Python 3.12/3.13, FastAPI (`api/telegram_webhook.py`), Uvicorn
- **AI Intelligence:** Groq API (`llama-3.1-8b-instant`, `compound-mini` fallback) for conversational and forensic reasoning
- **Frontend:** Responsive HTML5 + Tailwind CSS v3/v4 + Google Stitch Design System (`templates/hub.html`, `templates/landing.html`, `templates/dashboard.html`)
- **Quishing Detection:** Client-side `jsQR` matrix scanning for decoding QR payload URLs
- **Voice Scam Interceptor:** Browser Web Speech API (`webkitSpeechRecognition`) + live audio waveform visualizer + preset simulation engine
- **Testing:** `pytest` (34 test cases across agent features, security scan, routing, history, and extraction)

---

## 4. Codebase Directory Map

```
C:\Users\Lenovo\Downloads\ShieldSense
├── api/
│   └── telegram_webhook.py      # Core FastAPI app, routes (/api/scan, /api/history, /hub, /dashboard, webhooks)
├── templates/
│   ├── hub.html                 # Main MVP No-Scroll UI with Call Guardian, QR scan, Groq chat, and firewall modal
│   ├── landing.html             # High-conversion landing page with 1-click Sign Up
│   └── dashboard.html           # Threat statistics & analytics dashboard
├── tests/
│   ├── test_agent_features.py   # Test suite for agent actions, quishing, and firewall
│   ├── test_frontend_routes.py  # Test suite for frontend endpoints and HTTP codes
│   ├── test_gmail_extraction.py # Test suite for email parsing and threat extraction
│   ├── test_scan_history.py     # Test suite for history storage and metrics
│   ├── test_security_scan.py    # Test suite for hybrid heuristic + LLM scanner
│   └── test_telegram_routing.py # Test suite for command dispatching and bot routing
├── stitch/                      # Google Stitch design artifacts (DESIGN.md, code.html, screen.png)
├── security_scan.py             # Two-tier detection engine (Deterministic rules + LLM reasoning)
├── scan_history.py              # Local persistent threat history & SQLite/file store
├── check_emails.py              # Gmail IMAP inbox extraction & 15-minute background monitoring
├── telegram_poll.py             # Standalone Telegram long-polling script
├── requirements.txt             # Dependencies (fastapi, uvicorn, groq, pytest, etc.)
├── vercel.json                  # Vercel deployment configuration
├── NEW_CHAT_CONTEXT.md          # Master context for AI agents in new sessions
├── CODEBASE_MAP.md              # Detailed structural architecture map
└── START_NEW_CHAT.txt           # Prompt snippet to kickstart new chat sessions
```

---

## 5. Core Architectural Highlights

### A. Two-Tier Detection Pipeline (`security_scan.py`)
1. **Tier 1 — Deterministic Baseline:** High-speed regex, entropy calculation, domain typo-squatting checks, and high-urgency keyword matching. Filters 90% of benign or obvious threats in <10ms without token costs.
2. **Tier 2 — AI Forensic Reasoning:** For suspicious or ambiguous inputs, calls Groq LLM to extract:
   - Risk score (0–100) and classification (`Safe`, `Suspicious`, `Dangerous`).
   - Plain-language Hinglish breakdown:
     - `1. Yeh Kya Hai` (Plain explanation)
     - `2. Kya Nuksaan` (Potential financial/data loss)
     - `3. Abhi Kya Karo` (Immediate safe action)
   - Scammer psychological trap (e.g. `AUTHORITY_PANIC`, `URGENCY_TRAP`).
   - Money trail & mule account indicators.

### B. MVP UI/UX Features (`templates/hub.html`)
- **No-Scroll / Single Viewport Fit:** Strictly locked to `100dvh` / `h-screen overflow-hidden` — no outer page scrollbars.
- **Sleek Shield Guardian Avatar:** Replaced generic robot icons with an emerald-gradient security badge.
- **Hidden AI Branding:** Zero mentions of model names ("Groq", "Llama") in the user-facing UI; branded as "ShieldSense Cyber Sentinel".
- **Live Call Scam Guardian:** Speakerphone speech recognition to detect live scams (Digital Arrest, Bank KYC OTP, AnyDesk).
- **Quishing Matrix Scanner:** Decodes uploaded QR images on-device to expose malicious destination URLs.
- **Inline Click Firewall:** Simulated DNS sinkhole modal that severs connections before malicious payloads load.
- **1-Click Guardrails:** `Auto-Hangup & Block`, `Sinkhole Domain`, and `Draft 1930 Cyber Crime Report`.

---

## 6. How to Run & Verify

### Run Automated Tests
```powershell
python -m pytest
# Expected output: 34 passed
```

### Run Locally
```powershell
python -m uvicorn api.telegram_webhook:app --host 127.0.0.1 --port 8000 --reload
# Access at: http://127.0.0.1:8000/hub
```

### Deploy to Production
```powershell
npx --yes vercel --prod --yes
git push origin main
git push landing main
```

---

## 7. Knowledge Graph Mapping (Graphify)
- **Repository:** `https://github.com/Graphify-Labs/graphify`
- **Installation:** `pip install graphifyy`
- **Usage:** Run `graphify .` in the root folder to generate the full AST codebase graph for AI agents.

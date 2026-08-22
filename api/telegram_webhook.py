import base64
import json
import os
import re
import sys
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pydantic import BaseModel
import requests

# Add parent directory to sys.path to import check_emails and security_scan
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import check_emails
import scan_history
import security_scan

app = FastAPI(title="ShieldSense AI Security Agent Platform")

# Load local .env file if it exists (for local testing)
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

# Retrieve Env Secrets
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.environ.get("GOOGLE_REFRESH_TOKEN")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TELEGRAM_BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "punk_rec_bot")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
WEBHOOK_SECRET_TOKEN = os.environ.get("WEBHOOK_SECRET_TOKEN")


class ScanRequest(BaseModel):
    text: str
    sender: str = ""
    subject: str = ""
    filename: str = ""
    groq_api_key: str = ""


class SignUpRequest(BaseModel):
    fullName: str
    workEmail: str
    company: str = ""
    password: str = ""


def render_template(template_name: str, context: dict = None) -> str:
    """Reads HTML template from templates/ directory and replaces context variables."""
    template_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", template_name
    )
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail=f"Template {template_name} not found")
    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()
    context = context or {}
    context.setdefault("bot_username", TELEGRAM_BOT_USERNAME)
    for key, val in context.items():
        html = html.replace("{{ " + key + " }}", str(val)).replace("{{" + key + "}}", str(val))
    return html


def get_gmail_service():
    """Refreshes the OAuth credentials and returns a Gmail API service client."""
    creds = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
    )
    creds.refresh(GoogleRequest())
    return build("gmail", "v1", credentials=creds)


def extract_draft_from_message(text):
    """Parses the drafted reply out of the Telegram alert message block."""
    pattern = r"```text\n(.*?)\n```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()

    if "Drafted Reply:" in text:
        parts = text.split("Drafted Reply:")
        if len(parts) > 1:
            return parts[1].strip()

    return None


def send_gmail_reply(service, thread_id, draft_body):
    """Sends a reply back in the original Gmail thread, preserving headers."""
    thread = service.users().threads().get(userId="me", id=thread_id).execute()
    messages = thread.get("messages", [])
    if not messages:
        raise Exception("Original email thread not found.")

    last_msg = messages[-1]
    headers = last_msg.get("payload", {}).get("headers", [])

    msg_id, subject, from_email = "", "", ""
    for h in headers:
        name = h["name"].lower()
        if name == "message-id":
            msg_id = h["value"]
        elif name == "subject":
            subject = h["value"]
        elif name == "from":
            from_email = h["value"]

    match = re.search(r"<(.*?)>", from_email)
    reply_to = match.group(1) if match else from_email

    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}"

    msg = MIMEText(draft_body)
    msg["To"] = reply_to
    msg["Subject"] = subject
    msg["In-Reply-To"] = msg_id
    msg["References"] = msg_id

    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    body = {"raw": raw_message, "threadId": thread_id}
    result = service.users().messages().send(userId="me", body=body).execute()
    return result, reply_to


def send_telegram_reply(chat_id, text, reply_markup=None):
    """Sends a standard text message back to Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    requests.post(url, json=payload)


def edit_telegram_message(chat_id, message_id, status_text):
    """Updates the original Telegram alert message, removing inline keyboard buttons."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText"
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": status_text,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps({"inline_keyboard": []}),
    }
    requests.post(url, json=payload)


def move_thread_to_safe_review(service, thread_id):
    """Moves a confirmed high-risk thread to a review label; never deletes it."""
    review_label_id = check_emails.get_or_create_label(service, check_emails.LABEL_REVIEW_NAME)
    if not review_label_id:
        raise Exception("Could not create the ShieldSense review label.")
    service.users().threads().modify(
        userId="me",
        id=thread_id,
        body={"addLabelIds": [review_label_id], "removeLabelIds": ["INBOX"]},
    ).execute()


def run_status_check():
    """Runs a check on all three cloud APIs to ensure connection is working."""
    status_msg = "🔌 *API CONNECTION STATUS CHECK*\n\n"
    try:
        gmail = get_gmail_service()
        profile = gmail.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress", "Unknown")
        status_msg += f"✅ *Gmail API:* Connected\n└ Account: `{email}`\n\n"
    except Exception as e:
        status_msg += f"❌ *Gmail API:* Disconnected\n└ Error: `{str(e)}`\n\n"

    try:
        calendar = check_emails.get_calendar_service()
        calendar.calendarList().list(maxResults=1).execute()
        status_msg += "✅ *Google Calendar API:* Connected\n└ Permissions: Read-Only (OK)\n\n"
    except Exception as e:
        status_msg += f"❌ *Google Calendar API:* Disconnected\n└ Error: `{str(e)}`\n\n"

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "Ping"}],
            "max_tokens": 5,
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            status_msg += "✅ *Groq API:* Connected\n└ Model: `llama-3.1-8b-instant` (Free Tier)\n\n"
        else:
            status_msg += f"❌ *Groq API:* Disconnected\n└ Error Code: {response.status_code}\n\n"
    except Exception as e:
        status_msg += f"❌ *Groq API:* Disconnected\n└ Error: `{str(e)}`\n\n"

    return status_msg


def perform_direct_scan(
    text: str, sender: str = "", subject: str = "", filename: str = "", groq_api_key: str = ""
) -> dict:
    """Core scanning logic for direct web/telegram user inputs."""
    attachments = [{"filename": filename}] if filename else None
    result = security_scan.scan_email(
        sender=sender or "Direct Submission <user-input@local>",
        subject=subject or (text[:50] if text else "Direct Scan Query"),
        body=text,
        attachments=attachments,
        groq_key_override=groq_api_key,
    )
    target_desc = f"File: {filename}" if filename else (f"{sender} | {subject}" if sender else text[:80])
    scan_history.add_scan_record(
        target_type="direct_input",
        target=target_desc,
        score=result["score"],
        verdict=result["verdict"],
        findings_summary=result["summary"],
        action_taken="evaluated",
    )
    return result


def handle_check_command(user_chat_id: str, content: str):
    """Processes a /check command or direct link/text scan from Telegram."""
    if not content:
        send_telegram_reply(
            user_chat_id,
            "⚠️ *Usage:* `/check <link or email text>`\nExample: `/check http://198.51.100.7/verify`",
        )
        return

    result = perform_direct_scan(content)
    score = result["score"]
    verdict = result["verdict"].upper().replace("_", " ")

    evidence = result.get("findings", [])[:3]
    evidence_text = "\n".join(f"• {item['explanation']}" for item in evidence) or "• No high-risk indicators were found."

    msg = (
        f"🛡️ *ShieldSense Direct Security Report*\n\n"
        f"Score: *{score}/100* ({verdict})\n\n"
        f"📋 *Summary:* {result.get('summary', '')}\n\n"
        f"⚠️ *Kyun suspicious hai:*\n{evidence_text}\n\n"
        f"💡 *Recommendation:* {result.get('recommendation', 'allow_with_caution')}"
    )

    keyboard = {
        "inline_keyboard": [
            [
                {"text": "🔒 Move to Safe Review", "callback_data": "secq:direct_scan"},
                {"text": "✅ Dismiss", "callback_data": "secok:direct_scan"},
            ]
        ]
    }
    send_telegram_reply(user_chat_id, msg, reply_markup=keyboard)


def handle_history_command(user_chat_id: str):
    """Replies with the 5 most recent scan history logs."""
    history = scan_history.get_scan_history(limit=5)
    if not history:
        send_telegram_reply(user_chat_id, "📜 *ShieldSense Scan History:*\n\nNo scans recorded yet!")
        return

    items = []
    for item in history:
        badge = "🔴" if item["verdict"] == "dangerous" else "🟡" if item["verdict"] == "suspicious" else "🟢"
        items.append(
            f"{badge} *{item['score']}/100* ({item['verdict'].upper()})\n"
            f"└ *Target:* `{item['target']}`\n"
            f"└ *Summary:* {item['findings_summary']}\n"
            f"└ *Date:* _{item['timestamp']}_"
        )
    msg = "📜 *ShieldSense Recent Scan History Log*\n\n" + "\n\n".join(items)
    send_telegram_reply(user_chat_id, msg)


def handle_conversational_chat(user_chat_id: str, text: str):
    """Responds conversationally or runs a scan if links/suspicious keywords are present."""
    if re.search(r"https?://", text, re.IGNORECASE) or any(
        w in text.lower() for w in ["verify", "password", "otp", "bank", "account", "suspended", "urgent"]
    ):
        handle_check_command(user_chat_id, text)
        return

    lower = text.lower()
    if any(w in lower for w in ["hi", "hello", "hey", "who are you"]):
        reply = (
            "👋 *Hey! I am ShieldSense Mail Guardian AI Agent.*\n\n"
            "I investigate emails, links, and messages to protect you from phishing and scams.\n"
            "You can:\n"
            "• Paste any link or text here to scan it\n"
            "• Type `/check <url>` to scan a specific site\n"
            "• Type `/scan` to check your Gmail inbox\n"
            "• Type `/history` to view your security log"
        )
    elif "phishing" in lower:
        reply = (
            "🛡️ *What is Phishing?*\n\n"
            "Phishing is an attack where scammers pretend to be trusted organizations (banks, Google, PayPal) "
            "using urgent threats ('account suspended') to trick you into entering your password or OTP.\n\n"
            "ShieldSense detects display name mismatches, fake IP domains, and credential pressure automatically!"
        )
    else:
        if GROQ_API_KEY:
            try:
                system_prompt = (
                    "You are ShieldSense, an intelligent, friendly AI security assistant protecting users from email phishing and scams. "
                    "Keep responses helpful, concise, and security-focused."
                )
                reply = check_emails.call_groq_api(system_prompt, text, json_mode=False)
            except Exception:
                reply = "🛡️ I am monitoring your security! Send any link or email text to scan it, or type `/check <link>`."
        else:
            reply = "🛡️ Send any link, text, or email body to me and I will analyze its security risk for you!"

    send_telegram_reply(user_chat_id, reply)


# --- Web Page HTML Routes ---


@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serves the ShieldSense Landing & Sign-Up Page for Round 3."""
    html_content = render_template("landing.html")
    return HTMLResponse(content=html_content)


@app.get("/hub", response_class=HTMLResponse)
async def analyst_hub():
    """Serves the ShieldSense Analyst Hub & Security Operations Scanner."""
    html_content = render_template("hub.html")
    return HTMLResponse(content=html_content)


@app.get("/dashboard", response_class=HTMLResponse)
async def usage_dashboard():
    """Serves the ShieldSense Usage Analysis & Stats Dashboard."""
    html_content = render_template("dashboard.html")
    return HTMLResponse(content=html_content)


# --- REST API Endpoints ---


@app.post("/api/signup")
async def api_signup(request: SignUpRequest):
    """Endpoint for analyst platform registration."""
    return JSONResponse(
        content={
            "status": "success",
            "message": f"Welcome {request.fullName} to ShieldSense Analyst Platform!",
            "redirect": "/hub",
        }
    )


@app.post("/api/login")
async def api_login():
    """Endpoint for analyst login."""
    return JSONResponse(content={"status": "success", "redirect": "/hub"})


@app.post("/api/scan")
async def api_scan(request: ScanRequest):
    """REST API endpoint for scanning direct content."""
    result = perform_direct_scan(
        request.text, request.sender, request.subject, request.filename, request.groq_api_key
    )
    return JSONResponse(content=result)


@app.get("/api/history")
async def api_history(limit: int = 20):
    """REST API endpoint for retrieving scan history."""
    history = scan_history.get_scan_history(limit=limit)
    return JSONResponse(content=history)


@app.get("/api/stats")
async def api_stats():
    """REST API endpoint for retrieving usage & threat stats."""
    stats = scan_history.get_scan_stats()
    return JSONResponse(content=stats)


# --- Telegram Webhook Endpoint ---


def handle_callback_query_internal(callback: dict):
    user_chat_id = str(callback["message"]["chat"]["id"])
    message_id = callback["message"]["message_id"]
    message_text = callback["message"]["text"]
    callback_data = callback["data"]

    if TELEGRAM_CHAT_ID and user_chat_id != TELEGRAM_CHAT_ID:
        return {"status": "unauthorized"}

    parts = callback_data.split(":")
    if len(parts) != 2:
        return {"status": "error", "reason": "invalid callback data format"}

    action, thread_id = parts[0], parts[1]

    if action == "ign":
        new_text = f"❌ *Archived Alert (Ignored)*\n\n{message_text}"
        edit_telegram_message(user_chat_id, message_id, new_text)
        return {"status": "ignored"}

    elif action == "secok":
        new_text = f"✅ *ShieldSense: marked for your review.*\n\n{message_text}"
        edit_telegram_message(user_chat_id, message_id, new_text)
        return {"status": "security_review_acknowledged"}

    elif action == "secq":
        try:
            if thread_id != "direct_scan":
                gmail = get_gmail_service()
                move_thread_to_safe_review(gmail, thread_id)
            new_text = (
                "🔒 *ShieldSense: moved to Safe Review.*\n\n"
                "The email was archived from Inbox and labelled `ShieldSense-Review`. It was not deleted.\n\n"
                f"{message_text}"
            )
            edit_telegram_message(user_chat_id, message_id, new_text)
            return {"status": "security_review_moved"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    elif action == "app":
        draft_reply = extract_draft_from_message(message_text)
        if not draft_reply:
            error_text = f"⚠️ *Error:* Could not extract draft reply from message.\n\n{message_text}"
            edit_telegram_message(user_chat_id, message_id, error_text)
            return {"status": "error", "reason": "draft parse failed"}

        try:
            gmail = get_gmail_service()
            _, recipient = send_gmail_reply(gmail, thread_id, draft_reply)

            success_text = (
                f"📬 *STATUS: Email Sent successfully!*\n\n"
                f"📧 *To:* `{recipient}`\n"
                f"✅ *Status:* Success (API 200)\n\n"
                f"*Sent Reply:*\n"
                f"```text\n{draft_reply}\n```"
            )
            edit_telegram_message(user_chat_id, message_id, success_text)
            return {"status": "sent"}
        except Exception as e:
            fail_text = (
                f"⚠️ *Error Sending Email:*\n`{str(e)}`\n\n"
                f"*Draft Preserved:*\n"
                f"```text\n{draft_reply}\n```"
            )
            edit_telegram_message(user_chat_id, message_id, fail_text)
            return {"status": "error", "reason": str(e)}


def handle_message_internal(message: dict):
    user_chat_id = str(message["chat"]["id"])
    text = message.get("text", "").strip()

    if TELEGRAM_CHAT_ID and user_chat_id != TELEGRAM_CHAT_ID:
        return {"status": "unauthorized"}

    if text.startswith("/"):
        parts = text.split(" ", 1)
        command = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if command == "/start":
            welcome_text = (
                "👋 *Welcome to ShieldSense Mail Guardian AI Agent!*\n\n"
                "I actively investigate incoming emails, links, and messages to protect you from phishing, malware, and credential theft.\n\n"
                "Commands you can use:\n"
                "🔍 `/check <link or text>` - Scan any link or message immediately\n"
                "📜 `/history` - View your security scan audit log\n"
                "🔌 `/status` - Check API connectivity status\n"
                "📩 `/scan` - Scan Gmail inbox immediately\n"
                "🧹 `/clean` - Clean promotional clutter\n"
                "📅 `/summary` - Daily digest summary"
            )
            send_telegram_reply(user_chat_id, welcome_text)
            return {"status": "command_processed", "command": "/start"}

        elif command == "/check":
            handle_check_command(user_chat_id, arg)
            return {"status": "command_processed", "command": "/check"}

        elif command == "/history":
            handle_history_command(user_chat_id)
            return {"status": "command_processed", "command": "/history"}

        elif command == "/status":
            status_text = run_status_check()
            send_telegram_reply(user_chat_id, status_text)
            return {"status": "command_processed", "command": "/status"}

        elif command == "/scan":
            send_telegram_reply(user_chat_id, "⏳ *Scanning your Gmail inbox for new emails...*")
            try:
                check_emails.main(max_emails=2)
                send_telegram_reply(user_chat_id, "✅ *Scan completed!* Check above for any new security alerts.")
                return {"status": "command_processed", "command": "/scan"}
            except Exception as e:
                send_telegram_reply(user_chat_id, f"⚠️ *Error scanning inbox:* `{str(e)}`")
                return {"status": "error", "reason": str(e)}

        elif command == "/clean":
            send_telegram_reply(user_chat_id, "⏳ *Cleaning up to 300 promotional emails...*")
            try:
                count = check_emails.clean_promotions(limit=300)
                if count > 0:
                    send_telegram_reply(
                        user_chat_id,
                        f"🧹 *Cleaned {count} promotional email(s)* from your inbox! Moved them to Trash.",
                    )
                elif count == 0:
                    send_telegram_reply(
                        user_chat_id, "🧹 *Your promotions folder is already empty!* Clean inbox! ✨"
                    )
                else:
                    send_telegram_reply(user_chat_id, "⚠️ *Error cleaning promotions.* Check Vercel logs.")
                return {"status": "command_processed", "command": "/clean"}
            except Exception as e:
                send_telegram_reply(user_chat_id, f"⚠️ *Error cleaning promotions:* `{str(e)}`")
                return {"status": "error", "reason": str(e)}

        elif command == "/summary":
            send_telegram_reply(user_chat_id, "⏳ *Generating your Daily Digest immediately...*")
            try:
                check_emails.send_daily_digest()
                return {"status": "command_processed", "command": "/summary"}
            except Exception as e:
                send_telegram_reply(user_chat_id, f"⚠️ *Error generating summary:* `{str(e)}`")
                return {"status": "error", "reason": str(e)}

        else:
            send_telegram_reply(user_chat_id, f"❓ *Unknown command:* `{command}`")
            return {"status": "unknown_command"}
    else:
        handle_conversational_chat(user_chat_id, text)
        return {"status": "chat_processed"}


@app.post("/api/telegram_webhook")
async def telegram_webhook(request: Request):
    """Entrypoint for Telegram webhook updates."""
    if WEBHOOK_SECRET_TOKEN:
        received_token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if received_token != WEBHOOK_SECRET_TOKEN:
            raise HTTPException(status_code=403, detail="Unauthorized webhook source")

    data = await request.json()

    if "callback_query" in data:
        return handle_callback_query_internal(data["callback_query"])
    elif "message" in data:
        return handle_message_internal(data["message"])

    return {"status": "ignored", "reason": "unhandled payload type"}

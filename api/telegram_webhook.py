import os
import json
import base64
import requests
import re
import sys
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from email.mime.text import MIMEText

# Add parent directory to sys.path to import check_emails
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import check_emails

app = FastAPI()

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
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

# Webhook Secret Token (optional, telegram can send it in header X-Telegram-Bot-Api-Secret-Token)
WEBHOOK_SECRET_TOKEN = os.environ.get("WEBHOOK_SECRET_TOKEN")

def get_gmail_service():
    """Refreshes the OAuth credentials and returns a Gmail API service client."""
    creds = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )
    creds.refresh(GoogleRequest())
    return build('gmail', 'v1', credentials=creds)

def extract_draft_from_message(text):
    """Parses the drafted reply out of the Telegram alert message block."""
    pattern = r"```text\n(.*?)\n```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
        
    # Fallback if Telegram strips backticks in plain text callback queries
    if "Drafted Reply:" in text:
        parts = text.split("Drafted Reply:")
        if len(parts) > 1:
            return parts[1].strip()
            
    return None

def send_gmail_reply(service, thread_id, draft_body):
    """Sends a reply back in the original Gmail thread, preserving headers."""
    thread = service.users().threads().get(userId='me', id=thread_id).execute()
    messages = thread.get('messages', [])
    if not messages:
        raise Exception("Original email thread not found.")
        
    last_msg = messages[-1]
    headers = last_msg.get('payload', {}).get('headers', [])
    
    # Extract headers
    msg_id = ""
    subject = ""
    to_email = ""
    from_email = ""
    
    for h in headers:
        name = h['name'].lower()
        if name == 'message-id':
            msg_id = h['value']
        elif name == 'subject':
            subject = h['value']
        elif name == 'from':
            from_email = h['value']
        elif name == 'to':
            to_email = h['value']

    # Reply to sender
    match = re.search(r'<(.*?)>', from_email)
    reply_to = match.group(1) if match else from_email

    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}"

    # Build MIME RFC 822 Email Message
    msg = MIMEText(draft_body)
    msg['To'] = reply_to
    msg['Subject'] = subject
    msg['In-Reply-To'] = msg_id
    msg['References'] = msg_id
    
    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
    body = {
        'raw': raw_message,
        'threadId': thread_id
    }
    
    result = service.users().messages().send(userId='me', body=body).execute()
    return result, reply_to

def send_telegram_reply(chat_id, text, reply_to_message_id=None):
    """Sends a standard text message back to Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
    requests.post(url, json=payload)

def edit_telegram_message(chat_id, message_id, status_text):
    """Updates the original Telegram alert message, removing inline keyboard buttons."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText"
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": status_text,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps({"inline_keyboard": []})
    }
    requests.post(url, json=payload)

def run_status_check():
    """Runs a check on all three cloud APIs to ensure connection is working."""
    status_msg = "🔌 *API CONNECTION STATUS CHECK*\n\n"
    
    # 1. Check Gmail
    try:
        gmail = get_gmail_service()
        profile = gmail.users().getProfile(userId='me').execute()
        email = profile.get('emailAddress', 'Unknown')
        status_msg += f"✅ *Gmail API:* Connected\n└ Account: `{email}`\n\n"
    except Exception as e:
        status_msg += f"❌ *Gmail API:* Disconnected\n└ Error: `{str(e)}`\n\n"

    # 2. Check Google Calendar
    try:
        calendar = check_emails.get_calendar_service()
        calendar.calendarList().list(maxResults=1).execute()
        status_msg += "✅ *Google Calendar API:* Connected\n└ Permissions: Read-Only (OK)\n\n"
    except Exception as e:
        status_msg += f"❌ *Google Calendar API:* Disconnected\n└ Error: `{str(e)}`\n\n"

    # 3. Check Groq
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "Ping"}],
            "max_tokens": 5
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            status_msg += "✅ *Groq API:* Connected\n└ Model: `llama-3.1-8b-instant` (Free Tier)\n\n"
        else:
            status_msg += f"❌ *Groq API:* Disconnected\n└ Error Code: {response.status_code}\n\n"
    except Exception as e:
        status_msg += f"❌ *Groq API:* Disconnected\n└ Error: `{str(e)}`\n\n"
        
    return status_msg

@app.post("/api/telegram_webhook")
async def telegram_webhook(request: Request):
    """Entrypoint for Telegram webhook updates."""
    # Webhook Security Check (if secret token header is set)
    if WEBHOOK_SECRET_TOKEN:
        received_token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if received_token != WEBHOOK_SECRET_TOKEN:
            raise HTTPException(status_code=403, detail="Unauthorized webhook source")

    data = await request.json()
    
    # Handle Callback Queries (Button Clicks)
    if "callback_query" in data:
        callback = data["callback_query"]
        user_chat_id = str(callback["message"]["chat"]["id"])
        message_id = callback["message"]["message_id"]
        message_text = callback["message"]["text"]
        callback_data = callback["data"]
        
        # Security check: Ignore unauthorized users
        if user_chat_id != TELEGRAM_CHAT_ID:
            return JSONResponse(content={"status": "unauthorized"})

        parts = callback_data.split(":")
        if len(parts) != 2:
            return JSONResponse(content={"status": "error", "reason": "invalid callback data format"})
            
        action, thread_id = parts[0], parts[1]

        if action == "ign":
            new_text = f"❌ *Archived Alert (Ignored)*\n\n{message_text}"
            edit_telegram_message(user_chat_id, message_id, new_text)
            return {"status": "ignored"}

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

    # Handle Text Messages & Slash Commands
    elif "message" in data:
        message = data["message"]
        user_chat_id = str(message["chat"]["id"])
        message_id = message["message_id"]
        text = message.get("text", "").strip()

        # Security check: Ignore unauthorized users
        if user_chat_id != TELEGRAM_CHAT_ID:
            return JSONResponse(content={"status": "unauthorized"})

        if text.startswith("/"):
            command = text.split(" ")[0].lower()
            
            if command == "/start":
                welcome_text = (
                    "👋 *Hello! I am your Personal Email AI Agent.*\n\n"
                    "I am currently running and ready to scan your Gmail inbox, "
                    "categorize incoming emails, and check your Google Calendar availability.\n\n"
                    "Commands you can use:\n"
                    "🔌 `/status` - Check API connectivity status\n"
                    "🔍 `/scan` - Scan inbox immediately for new emails\n"
                    "🧹 `/clean` - Clean up to 300 promotional emails from inbox\n"
                    "📅 `/summary` - Trigger your Daily Digest summary immediately"
                )
                send_telegram_reply(user_chat_id, welcome_text)
                return {"status": "command_processed", "command": "/start"}
                
            elif command == "/status":
                status_text = run_status_check()
                send_telegram_reply(user_chat_id, status_text)
                return {"status": "command_processed", "command": "/status"}
                
            elif command == "/scan":
                send_telegram_reply(user_chat_id, "⏳ *Scanning your Gmail inbox for new emails...*")
                try:
                    # Scan at most 2 emails from the webhook to stay within Vercel's 10s timeout
                    check_emails.main(max_emails=2)
                    send_telegram_reply(user_chat_id, "✅ *Scan completed!* Check above for any new URGENT email alerts.")
                    return {"status": "command_processed", "command": "/scan"}
                except Exception as e:
                    send_telegram_reply(user_chat_id, f"⚠️ *Error scanning inbox:* `{str(e)}`")
                    return {"status": "error", "reason": str(e)}

            elif command == "/clean":
                send_telegram_reply(user_chat_id, "⏳ *Cleaning up to 300 promotional emails...*")
                try:
                    count = check_emails.clean_promotions(limit=300)
                    if count > 0:
                        send_telegram_reply(user_chat_id, f"🧹 *Cleaned {count} promotional email(s)* from your inbox! Moved them to Trash.")
                    elif count == 0:
                        send_telegram_reply(user_chat_id, "🧹 *Your promotions folder is already empty!* Clean inbox! ✨")
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

    return {"status": "ignored", "reason": "unhandled payload type"}

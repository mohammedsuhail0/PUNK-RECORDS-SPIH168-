import os
import sys
import time
import json
import base64
import requests
from security_scan import scan_email
from datetime import datetime, timedelta, timezone
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Load local .env file if it exists (for local testing)
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

# Set console encoding to UTF-8 to prevent print crashes on Windows when encountering emojis/unicode
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Load Environment Variables (GitHub Secrets or Local Env)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_REFRESH_TOKEN = os.environ.get("GOOGLE_REFRESH_TOKEN")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
STUDENT_PROFILE = os.environ.get("STUDENT_PROFILE", "I am a college student in India studying Computer Science. Actively looking for internships and scholarship opportunities. Keep typical reply tone helpful, polite, and formal.")

LABEL_SCAN_NAME = "AI-Scanned"
LABEL_INFO_NAME = "AI-Info"
LABEL_REVIEW_NAME = "ShieldSense-Review"

def get_gmail_service():
    """Authenticates and returns the Gmail API service client."""
    creds = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )
    creds.refresh(Request())
    return build('gmail', 'v1', credentials=creds)

def get_calendar_service():
    """Authenticates and returns the Google Calendar API service client."""
    creds = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )
    creds.refresh(Request())
    return build('calendar', 'v3', credentials=creds)

def get_or_create_label(service, label_name):
    """Checks if a label exists, creates it if not, and returns its ID."""
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'] == label_name:
                return label['id']
        
        # Label doesn't exist, create it
        label_body = {
            'name': label_name,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        created_label = service.users().labels().create(userId='me', body=label_body).execute()
        print(f"Created new label: {label_name}")
        return created_label['id']
    except Exception as e:
        print(f"Error getting/creating label {label_name}: {e}")
        return None

def parse_email_body(payload):
    """Recursively parses the email parts to retrieve the plain text body."""
    body = ""
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data', '')
                body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            elif 'parts' in part:
                body += parse_email_body(part)
    else:
        # Single-part message
        data = payload['body'].get('data', '')
        body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    return body

def clean_email_headers(message_detail):
    """Extracts the email headers needed for triage and safe replies."""
    headers = message_detail.get('payload', {}).get('headers', [])
    email_data = {'Subject': '', 'From': '', 'Reply-To': '', 'Date': '', 'Message-ID': ''}
    header_map = {k.lower(): k for k in email_data}
    for header in headers:
        name = (header.get('name') or '').lower()
        if name in header_map:
            email_data[header_map[name]] = header.get('value', '')
    return email_data

def extract_attachment_metadata(payload):
    """Returns filename/MIME metadata only; attachments are never opened or downloaded."""
    attachments = []
    for part in payload.get('parts', []):
        filename = part.get('filename', '')
        if filename:
            attachments.append({
                'filename': filename,
                'mime_type': part.get('mimeType', ''),
                'size': part.get('body', {}).get('size', 0)
            })
        attachments.extend(extract_attachment_metadata(part))
    return attachments


def get_upcoming_events(service):
    """Fetches calendar events for the next 3 days to check availability."""
    try:
        now = datetime.now(timezone.utc)
        time_min = now.isoformat()
        time_max = (now + timedelta(days=3)).isoformat()
        
        events_result = service.events().list(
            calendarId='primary', 
            timeMin=time_min,
            timeMax=time_max, 
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        formatted_events = []
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            summary = event.get('summary', 'Busy')
            
            try:
                start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
                start_str = start_dt.strftime("%A, %b %d at %I:%M %p")
                end_str = end_dt.strftime("%I:%M %p")
                time_range = f"{start_str} - {end_str}"
            except Exception:
                time_range = f"{start} to {end}"

            formatted_events.append(f"- {summary} ({time_range})")
        
        return "\n".join(formatted_events) if formatted_events else "No upcoming events (completely free)."
    except Exception as e:
        print(f"Error fetching calendar events: {e}")
        return "Could not retrieve calendar events."


def call_groq_api(system_prompt, user_prompt, json_mode=True, groq_key_override=None):
    """Calls Groq API chat completions endpoint using requests with resilient model fallbacks."""
    api_key = groq_key_override or os.environ.get("GROQ_API_KEY") or GROQ_API_KEY
    if not api_key:
        raise Exception("GROQ_API_KEY not configured")

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    candidate_models = ["groq/compound-mini", "groq/compound", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]
    last_err = None

    for model in candidate_models:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=8)
            if response.status_code == 200:
                result = response.json()
                return result["choices"][0]["message"]["content"].strip()
            else:
                last_err = response.text
        except Exception as e:
            last_err = str(e)

    raise Exception(f"Groq API Error across models: {last_err}")


def classify_email(sender, subject, body, calendar_context):
    """Uses Groq (Llama 3.1) to categorize the email, check calendar, and draft a reply."""
    system_prompt = f"""
    You are an elite personal AI assistant for a college student in India. 
    Analyze the incoming email and categorize it.
    
    Student Profile Context:
    {STUDENT_PROFILE}
    """
    
    user_prompt = f"""
    Gmail Message Details:
    From: {sender}
    Subject: {subject}
    Body:
    {body}

    Student's Upcoming Google Calendar Schedule (Next 3 Days):
    {calendar_context}
    
    Decide if this email is:
    1. "URGENT": Immediate action required (scholarships, job/placement cell invites, official exams/grades, interviews).
    2. "INFO": No immediate response needed but good to know (academic newsletters, generic campus updates, club announcements).
    3. "SPAM": Ads, promotional coupons, social networks, receipts.

    If the email is URGENT:
    - Write a concise, professional draft reply in English as the student. 
    - If the email is asking to schedule a meeting, call, or interview, check the student's calendar schedule context provided above. Suggest free time slots that DO NOT conflict with their calendar events. Keep the tone professional, polite, and helpful.
    
    You MUST respond with a valid, clean JSON object matching this schema:
    {{
      "category": "URGENT" | "INFO" | "SPAM",
      "urgency_score": 1-5,
      "reasoning": "A 1-sentence explanation of why you classified it this way.",
      "draft_reply": "Your drafted reply (leave empty if category is INFO or SPAM)"
    }}
    Do NOT include any markdown code blocks (like ```json) in your response, return ONLY the raw JSON string.
    """
    try:
        response_text = call_groq_api(system_prompt, user_prompt, json_mode=True)
        return json.loads(response_text)
    except Exception as e:
        print(f"Groq Classification Error: {e}")
        return {
            "category": "INFO",
            "urgency_score": 1,
            "reasoning": f"Failed to call Groq: {str(e)}",
            "draft_reply": ""
        }

def send_telegram_alert(sender, subject, summary, draft, thread_id):
    """Sends an interactive Telegram alert with Approve & Ignore inline buttons."""
    message = (
        f"🔴 *URGENT EMAIL DETECTED*\n\n"
        f"📧 *From:* {sender}\n"
        f"📌 *Subject:* {subject}\n\n"
        f"📖 *Summary:* {summary}\n\n"
        f"📝 *Drafted Reply:*\n"
        f"```text\n{draft}\n```"
    )
    keyboard = {
        "inline_keyboard": [
            [
                {"text": "✅ Send Reply", "callback_data": f"app:{thread_id}"},
                {"text": "❌ Ignore", "callback_data": f"ign:{thread_id}"}
            ]
        ]
    }
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps(keyboard)
    }
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"Telegram Notification Error: {response.text}")
    else:
        print("Telegram push alert sent successfully.")

def send_security_alert(sender, subject, security, thread_id):
    """Sends evidence-bound ShieldSense alerts. No email action occurs until a button is confirmed."""
    evidence = security.get('findings', [])[:3]
    evidence_text = "\n".join(
        f"• {item['explanation']}" for item in evidence
    ) or "• No high-risk indicators were found."
    verdict = security.get('verdict', 'suspicious').upper().replace('_', ' ')
    message = (
        f"🛡️ *ShieldSense Alert — {verdict} ({security.get('score', 0)}/100)*\n\n"
        f"*From:* {sender}\n*Subject:* {subject}\n\n"
        f"{security.get('summary', '')}\n\n"
        f"*Kyun suspicious hai:*\n{evidence_text}\n\n"
        "*Abhi kya karo:* Link/attachment mat kholo. Review karke decide karo."
    )
    keyboard = {
        "inline_keyboard": [[
            {"text": "🔒 Move to Safe Review", "callback_data": f"secq:{thread_id}"},
            {"text": "✅ I Will Review", "callback_data": f"secok:{thread_id}"}
        ]]
    }
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    response = requests.post(url, json={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "reply_markup": json.dumps(keyboard)
    })
    if response.status_code != 200:
        print(f"ShieldSense Telegram alert error: {response.text}")

def send_telegram_text(text):
    """Helper to send a text message to Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"Telegram Send Error: {response.text}")

def summarize_email_for_digest(sender, subject, body):
    """Uses Groq to summarize an informational email in a single line."""
    system_prompt = "You are an AI assistant. Summarize the following email in a single, clear, action-oriented sentence for a daily digest."
    user_prompt = f"""
    From: {sender}
    Subject: {subject}
    Body:
    {body}
    
    Response must be a single sentence. Do not include markdown or quotes.
    """
    try:
        return call_groq_api(system_prompt, user_prompt, json_mode=False)
    except Exception as e:
        print(f"Groq digest error: {e}")
        return "Failed to summarize email contents."

def send_daily_digest():
    """Queries Gmail for label:AI-Info, compiles and sends a digest to Telegram, then clears the labels."""
    print("Generating Daily Digest...")
    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, GROQ_API_KEY]):
        print("Error: Missing secrets.")
        return

    gmail = get_gmail_service()
    info_label_id = get_or_create_label(gmail, LABEL_INFO_NAME)
    if not info_label_id:
        print("AI-Info label not found. No digest to compile.")
        return

    # Query for label:AI-Info
    query = f"label:{LABEL_INFO_NAME}"
    results = gmail.users().messages().list(userId='me', q=query).execute()
    all_messages = results.get('messages', [])

    if not all_messages:
        print("No new INFO emails found for the daily digest.")
        send_telegram_text("📅 *DAILY DIGEST*\n\nNo updates today! Your inbox is clean.")
        return

    # Process at most 5 emails per execution to stay within Vercel 10s timeout
    messages = all_messages[:5]
    print(f"Summarizing {len(messages)} of {len(all_messages)} INFO emails for digest...")
    digest_items = []
    msg_ids = []

    for msg in messages:
        msg_id = msg['id']
        msg_ids.append(msg_id)
        
        try:
            msg_detail = gmail.users().messages().get(userId='me', id=msg_id).execute()
            headers = clean_email_headers(msg_detail)
            body = parse_email_body(msg_detail.get('payload', {}))
            
            sender = headers['From']
            subject = headers['Subject']
            
            # Truncate body to stay within Groq TPM limits
            body_truncated = body[:2000] if len(body) > 2000 else body
            
            summary = summarize_email_for_digest(sender, subject, body_truncated)
            digest_items.append(f"🔹 *{sender}*\n└ *Subject:* {subject}\n└ *AI Summary:* {summary}")
        except Exception as e:
            print(f"Error processing message {msg_id} for digest: {e}")

    # Send to Telegram
    date_str = datetime.now().strftime("%d %B %Y")
    digest_content = "\n\n".join(digest_items)
    suffix = ""
    if len(all_messages) > 5:
        suffix = f"\n\n🕒 *Note:* Showing 5 of {len(all_messages)} emails. Send `/summary` again to see the next ones."
        
    telegram_message = (
        f"📅 *DAILY DIGEST - {date_str}*\n\n"
        f"Total emails scanned today: *{len(all_messages)}*\n\n"
        f"{digest_content}"
        f"{suffix}"
    )
    send_telegram_text(telegram_message)

    # Clean up: remove AI-Info label for processed messages only
    gmail.users().messages().batchModify(
        userId='me',
        body={
            'ids': msg_ids,
            'removeLabelIds': [info_label_id]
        }
    ).execute()
    print("Daily digest sent successfully and labels cleared.")

def clean_promotions(limit=300):
    """Deletes up to `limit` promotional emails in Gmail."""
    gmail = get_gmail_service()
    query = "category:promotions"
    try:
        results = gmail.users().messages().list(userId='me', q=query, maxResults=limit).execute()
        messages = results.get('messages', [])
        if not messages:
            return 0
            
        msg_ids = [m['id'] for m in messages]
        gmail.users().messages().batchModify(
            userId='me',
            body={
                'ids': msg_ids,
                'addLabelIds': ['TRASH'],
                'removeLabelIds': ['INBOX']
            }
        ).execute()
        return len(msg_ids)
    except Exception as e:
        print(f"Error cleaning promotions: {e}")
        return -1

def main(max_emails=10):
    if len(sys.argv) > 1 and sys.argv[1] == "--digest":
        send_daily_digest()
        return

    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, GROQ_API_KEY]):
        print("Error: Missing required environment variables. Please check secrets.")
        return

    gmail = get_gmail_service()
    scan_label_id = get_or_create_label(gmail, LABEL_SCAN_NAME)
    info_label_id = get_or_create_label(gmail, LABEL_INFO_NAME)
    
    if not scan_label_id or not info_label_id:
        print("Failed to access or create Gmail labels. Aborting.")
        return

    # Scan for unread emails not marked with our scan label
    query = f"is:unread -label:{LABEL_SCAN_NAME}"
    results = gmail.users().messages().list(userId='me', q=query).execute()
    all_messages = results.get('messages', [])

    if not all_messages:
        print("No new unread emails to scan.")
        return

    # Process at most max_emails per execution to avoid hitting rate limits
    messages = all_messages[:max_emails]
    print(f"Found {len(all_messages)} unread email(s). Processing up to {len(messages)} in this execution.")

    # Get Calendar Context once if there are messages to process
    calendar_context = "Could not connect to Google Calendar."
    try:
        calendar_service = get_calendar_service()
        calendar_context = get_upcoming_events(calendar_service)
    except Exception as e:
        print(f"Failed to check calendar: {e}")

    for msg in messages:
        msg_id = msg['id']
        thread_id = msg['threadId']
        
        # Apply scan label immediately to avoid duplicate runs if the script times out
        gmail.users().messages().batchModify(
            userId='me',
            body={
                'ids': [msg_id],
                'addLabelIds': [scan_label_id]
            }
        ).execute()

        # Fetch full email details
        msg_detail = gmail.users().messages().get(userId='me', id=msg_id).execute()
        headers = clean_email_headers(msg_detail)
        body = parse_email_body(msg_detail.get('payload', {}))
        attachments = extract_attachment_metadata(msg_detail.get('payload', {}))
        
        sender = headers['From']
        subject = headers['Subject']

        # Security triage is deterministic and non-invasive. It runs before any AI drafting.
        security = scan_email(sender, subject, body, headers.get('Reply-To', ''), attachments)
        if security['verdict'] in ('suspicious', 'dangerous'):
            send_security_alert(sender, subject, security, thread_id)
        if security['verdict'] == 'dangerous':
            print(f"ShieldSense flagged as dangerous ({security['score']}/100). Awaiting user review.")
            continue

        # Truncate body to first 3000 characters to stay within Groq TPM limits
        body_truncated = body[:3000] if len(body) > 3000 else body

        print(f"Scanning email: {subject} from {sender}")
        
        # Existing opportunity classification runs only after the safety gate.
        analysis = classify_email(sender, subject, body_truncated, calendar_context)
        
        category = analysis.get("category", "INFO")
        reason = analysis.get("reasoning", "")
        draft = analysis.get("draft_reply", "")
        
        print(f"AI Category: {category} | Reason: {reason}")
        
        if category == "URGENT":
            send_telegram_alert(sender, subject, reason, draft, thread_id)
        elif category == "INFO":
            # Apply AI-Info label for later Daily Digest summary
            gmail.users().messages().batchModify(
                userId='me',
                body={
                    'ids': [msg_id],
                    'addLabelIds': [info_label_id]
                }
            ).execute()
            print("Categorized as INFO. Labeled for daily digest.")
        else:
            print("Categorized as SPAM. Moving to Trash...")
            try:
                gmail.users().messages().trash(userId='me', id=msg_id).execute()
                print("Successfully moved SPAM email to Trash.")
            except Exception as e:
                print(f"Error trashing SPAM email: {e}")
            
        # Sleep for 4 seconds to respect the rate limit of Groq Free Tier
        time.sleep(4)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"Global execution failure:\n{tb}")
        
        # If running in GitHub Actions, push the traceback to Telegram for remote diagnostics
        if os.environ.get("GITHUB_ACTIONS") == "true":
            try:
                error_msg = f"⚠️ *GitHub Actions Workflow Failure:*\n\n```text\n{tb[:3800]}\n```"
                send_telegram_text(error_msg)
            except Exception as te:
                print(f"Failed to send failure alert to Telegram: {te}")
        sys.exit(1)

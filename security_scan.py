"""Deterministic + Groq LLM AI security checks for ShieldSense.

This module inspects supplied text, URLs, file metadata, and email headers.
It integrates Groq (Llama 3.1) AI intent analysis whenever GROQ_API_KEY is available or supplied.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass
from email.utils import parseaddr
from typing import Iterable
from urllib.parse import parse_qs, urlparse
import requests

URL_PATTERN = re.compile(r"https?://[^\s<>()\[\]{}]+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}
RISKY_URL_WORDS = {"verify", "secure", "login", "signin", "password", "update", "wallet", "kyc"}
REDIRECT_PARAMETERS = {"url", "redirect", "redirect_url", "target", "next", "continue", "dest"}
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "sbi": {"sbi.co.in"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
}
EXECUTABLE_EXTENSIONS = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".js", ".jse", ".vbs", ".vbe", ".scr", ".jar", ".apk"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    score: int
    explanation: str


def _host_matches(host: str, allowed_domains: set[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains)


def _finding(code: str, score: int, explanation: str) -> Finding:
    severity = "high" if score >= 20 else "medium" if score >= 10 else "low"
    return Finding(code, severity, score, explanation)


def extract_urls(text: str) -> list[str]:
    return [match.rstrip(".,!?;:'\"") for match in URL_PATTERN.findall(text or "")]


def scan_url(url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()

    if parsed.scheme.lower() == "http":
        findings.append(_finding("url.insecure_http", 8, "The link uses HTTP, so its connection is not encrypted."))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(_finding("url.punycode", 25, "The domain uses punycode, which can be used to imitate familiar websites."))
    try:
        ipaddress.ip_address(host)
        findings.append(_finding("url.raw_ip_host", 30, "The link uses an IP address instead of a recognizable website domain."))
    except ValueError:
        pass
    if host in SHORTENERS:
        findings.append(_finding("url.shortener", 12, "The link is shortened, so its final destination is hidden."))
    if host.count(".") >= 3:
        findings.append(_finding("url.excessive_subdomains", 10, "The link has many subdomains, a pattern often used to make a fake site look legitimate."))
    if any(word in path_and_query for word in RISKY_URL_WORDS):
        findings.append(_finding("url.credential_language", 10, "The link contains account or verification language commonly used in phishing."))
    if any(key.lower() in REDIRECT_PARAMETERS for key in parse_qs(parsed.query)):
        findings.append(_finding("url.redirect_parameter", 12, "The link contains a redirect parameter that can hide the final destination."))
    if re.search(r"(paypa1|g00gle|micr0soft|amaz0n|faceb00k)", host):
        findings.append(_finding("url.lookalike_domain", 30, "The domain looks like a misspelled version of a known brand."))
    return findings


def scan_sender(sender: str, reply_to: str = "") -> list[Finding]:
    display_name, address = parseaddr(sender or "")
    _, reply_address = parseaddr(reply_to or "")
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    reply_domain = reply_address.rsplit("@", 1)[-1].lower() if "@" in reply_address else ""
    findings: list[Finding] = []

    lowered_name = display_name.lower()
    for brand, allowed_domains in BRAND_DOMAINS.items():
        if brand in lowered_name and domain and not _host_matches(domain, allowed_domains):
            findings.append(_finding("sender.brand_domain_mismatch", 30, f"The sender name claims to be {brand.title()}, but its domain does not match the official domain."))
            break
    if reply_domain and domain and reply_domain != domain:
        findings.append(_finding("sender.reply_to_mismatch", 20, "The reply-to address points to a different domain than the sender."))
    return findings


def scan_message(subject: str, body: str) -> list[Finding]:
    text = f"{subject}\n{body}".lower()
    findings: list[Finding] = []
    if re.search(r"(urgent|immediately|act now|within \d+ hours|suspended|final warning|account.*locked)", text):
        findings.append(_finding("message.urgency", 8, "The message creates urgency or threatens a consequence to pressure a quick decision."))
    if re.search(r"(password|passcode|otp|one.time password|verification code|login credentials)", text):
        findings.append(_finding("message.credential_request", 20, "The message asks for credentials or a verification code. Legitimate services should not request these by email."))
    if re.search(r"(gift card|wire transfer|upi|bank transfer|payment required|invoice overdue)", text):
        findings.append(_finding("message.payment_pressure", 12, "The message pressures the recipient about money or payment."))
    return findings


def scan_attachments(attachments: Iterable[dict] | None) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in attachments or []:
        name = str(attachment.get("filename", "")).lower().strip()
        mime_type = str(attachment.get("mime_type", "")).lower()
        if not name:
            continue
        suffixes = re.findall(r"\.[a-z0-9]+", name)
        final_extension = suffixes[-1] if suffixes else ""
        if len(suffixes) >= 2 and final_extension in EXECUTABLE_EXTENSIONS:
            findings.append(_finding("attachment.double_extension", 40, f"Attachment '{name}' hides an executable/script behind a second extension."))
        elif final_extension in EXECUTABLE_EXTENSIONS:
            findings.append(_finding("attachment.executable", 25, f"Attachment '{name}' is an executable or script file."))
        elif final_extension in MACRO_EXTENSIONS:
            findings.append(_finding("attachment.macro_enabled", 18, f"Attachment '{name}' is macro-enabled and may run embedded code."))
        elif final_extension in ARCHIVE_EXTENSIONS:
            findings.append(_finding("attachment.archive", 8, f"Attachment '{name}' is an archive; inspect its contents before opening."))
        if "application/x-msdownload" in mime_type:
            findings.append(_finding("attachment.executable_mime", 25, f"Attachment '{name}' is declared as an executable file."))
    return findings


def scan_call_transcript(transcript: str) -> list[Finding]:
    """Analyzes real-time live phone call transcripts for high-risk vishing, digital arrest, and extortion."""
    text = (transcript or "").lower()
    findings: list[Finding] = []
    if not text:
        return findings

    # Digital Arrest / Law Enforcement Extortion
    if re.search(r"(cbi|police|narcotics|customs|cyber crime cell|arrest warrant|money laundering|fir lodged|supreme court|court order)", text):
        findings.append(_finding("call.digital_arrest", 45, "Caller claims to represent Police/CBI/Law Enforcement alleging criminal charges. Real police never conduct interrogations or demand settlements over phone calls."))

    # Remote Screen Share Traps
    if re.search(r"(anydesk|teamviewer|rustdesk|quicksupport|screen share|share screen|download app from play store to verify)", text):
        findings.append(_finding("call.screen_share_trap", 40, "Caller is instructing you to install screen-sharing software (AnyDesk/TeamViewer). This allows attackers to view your screen and steal banking OTPs."))

    # OTP / PIN / Banking Credential Interception
    if re.search(r"(read (the )?otp|tell (me )?(the )?otp|share (the )?6.digit code|enter pin|atm pin|cvv number|verify debit card)", text):
        findings.append(_finding("call.otp_pin_extraction", 35, "Caller is demanding an OTP, PIN, or CVV. Legitimate banks and support agents NEVER ask for your OTP or PIN."))

    # Utility Disconnection Threats
    if re.search(r"(electricity (will be )?disconnect|power (will be )?cut|bill unpaid|call this electricity officer|pay 10 rupees to verify)", text):
        findings.append(_finding("call.electricity_scam", 30, "Caller is using electricity disconnection threats to force immediate payments."))

    # Secrecy & Isolation Coercion
    if re.search(r"(do not disconnect|do not tell (anyone|family|bank)|stay on line|lock your room|confidential investigation)", text):
        findings.append(_finding("call.secrecy_coercion", 25, "Caller is demanding secrecy or isolation to prevent you from consulting family or your bank."))

    return findings


def call_groq_ai_scan(sender: str, subject: str, body: str, groq_key_override: str = "") -> dict | None:
    """Uses Groq Llama 3.1 AI model to perform deep multi-vector AI threat reasoning."""
    api_key = groq_key_override or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    system_prompt = (
        "You are an expert AI Cyber Threat Analyst inspecting suspicious emails, links, file metadata, messages, and phone call transcripts for ShieldSense. "
        "Analyze the input across all vector possibilities: phishing, brand impersonation, urgency pressure, fake login URLs, credential harvesting, dangerous file extensions, digital arrest, AnyDesk screen takeover, or scams.\n"
        "Return a raw JSON object with this exact schema:\n"
        "{\n"
        '  "llm_score": 0-100,\n'
        '  "llm_verdict": "dangerous" | "suspicious" | "low_risk",\n'
        '  "llm_reasoning": "A concise 1-2 sentence explanation of why this content is suspicious or safe.",\n'
        '  "findings": ["finding 1 explanation"],\n'
        '  "hinglish": {\n'
        '    "yeh_kya_hai": "Simple conversational Hinglish breakdown of what this threat is.",\n'
        '    "kya_nuksaan": "What damage can happen in Hinglish (e.g. Bank OTP theft, AnyDesk takeover).",\n'
        '    "kya_karna_hai": "Exact immediate advice in Hinglish (e.g. Link mat kholo, Phone cut karo)."\n'
        '  },\n'
        '  "scammer_forensics": {\n'
        '    "immediate_ask": "What the scammer wants right now (e.g. OTP, ₹20000 transfer, AnyDesk code)",\n'
        '    "psychological_trap": "Why they use this mind game (e.g. Police fear shutdown, evening deadline panic)",\n'
        '    "scammer_profit": "Where money/data goes (e.g. Rented mule account to Crypto laundering in 6 mins)"\n'
        '  }\n'
        "}"
    )
    user_prompt = f"Sender: {sender}\nSubject: {subject}\nBody/Text/URL/File/Transcript:\n{body}"
    candidate_models = ["groq/compound-mini", "groq/compound", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]
    for model in candidate_models:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=6)
            if response.status_code == 200:
                content = response.json()["choices"][0]["message"]["content"].strip()
                return json.loads(content)
        except Exception as e:
            print(f"Groq AI Scan Warning for {model}: {e}")
    return None


def scan_email(
    sender: str,
    subject: str,
    body: str,
    reply_to: str = "",
    attachments: Iterable[dict] | None = None,
    groq_key_override: str = "",
) -> dict:
    findings = scan_sender(sender, reply_to) + scan_message(subject, body) + scan_attachments(attachments) + scan_call_transcript(f"{subject}\n{body}")
    for url in extract_urls(f"{subject}\n{body}"):
        findings.extend(scan_url(url))

    # Also detect if body is a filename directly
    if not attachments and re.search(r"\.[a-z0-9]{2,5}$", body.strip().lower()):
        findings.extend(scan_attachments([{"filename": body.strip()}]))

    groq_res = call_groq_ai_scan(sender, subject, body, groq_key_override=groq_key_override)
    groq_hinglish = None
    groq_forensics = None

    if groq_res and isinstance(groq_res, dict):
        reasoning = groq_res.get("llm_reasoning", "AI intent analysis evaluated potential threat patterns.")
        findings.append(_finding("llm.groq_ai_intent", 0, f"AI Intelligence Model: {reasoning}"))

        for extra_finding in groq_res.get("findings", []):
            if extra_finding:
                findings.append(_finding("llm.groq_finding", 0, f"AI Threat Indicator: {extra_finding}"))
        groq_hinglish = groq_res.get("hinglish")
        groq_forensics = groq_res.get("scammer_forensics")

    deduplicated: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.code, finding.explanation)
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)

    score = min(100, sum(finding.score for finding in deduplicated))
    if score >= 60:
        verdict, recommendation = "dangerous", "review_quarantine"
    elif score >= 30:
        verdict, recommendation = "suspicious", "warn_verify"
    else:
        verdict, recommendation = "low_risk", "allow_with_caution"

    return {
        "score": score,
        "verdict": verdict,
        "recommendation": recommendation,
        "findings": [asdict(finding) for finding in deduplicated],
        "summary": _summary(verdict, deduplicated),
        "bilingual_hinglish": _generate_hinglish_summary(verdict, deduplicated, groq_hinglish),
        "scammer_forensics": _generate_scammer_forensics(verdict, deduplicated, groq_forensics),
        "ai_powered": bool(groq_res),
    }


def _summary(verdict: str, findings: list[Finding]) -> str:
    if verdict == "low_risk":
        return "No high-risk indicators were found. This is not a guarantee of safety."
    strongest = max(findings, key=lambda finding: finding.score)
    prefix = "Dangerous" if verdict == "dangerous" else "Suspicious"
    return f"{prefix}: {strongest.explanation}"


def _generate_hinglish_summary(verdict: str, findings: list[Finding], groq_hinglish: dict | None) -> dict:
    if groq_hinglish and isinstance(groq_hinglish, dict) and groq_hinglish.get("yeh_kya_hai"):
        return groq_hinglish
    if verdict == "low_risk":
        return {
            "yeh_kya_hai": "Yeh message authentic lag raha hai. Koi direct scam ya fake link indicators nahi mile.",
            "kya_nuksaan": "Filhaal koi immediate threat nahi hai, par personal info verify karke hi share karein.",
            "kya_karna_hai": "Safe to proceed, par kisi unknown person ko OTP ya password share na karein."
        }
    if verdict == "dangerous":
        return {
            "yeh_kya_hai": "Yeh message official brand ya police ban kar fake link aur dar ka pressure use kar raha hai.",
            "kya_nuksaan": "Aapka bank password, OTP, ya device access chori ho sakta hai.",
            "kya_karna_hai": "Link par click mat karo aur call disconnect karo. Safe Review mein move karo."
        }
    return {
        "yeh_kya_hai": "Is message mein kuch suspicious signals aur urgency elements mile hain.",
        "kya_nuksaan": "Unknown link se fake portal par redirect hone ka risk ho sakta hai.",
        "kya_karna_hai": "Sender ki identity official channel se verify karein aur savdhani bartein."
    }


def _generate_scammer_forensics(verdict: str, findings: list[Finding], groq_forensics: dict | None) -> dict:
    if groq_forensics and isinstance(groq_forensics, dict) and groq_forensics.get("immediate_ask"):
        return groq_forensics
    if verdict == "dangerous":
        return {
            "immediate_ask": "Immediate OTP, fake KYC verification, or urgent money transfer to a fake clearing account.",
            "psychological_trap": "Using fear of legal arrest or urgent service cutoff to disable rational verification.",
            "scammer_profit": "Funds are rapidly siphoned through rented mule bank accounts and laundered to untraceable crypto within minutes."
        }
    elif verdict == "suspicious":
        return {
            "immediate_ask": "Clicking an unverified link or replying to confirm active contact details.",
            "psychological_trap": "Curiosity and artificial urgency to trigger an impulsive click before checking.",
            "scammer_profit": "Harvesting validated phone/email lists for targeted follow-up fraud."
        }
    return {
        "immediate_ask": "Standard informational communication or genuine inquiry.",
        "psychological_trap": "None observed; normal business or personal dialogue.",
        "scammer_profit": "No malicious financial exploitation vectors detected."
    }

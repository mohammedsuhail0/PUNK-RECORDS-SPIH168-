"""Deterministic + Groq LLM AI security checks for ShieldSense.

This module inspects supplied text, URLs, and metadata.
It integrates Groq (Llama 3.1) AI intent analysis whenever GROQ_API_KEY is available.
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


def call_groq_ai_scan(sender: str, subject: str, body: str) -> dict | None:
    """Uses Groq Llama 3.1 AI model to perform deep LLM threat intent reasoning."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    system_prompt = (
        "You are an expert AI Cyber Threat Analyst inspecting suspicious emails, links, and messages. "
        "Analyze the input for phishing, brand impersonation, urgency pressure, fake login domains, credential harvesting, or scams. "
        "Return a raw JSON object with this exact schema:\n"
        "{\n"
        '  "llm_score": 0-100,\n'
        '  "llm_verdict": "dangerous" | "suspicious" | "low_risk",\n'
        '  "llm_reasoning": "A concise 1-2 sentence explanation of why this content is suspicious or safe.",\n'
        '  "findings": ["finding 1 explanation"]\n'
        "}"
    )
    user_prompt = f"Sender: {sender}\nSubject: {subject}\nBody/Text:\n{body}"
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"].strip()
            return json.loads(content)
    except Exception as e:
        print(f"Groq AI Scan Warning: {e}")
    return None


def scan_email(sender: str, subject: str, body: str, reply_to: str = "", attachments: Iterable[dict] | None = None) -> dict:
    findings = scan_sender(sender, reply_to) + scan_message(subject, body) + scan_attachments(attachments)
    for url in extract_urls(f"{subject}\n{body}"):
        findings.extend(scan_url(url))

    groq_res = call_groq_ai_scan(sender, subject, body)
    if groq_res and isinstance(groq_res, dict):
        llm_score = int(groq_res.get("llm_score", 0))
        reasoning = groq_res.get("llm_reasoning", "AI intent analysis evaluated potential phishing patterns.")
        findings.append(_finding("llm.groq_ai_intent", llm_score, f"AI Intelligence Model (Groq Llama 3.1): {reasoning}"))

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
    }


def _summary(verdict: str, findings: list[Finding]) -> str:
    if verdict == "low_risk":
        return "No high-risk indicators were found. This is not a guarantee of safety."
    strongest = max(findings, key=lambda finding: finding.score)
    prefix = "Dangerous" if verdict == "dangerous" else "Suspicious"
    return f"{prefix}: {strongest.explanation}"

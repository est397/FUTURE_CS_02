#!/usr/bin/env python3
"""Educational phishing triage tool. Does not open links or attachments."""
import re
import sys
from pathlib import Path

URGENT = [
    "urgent", "immediately", "account will be closed", "act now",
    "within 24 hours", "suspended", "final warning"
]
CREDENTIALS = [
    "password", "one-time code", "verification code", " otp ",
    "sign in to verify", "confirm your account"
]
PAYMENT = ["wire transfer", "gift card", "payment details", "bank details"]
SHORTENERS = ["bit.ly/", "tinyurl.com/", "t.co/", "is.gd/"]
RISKY_EXTENSIONS = [".exe", ".scr", ".js", ".bat", ".cmd", ".vbs", ".iso"]

def analyze(text: str):
    lower = text.lower()
    findings = []

    for phrase in URGENT:
        if phrase in lower:
            findings.append(("Urgency or pressure", f"Message contains: {phrase!r}"))
    for phrase in CREDENTIALS:
        if phrase in lower:
            findings.append(("Credential request", f"Message refers to: {phrase.strip()!r}"))
    for phrase in PAYMENT:
        if phrase in lower:
            findings.append(("Payment request", f"Message refers to: {phrase!r}"))

    urls = re.findall(r"https?://[^\s<>()]+", text, flags=re.I)
    for url in urls:
        if any(shortener in url.lower() for shortener in SHORTENERS):
            findings.append(("Shortened link", f"Review the destination independently: {url}"))
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            findings.append(("Unusual URL format", "The URL authority contains an @ symbol."))

    for ext in RISKY_EXTENSIONS:
        if ext in lower:
            findings.append(("Potentially risky attachment", f"Filename/text mentions {ext}."))

    categories = {item[0] for item in findings}
    if "Credential request" in categories or "Payment request" in categories:
        verdict = "PHISHING (high suspicion)"
    elif len(findings) >= 2:
        verdict = "SUSPICIOUS"
    elif findings:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NO OBVIOUS INDICATORS FOUND — NOT PROOF OF SAFETY"

    return verdict, findings, urls

def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    else:
        print("Paste fictional/sample email text. Finish with Ctrl-D (Linux/macOS) or Ctrl-Z then Enter (Windows):")
        text = sys.stdin.read()

    verdict, findings, urls = analyze(text)
    print("\nClassification:", verdict)
    if findings:
        print("\nIndicators:")
        for category, detail in findings:
            print(f"- {category}: {detail}")
    else:
        print("\nNo indicators matched the simple rules.")

    if urls:
        print("\nURLs found (NOT opened):")
        for url in urls:
            print("-", url)

    print("\nSafety advice:")
    print("- Do not click unexpected links or open unexpected attachments.")
    print("- Verify requests through a known, separate contact channel.")
    print("- Never share passwords or one-time verification codes.")
    print("- Report suspicious messages to the organization's IT/security team.")

if __name__ == "__main__":
    main()

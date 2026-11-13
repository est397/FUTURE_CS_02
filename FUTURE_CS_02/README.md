# FUTURE_CS_02 — Phishing Email Detection & Awareness System

## Objective
Classify a sample email as **Safe**, **Suspicious**, or **Phishing**, explain the indicators in plain language, and provide prevention guidance.

## Safety and limitations
This is a lightweight educational triage helper, not a production email-security gateway. It does not open links, download attachments, or send email. A result is a warning signal, not proof. Never paste real passwords, private messages, or personal information into a public repository.

## Run
Requires Python 3.9+ and no third-party packages.

```bash
python phishing_checker.py
```

Or analyze a text file:
```bash
python phishing_checker.py sample_email.txt
```

## What it checks
- Urgent or threatening language
- Requests for passwords, payment, or verification codes
- Sender/display-name mismatch indicators when manually provided
- URL text that may use deceptive wording or an unfamiliar domain
- Suspicious attachment extensions mentioned in the message

The checker deliberately does not visit links or inspect files.

## Project files
- `phishing_checker.py` — local rule-based educational checker
- `samples/` — fictional examples
- `report/phishing-awareness-report.md` — report template

## Improvements to consider
Add a reviewed public dataset, a safe URL reputation source, header parsing, unit tests, and multilingual awareness material. Clearly document false positives and false negatives.

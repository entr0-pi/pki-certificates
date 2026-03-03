#!/usr/bin/env python3
"""
Notify about expiring certificates via email, webhook, or log output.

Environment variables:
  NOTIFY_METHOD=email|webhook|log   (default: log)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_TO
  WEBHOOK_URL
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path
from urllib import request


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

import db  # noqa: E402


def _format_lines(certs: list[dict]) -> list[str]:
    lines = []
    for cert in certs:
        lines.append(
            f"- {cert.get('cert_name')} ({cert.get('cert_type')}) | "
            f"Org: {cert.get('org_name')} (ID {cert.get('org_id')}) | "
            f"Expires: {cert.get('not_after')} | "
            f"Days remaining: {cert.get('days_remaining')}"
        )
    return lines


def send_email(certs: list[dict]) -> None:
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    recipients = [x.strip() for x in os.environ.get("EMAIL_TO", "").split(",") if x.strip()]

    if not smtp_host or not recipients:
        raise RuntimeError("Missing SMTP_HOST or EMAIL_TO for email notifications.")

    body = "Certificates expiring soon:\n\n" + "\n".join(_format_lines(certs))
    msg = EmailMessage()
    msg["Subject"] = f"[PKI] {len(certs)} certificate(s) expiring soon"
    msg["From"] = smtp_user or "pki-notify@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls(context=context)
        if smtp_user:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def send_webhook(certs: list[dict]) -> None:
    webhook_url = os.environ.get("WEBHOOK_URL", "").strip()
    if not webhook_url:
        raise RuntimeError("Missing WEBHOOK_URL for webhook notifications.")

    payload = {
        "text": f"{len(certs)} certificate(s) expiring soon",
        "certificates": certs,
    }
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=20) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"Webhook failed with status {resp.status}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Notify on expiring certificates.")
    parser.add_argument("--days", type=int, default=30, help="Window in days (default: 30)")
    parser.add_argument("--dry-run", action="store_true", help="Print notifications without sending")
    args = parser.parse_args()

    certs = db.get_expiring_certificates(days_ahead=args.days)
    if not certs:
        print("No expiring certificates in the selected window.")
        return 0

    method = os.environ.get("NOTIFY_METHOD", "log").strip().lower()

    print(f"Found {len(certs)} expiring certificate(s) in next {args.days} days.")
    for line in _format_lines(certs):
        print(line)

    if args.dry_run:
        print("Dry-run mode: no notification sent.")
        return 0

    if method == "email":
        send_email(certs)
        print("Email notification sent.")
        return 0
    if method == "webhook":
        send_webhook(certs)
        print("Webhook notification sent.")
        return 0
    if method == "log":
        print("Log mode selected: output only.")
        return 0

    raise RuntimeError("NOTIFY_METHOD must be one of: email, webhook, log")


if __name__ == "__main__":
    raise SystemExit(main())

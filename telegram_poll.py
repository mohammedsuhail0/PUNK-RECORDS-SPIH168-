"""Local Telegram Bot Long-Polling Runner for ShieldSense.

Allows testing Telegram bot commands and alerts locally without deploying a public webhook.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import requests

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from api.telegram_webhook import (
    TELEGRAM_BOT_TOKEN,
    handle_callback_query_internal,
    handle_message_internal,
)

# Load local .env if present
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") or TELEGRAM_BOT_TOKEN


def delete_webhook():
    """Clears any existing webhook so long-polling works."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook"
    try:
        res = requests.get(url, timeout=10)
        print(f"Cleared existing Telegram webhook: {res.json()}")
    except Exception as e:
        print(f"Warning clearing webhook: {e}")


def start_polling():
    """Polls Telegram getUpdates API in a loop."""
    if not BOT_TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN is missing in .env")
        return

    delete_webhook()
    print("🤖 ShieldSense Telegram Bot Polling Agent Started!")
    print("Press CTRL+C to stop.\n")

    offset = 0
    while True:
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            params = {"offset": offset, "timeout": 10}
            resp = requests.get(url, params=params, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("result", []):
                    offset = result["update_id"] + 1

                    if "callback_query" in result:
                        handle_callback_query_internal(result["callback_query"])
                    elif "message" in result:
                        handle_message_internal(result["message"])

            time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping Telegram Polling Bot...")
            break
        except Exception as e:
            print(f"Polling error: {e}")
            time.sleep(3)


if __name__ == "__main__":
    start_polling()

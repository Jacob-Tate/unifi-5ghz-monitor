#!/usr/bin/env python3
import os
import requests
from dotenv import load_dotenv

load_dotenv()

token = os.getenv('PUSHOVER_TOKEN')
user = os.getenv('PUSHOVER_USER')

if not token or not user:
    print("ERROR: PUSHOVER_TOKEN or PUSHOVER_USER not set in .env")
    exit(1)

print(f"Sending test notification...")
print(f"  Token: {token[:4]}...{token[-4:]}")
print(f"  User:  {user[:4]}...{user[-4:]}")

response = requests.post("https://api.pushover.net/1/messages.json", data={
    "token": token,
    "user": user,
    "title": "UniFi Monitor Test",
    "message": "Pushover test notification from test_pushover.py",
    "priority": 0
}, timeout=10)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

import gzip
import hashlib
import hmac
import json
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import cookies_pb2

AES_KEY = b"1234567890abcdef"
AES_IV = b"abcdef1234567890"
SECRET_KEY = b"CookiesService"
TOKEN = "CookiesService"


def encrypt_and_compress(pb_msg) -> bytes:
    raw = pb_msg.SerializeToString()
    gz = gzip.compress(raw)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    ct = cipher.encrypt(pad(gz, AES.block_size))
    return ct


def generate_headers(body: bytes):
    timestamp = str(int(time.time()))
    signature = hmac.new(SECRET_KEY, body + timestamp.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Timestamp": timestamp,
        "X-Signature": signature,
        "X-Token": TOKEN
    }


def upload_automation_cookies():
    with open("cookies/automation_cookies.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    msg = getattr(cookies_pb2, "AutomationCookies")()
    for item in data:
        c = msg.cookies.add()
        c.name = item["name"]
        c.value = item["value"]
        c.domain = item["domain"]

    data = encrypt_and_compress(msg)
    headers = generate_headers(data)

    response = requests.post(
        "http://127.0.0.1:7452/upload_automation_cookies",
        data=data,
        headers=headers
    )
    print("Automation response:", response.status_code, response.json())


def upload_protocol_cookies():
    with open("cookies/protocol_cookies.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    msg = getattr(cookies_pb2, "ProtocolCookies")()
    for k, v in data.items():
        msg.cookies[k] = v

    data = encrypt_and_compress(msg)
    headers = generate_headers(data)

    response = requests.post(
        "http://127.0.0.1:7452/upload_protocol_cookies",
        data=data,
        headers=headers
    )
    print("Protocol response:", response.status_code, response.json())


if __name__ == '__main__':
    upload_automation_cookies()
    upload_protocol_cookies()

import gzip
import hashlib
import hmac
import json
import os.path
import time

import uvicorn
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

import cookies_pb2

app = FastAPI(title="CookiesService")

AES_KEY = b"1234567890abcdef"
AES_IV = b"abcdef1234567890"
SECRET_KEY = b"CookiesService"
TOKEN = "CookiesService"
TIME_WINDOW = 60
BASE_DIR_PATH = os.path.dirname(os.path.abspath(__file__))


def verify_headers(timestamp: str, signature: str, token: str, body: bytes):
    if token != TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        ts = int(timestamp)
    except:
        raise HTTPException(status_code=400, detail="Invalid timestamp")
    now = int(time.time())
    if abs(now - ts) > TIME_WINDOW:
        raise HTTPException(status_code=400, detail="Timestamp expired")

    hm = hmac.new(SECRET_KEY, body + timestamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(hm, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")


def decrypt_body(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted


def decompress_body(data: bytes) -> bytes:
    return gzip.decompress(data)


async def handle_request(request: Request):
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")
    token = request.headers.get("X-Token")

    body = await request.body()
    verify_headers(timestamp, signature, token, body)

    decrypted = decrypt_body(body)

    decompressed = decompress_body(decrypted)
    return decompressed


@app.post("/upload_automation_cookies")
async def upload_automation_cookies(request: Request):
    try:
        decompressed = await handle_request(request)
        msg = getattr(cookies_pb2, "AutomationCookies")()
        msg.ParseFromString(decompressed)

        automation_cookies = [dict(name=c.name, value=c.name, domain=c.domain) for c in msg.cookies]

        automation_cookies_file_path = os.path.join(BASE_DIR_PATH, "cookies", "automation_cookies.json")
        os.makedirs(os.path.dirname(automation_cookies_file_path), exist_ok=True)
        with open(automation_cookies_file_path, "w") as f:
            json.dump(automation_cookies, f)

        return JSONResponse({"status": "ok"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload_protocol_cookies")
async def upload_protocol_cookies(request: Request):
    try:
        decompressed = await handle_request(request)
        msg = getattr(cookies_pb2, "ProtocolCookies")()
        msg.ParseFromString(decompressed)

        protocol_cookies = {k: v for k, v in msg.cookies.items()}

        protocol_cookies_file_path = os.path.join(BASE_DIR_PATH, "cookies", "protocol_cookies.json")
        os.makedirs(os.path.dirname(protocol_cookies_file_path), exist_ok=True)
        with open(protocol_cookies_file_path, "w") as f:
            json.dump(protocol_cookies, f)

        return JSONResponse({"status": "ok"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=7452, log_level="info")

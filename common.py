import gzip
import hashlib
import hmac
import json
import os
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from fastapi import HTTPException


class Common:
    def __init__(
            self,
            aes_key: bytes = b"1234567890abcdef",
            aes_iv: bytes = b"abcdef1234567890",
            secret_key: bytes = b"CookiesService",
            token: str = "CookiesService",
            expiry_seconds: int = 60
    ):
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.secret_key = secret_key
        self.token = token
        self.expiry_seconds = expiry_seconds

    def compress_and_encrypt(self, data: bytes) -> bytes:
        gz = gzip.compress(data)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        return cipher.encrypt(pad(gz, AES.block_size))

    def decrypt_and_decompress(self, data: bytes) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        return gzip.decompress(decrypted)

    def verify_headers(self, timestamp: str, signature: str, token: str, body: bytes):
        try:
            ts = int(timestamp)
        except Exception:
            raise HTTPException(400, "Invalid timestamp")

        hm = hmac.new(self.secret_key, body + timestamp.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(hm, signature):
            raise HTTPException(401, "Invalid signature")

        if token != self.token:
            raise HTTPException(401, "Invalid token")

        now = int(time.time())

        if abs(now - ts) > self.expiry_seconds:
            raise HTTPException(400, "Timestamp expired")

    def save_json(self, data: dict, file_path: str):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_json(self, file_path: str) -> dict:
        if not os.path.exists(file_path):
            raise HTTPException(404, f"{file_path} not found")

        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

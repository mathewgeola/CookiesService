import gzip
import hashlib
import hmac
import os
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from fastapi import HTTPException
from google.protobuf.message import Message


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

    def verify_headers(self, timestamp: str, signature: str, token: str, body: bytes) -> None:
        try:
            ts = int(timestamp)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid timestamp")

        hm = hmac.new(self.secret_key, body + timestamp.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(hm, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

        if token != self.token:
            raise HTTPException(status_code=401, detail="Invalid token")

        now = int(time.time())
        if abs(now - ts) > self.expiry_seconds:
            raise HTTPException(status_code=400, detail="Timestamp expired")

    def save(self, msg: Message, file_path: str) -> None:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(msg.SerializeToString())

    def load(self, file_path: str) -> bytes:
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"{file_path} not found")
        with open(file_path, "rb") as f:
            return f.read()

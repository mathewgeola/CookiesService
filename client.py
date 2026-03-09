import hashlib
import hmac
import json
import os
import time

import requests

from common import Common


class Client:
    def __init__(self, host="localhost", port=7452):
        self.host_port = f"{host}:{port}"

        self.common = Common()

    def generate_headers(self, body: bytes):
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self.common.secret_key,
            body + timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        return {
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "X-Token": self.common.token
        }

    def upload_automation_cookies(self, key: str, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        payload = {
            "key": key,
            "value": data
        }
        body = self.common.compress_and_encrypt(
            json.dumps(payload).encode()
        )
        headers = self.generate_headers(body)

        return requests.post(
            f"http://{self.host_port}/upload_automation_cookies",
            data=body,
            headers=headers
        )

    def upload_protocol_cookies(self, key: str, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        payload = {
            "key": key,
            "value": data
        }
        body = self.common.compress_and_encrypt(
            json.dumps(payload).encode()
        )
        headers = self.generate_headers(body)
        return requests.post(
            f"http://{self.host_port}/upload_protocol_cookies",
            data=body,
            headers=headers
        )

    def download_automation_cookies(self, key: str, file_path=None):
        r = requests.get(
            f"http://{self.host_port}/download_automation_cookies/{key}"
        )
        r.raise_for_status()

        raw = self.common.decrypt_and_decompress(r.content)
        data = json.loads(raw)

        if file_path:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        return data

    def download_protocol_cookies(self, key: str, file_path=None):
        r = requests.get(
            f"http://{self.host_port}/download_protocol_cookies/{key}"
        )
        r.raise_for_status()

        raw = self.common.decrypt_and_decompress(r.content)
        data = json.loads(raw)

        if file_path:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        return data


if __name__ == "__main__":
    client = Client()

    client.upload_automation_cookies(
        "test",
        "client/cookies/test/automation_cookies.json"
    )
    client.upload_protocol_cookies(
        "test",
        "client/cookies/test/protocol_cookies.json"
    )

    print(client.download_automation_cookies("test"))
    print(client.download_protocol_cookies("test"))

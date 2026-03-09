import hashlib
import hmac
import json
import time

import requests

import cookies_pb2
from common import Common


class Client:
    def __init__(self, host: str = "localhost", port: int = 7452):
        self.host_port = f"{host}:{port}"
        self.common = Common()

    def generate_headers(self, body: bytes) -> dict:
        timestamp = str(int(time.time()))
        signature = hmac.new(self.common.secret_key, body + timestamp.encode(), hashlib.sha256).hexdigest()
        return {
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "X-Token": self.common.token
        }

    def upload_automation_cookies(self, key: str, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        msg = cookies_pb2.AutomationCookies()
        msg.key = key
        for item in data:
            c = msg.value.add()
            c.name = item["name"]
            c.value = item["value"]
            c.domain = item["domain"]

        body = self.common.compress_and_encrypt(msg.SerializeToString())
        headers = self.generate_headers(body)
        return requests.post(f"http://{self.host_port}/upload_automation_cookies", data=body, headers=headers)

    def upload_protocol_cookies(self, key: str, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        msg = cookies_pb2.ProtocolCookies()
        msg.key = key
        for k, v in data.items():
            msg.value[k] = v

        body = self.common.compress_and_encrypt(msg.SerializeToString())
        headers = self.generate_headers(body)
        return requests.post(f"http://{self.host_port}/upload_protocol_cookies", data=body, headers=headers)

    def download_automation_cookies(self, key: str) -> cookies_pb2.AutomationCookies:
        r = requests.get(f"http://{self.host_port}/download_automation_cookies/{key}")
        r.raise_for_status()
        raw = self.common.decrypt_and_decompress(r.content)
        msg = cookies_pb2.AutomationCookies()
        msg.ParseFromString(raw)
        return msg

    def download_protocol_cookies(self, key: str) -> cookies_pb2.ProtocolCookies:
        r = requests.get(f"http://{self.host_port}/download_protocol_cookies/{key}")
        r.raise_for_status()
        raw = self.common.decrypt_and_decompress(r.content)
        msg = cookies_pb2.ProtocolCookies()
        msg.ParseFromString(raw)
        return msg


if __name__ == "__main__":
    client = Client()
    client.upload_automation_cookies("test", "client/cookies/test/automation_cookies.json")
    client.upload_protocol_cookies("test", "client/cookies/test/protocol_cookies.json")

    automation = client.download_automation_cookies("test")
    print([{"name": c.name, "value": c.value, "domain": c.domain} for c in automation.value])

    protocol = client.download_protocol_cookies("test")
    print(dict(protocol.value))

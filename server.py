import json
import os
import traceback

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response

from common import Common


class Server:
    def __init__(self, host="0.0.0.0", port=7452, server_dir="server"):
        self.app = FastAPI(title="CookiesService")

        self.host = host
        self.port = port

        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.SERVER_DIR = os.path.join(BASE_DIR, server_dir)

        self.common = Common()

        self._register_routes()

    def _register_routes(self):
        @self.app.post("/upload_automation_cookies")
        async def upload_automation_cookies(request: Request):
            try:
                data = await self.parse_request(request)
                key = data["key"]
                value = data["value"]
                file_path = os.path.join(
                    self.SERVER_DIR,
                    "cookies",
                    key,
                    "automation_cookies.json"
                )
                self.common.save_json(value, file_path)
                return {"status": "ok"}
            except Exception:
                traceback.print_exc()
                raise HTTPException(500, "Upload failed")

        @self.app.post("/upload_protocol_cookies")
        async def upload_protocol_cookies(request: Request):
            try:
                data = await self.parse_request(request)
                key = data["key"]
                value = data["value"]
                file_path = os.path.join(
                    self.SERVER_DIR,
                    "cookies",
                    key,
                    "protocol_cookies.json"
                )
                self.common.save_json(value, file_path)
                return {"status": "ok"}
            except Exception:
                traceback.print_exc()
                raise HTTPException(500, "Upload failed")

        @self.app.get("/download_automation_cookies/{key}")
        async def download_automation_cookies(key: str):
            try:
                file_path = os.path.join(
                    self.SERVER_DIR,
                    "cookies",
                    key,
                    "automation_cookies.json"
                )
                data = self.common.load_json(file_path)
                raw = json.dumps(data).encode()
                encrypted = self.common.compress_and_encrypt(raw)
                return Response(
                    content=encrypted,
                    media_type="application/octet-stream"
                )
            except Exception:
                traceback.print_exc()
                raise HTTPException(500, "Download failed")

        @self.app.get("/download_protocol_cookies/{key}")
        async def download_protocol_cookies(key: str):
            try:
                file_path = os.path.join(
                    self.SERVER_DIR,
                    "cookies",
                    key,
                    "protocol_cookies.json"
                )
                data = self.common.load_json(file_path)
                raw = json.dumps(data).encode()
                encrypted = self.common.compress_and_encrypt(raw)
                return Response(
                    content=encrypted,
                    media_type="application/octet-stream"
                )
            except Exception:
                traceback.print_exc()
                raise HTTPException(500, "Download failed")

    async def parse_request(self, request: Request):
        timestamp = request.headers.get("X-Timestamp")
        signature = request.headers.get("X-Signature")
        token = request.headers.get("X-Token")
        body = await request.body()
        self.common.verify_headers(timestamp, signature, token, body)
        raw = self.common.decrypt_and_decompress(body)
        return json.loads(raw)

    def run(self):
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )


if __name__ == "__main__":
    Server().run()

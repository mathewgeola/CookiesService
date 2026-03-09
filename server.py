import os
import traceback

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response

import cookies_pb2
from common import Common


class Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 7452, server_dir: str = "server"):
        self.app = FastAPI(title="CookiesService")
        self.common = Common()
        self.host = host
        self.port = port
        self.BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.SERVER_DIR = os.path.join(self.BASE_DIR, server_dir)
        self._register_routes()

    def _register_routes(self):
        @self.app.post("/upload_automation_cookies")
        async def upload_automation_cookies(request: Request):
            try:
                msg = await self.parse_request(request, "AutomationCookies")
                file_path = os.path.join(self.SERVER_DIR, "cookies", msg.key, "automation_cookies.pb")
                self.common.save(msg, file_path)
                return {"status": "ok"}
            except Exception:
                traceback.print_exc()
                raise HTTPException(status_code=500, detail="Upload failed")

        @self.app.post("/upload_protocol_cookies")
        async def upload_protocol_cookies(request: Request):
            try:
                msg = await self.parse_request(request, "ProtocolCookies")
                file_path = os.path.join(self.SERVER_DIR, "cookies", msg.key, "protocol_cookies.pb")
                self.common.save(msg, file_path)
                return {"status": "ok"}
            except Exception:
                traceback.print_exc()
                raise HTTPException(status_code=500, detail="Upload failed")

        @self.app.get("/download_automation_cookies/{key}")
        async def download_automation_cookies(key: str):
            try:
                file_path = os.path.join(self.SERVER_DIR, "cookies", key, "automation_cookies.pb")
                raw = self.common.load(file_path)
                encrypted = self.common.compress_and_encrypt(raw)
                return Response(content=encrypted, media_type="application/octet-stream")
            except Exception:
                traceback.print_exc()
                raise HTTPException(status_code=500, detail="Download failed")

        @self.app.get("/download_protocol_cookies/{key}")
        async def download_protocol_cookies(key: str):
            try:
                file_path = os.path.join(self.SERVER_DIR, "cookies", key, "protocol_cookies.pb")
                raw = self.common.load(file_path)
                encrypted = self.common.compress_and_encrypt(raw)
                return Response(content=encrypted, media_type="application/octet-stream")
            except Exception:
                traceback.print_exc()
                raise HTTPException(status_code=500, detail="Download failed")

    async def parse_request(self, request: Request, msg_name: str):
        timestamp = request.headers.get("X-Timestamp")
        signature = request.headers.get("X-Signature")
        token = request.headers.get("X-Token")
        body = await request.body()

        self.common.verify_headers(timestamp, signature, token, body)
        raw = self.common.decrypt_and_decompress(body)
        msg = getattr(cookies_pb2, msg_name)()
        msg.ParseFromString(raw)
        return msg

    def run(self):
        uvicorn.run(self.app, host=self.host, port=self.port, log_level="info")


if __name__ == "__main__":
    server = Server()
    server.run()

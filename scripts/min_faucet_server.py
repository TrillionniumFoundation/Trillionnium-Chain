#!/usr/bin/env python3
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RPC_WORKDIR = os.path.join(ROOT, "trillionnium")

HOST = os.environ.get("FAUCET_HOST", "127.0.0.1")
PORT = int(os.environ.get("FAUCET_PORT", "8546"))
DEFAULT_AMOUNT = os.environ.get("FAUCET_DEFAULT_AMOUNT", "1000")


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, body: dict):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True, "service": "trnm-faucet", "version": 1})
            return
        self._json(404, {"ok": False, "code": "NOT_FOUND"})

    def do_POST(self):
        if self.path != "/faucet/request":
            self._json(404, {"ok": False, "code": "NOT_FOUND"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8")) if raw else {}
            address = data.get("address", "")
            amount = str(data.get("amount", DEFAULT_AMOUNT))
            if not address:
                self._json(400, {"ok": False, "code": "INVALID_ADDRESS", "message": "address required"})
                return

            cmd = [
                "cargo", "run", "-q", "-p", "trnm-rpc", "--",
                "faucet-request", "--address", address, "--amount", amount,
            ]
            out = subprocess.run(cmd, cwd=RPC_WORKDIR, capture_output=True, text=True)
            if out.returncode != 0:
                msg = (out.stderr or out.stdout or "faucet command failed").strip()
                self._json(400, {"ok": False, "code": "FAUCET_REQUEST_FAILED", "message": msg})
                return
            body = json.loads(out.stdout)
            self._json(200, body)
        except Exception as e:
            self._json(500, {"ok": False, "code": "INTERNAL", "message": str(e)})


if __name__ == "__main__":
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"[trnm-faucet] listening on http://{HOST}:{PORT}")
    httpd.serve_forever()

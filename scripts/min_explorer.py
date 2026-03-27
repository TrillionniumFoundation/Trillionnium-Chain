#!/usr/bin/env python3
"""TRNM minimal local explorer.

Pages:
- /healthz            -> liveness probe
- /address/<address>  -> balance / nonce / recent tx
- /tx/<tx_hash>       -> status / error
- /block/<height>     -> height / state_root

Data source (default):
- run/rpc/accounts.json
- run/rpc/txs.json
- run/node1.log, run/node2.log, run/node3.log, run/parallel-sanity.log
"""

from __future__ import annotations

import argparse
import html
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


def _safe_read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


class ExplorerData:
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.accounts_file = repo_root / "run/rpc/accounts.json"
        self.txs_file = repo_root / "run/rpc/txs.json"
        self.block_logs = [
            repo_root / "run/parallel-sanity.log",
            repo_root / "run/node1.log",
            repo_root / "run/node2.log",
            repo_root / "run/node3.log",
        ]

    def load_accounts(self) -> dict[str, Any]:
        raw = _safe_read_json(self.accounts_file, {})
        if isinstance(raw, dict):
            return raw
        return {}

    def load_txs(self) -> dict[str, Any]:
        raw = _safe_read_json(self.txs_file, {})
        if isinstance(raw, dict):
            return raw
        return {}

    def find_tx(self, tx_hash: str) -> tuple[str, dict[str, Any]] | None:
        txs = self.load_txs()
        rec = txs.get(tx_hash)
        if isinstance(rec, dict):
            return tx_hash, rec

        normalized = tx_hash.lower()
        for key, value in txs.items():
            if isinstance(key, str) and key.lower() == normalized and isinstance(value, dict):
                return key, value
        return None

    def load_blocks(self) -> dict[int, dict[str, Any]]:
        # keep latest occurrence for each height
        blocks: dict[int, dict[str, Any]] = {}
        pattern = re.compile(r"\[block\].*?height=(\d+).*?state_root=((?:0x)?[0-9a-fA-F]+)")
        for logf in self.block_logs:
            if not logf.exists():
                continue
            try:
                for line in logf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    m = pattern.search(line)
                    if not m:
                        continue
                    h = int(m.group(1))
                    blocks[h] = {
                        "height": h,
                        "state_root": m.group(2),
                        "raw": line.strip(),
                        "source": logf.name,
                    }
            except Exception:
                continue
        return blocks


def _layout(title: str, body: str) -> bytes:
    page = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; line-height: 1.45; }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .muted {{ color: #666; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 12px 14px; margin: 12px 0; }}
    input {{ padding: 6px 8px; width: min(640px, 95vw); }}
    button {{ padding: 6px 10px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #eee; text-align: left; padding: 8px 4px; vertical-align: top; }}
    .ok {{ color: #106b10; }} .bad {{ color: #a20000; }} .pending {{ color: #9b6a00; }}
    a {{ text-decoration: none; }} a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <h1>TRNM Minimal Explorer</h1>
  <p class=\"muted\">Local-only lightweight explorer</p>
  <div class=\"card\">
    <form action=\"/address\" method=\"get\">
      <label>Address:</label><br />
      <input name=\"q\" placeholder=\"trnm1...\" /> <button>Open</button>
    </form>
    <form action=\"/tx\" method=\"get\" style=\"margin-top:8px\">
      <label>Tx Hash:</label><br />
      <input name=\"q\" placeholder=\"0x...\" /> <button>Open</button>
    </form>
    <form action=\"/block\" method=\"get\" style=\"margin-top:8px\">
      <label>Block Height:</label><br />
      <input name=\"q\" placeholder=\"123\" /> <button>Open</button>
    </form>
  </div>
  {body}
</body>
</html>"""
    return page.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    data: ExplorerData

    def _send_html(self, code: int, title: str, body: str) -> None:
        out = _layout(title, body)
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        if path == "/":
            self._send_html(200, "Home", "<p>Use the forms above to open address / tx / block pages.</p>")
            return

        if path == "/healthz":
            out = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return

        if path == "/address":
            addr = (q.get("q") or [""])[0].strip()
            if not addr:
                self._send_html(400, "Address", "<p>Missing address query param <code>?q=...</code>.</p>")
                return
            self._render_address(addr)
            return

        if path.startswith("/address/"):
            self._render_address(unquote(path[len("/address/") :]))
            return

        if path == "/tx":
            txh = (q.get("q") or [""])[0].strip()
            if not txh:
                self._send_html(400, "Tx", "<p>Missing tx hash query param <code>?q=...</code>.</p>")
                return
            self._render_tx(txh)
            return

        if path.startswith("/tx/"):
            self._render_tx(unquote(path[len("/tx/") :]))
            return

        if path == "/block":
            raw = (q.get("q") or [""])[0].strip()
            if not raw:
                self._send_html(400, "Block", "<p>Missing block height query param <code>?q=...</code>.</p>")
                return
            self._render_block(raw)
            return

        if path.startswith("/block/"):
            self._render_block(unquote(path[len("/block/") :]))
            return

        self._send_html(404, "Not Found", "<p>Not found.</p>")

    def _render_address(self, addr: str) -> None:
        accounts = self.data.load_accounts()
        txs = self.data.load_txs()

        acc = accounts.get(addr)
        if not isinstance(acc, dict):
            self._send_html(
                404,
                f"Address {addr}",
                f"<h2>Address</h2><p><code>{html.escape(addr)}</code></p><p class='bad'>Account not found in run/rpc/accounts.json</p>",
            )
            return

        recent = []
        for tx_hash, rec in txs.items():
            if not isinstance(rec, dict):
                continue
            tx = rec.get("tx") if isinstance(rec.get("tx"), dict) else {}
            if tx.get("from") == addr or tx.get("to") == addr:
                recent.append(
                    {
                        "tx_hash": tx_hash,
                        "status": str(rec.get("status", "unknown")),
                        "error": rec.get("error"),
                        "from": tx.get("from"),
                        "to": tx.get("to"),
                        "amount": tx.get("amount"),
                        "nonce": tx.get("nonce"),
                        "updated": rec.get("updated_at_unix_ms", 0),
                    }
                )
        recent.sort(key=lambda x: int(x.get("updated") or 0), reverse=True)

        rows = []
        for r in recent[:20]:
            st = html.escape(r["status"])
            st_cls = "ok" if st == "committed" else ("bad" if st == "fail" else "pending")
            err = html.escape(str(r.get("error") or ""))
            rows.append(
                "<tr>"
                f"<td><a href='/tx/{html.escape(r['tx_hash'])}'><code>{html.escape(r['tx_hash'])}</code></a></td>"
                f"<td class='{st_cls}'>{st}</td>"
                f"<td><code>{html.escape(str(r.get('from') or ''))}</code> → <code>{html.escape(str(r.get('to') or ''))}</code></td>"
                f"<td>{html.escape(str(r.get('amount') or ''))}</td>"
                f"<td>{html.escape(str(r.get('nonce') or ''))}</td>"
                f"<td>{err}</td>"
                "</tr>"
            )

        empty_row = "<tr><td colspan='6' class='muted'>No tx found for this address.</td></tr>"
        rows_html = ''.join(rows) if rows else empty_row

        body = (
            f"<h2>Address</h2><p><code>{html.escape(addr)}</code></p>"
            f"<div class='card'><b>balance:</b> {html.escape(str(acc.get('balance')))}<br /><b>nonce:</b> {html.escape(str(acc.get('nonce')))}</div>"
            "<h3>Recent Transactions</h3>"
            "<table><thead><tr><th>tx_hash</th><th>status</th><th>from/to</th><th>amount</th><th>nonce</th><th>error</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table>"
        )
        self._send_html(200, f"Address {addr}", body)

    def _render_tx(self, txh: str) -> None:
        found = self.data.find_tx(txh)
        if not found:
            self._send_html(404, f"Tx {txh}", f"<h2>Tx</h2><p><code>{html.escape(txh)}</code></p><p class='bad'>Transaction not found in run/rpc/txs.json</p>")
            return

        resolved_txh, rec = found
        tx = rec.get("tx") if isinstance(rec.get("tx"), dict) else {}
        st = str(rec.get("status", "unknown"))
        st_cls = "ok" if st == "committed" else ("bad" if st == "fail" else "pending")
        lookup_note = ""
        if resolved_txh != txh:
            lookup_note = (
                "<p class='muted'>Resolved case-insensitive match to stored tx hash "
                f"<code>{html.escape(resolved_txh)}</code>.</p>"
            )
        body = (
            f"<h2>Transaction</h2><p><code>{html.escape(resolved_txh)}</code></p>"
            f"{lookup_note}"
            f"<div class='card'><b>status:</b> <span class='{st_cls}'>{html.escape(st)}</span><br />"
            f"<b>error:</b> {html.escape(str(rec.get('error') or ''))}</div>"
            "<h3>Detail</h3>"
            "<pre>" + html.escape(json.dumps(tx, ensure_ascii=False, indent=2)) + "</pre>"
        )
        self._send_html(200, f"Tx {txh}", body)

    def _render_block(self, raw_height: str) -> None:
        try:
            h = int(raw_height)
        except ValueError:
            self._send_html(400, "Block", f"<p class='bad'>Invalid height: <code>{html.escape(raw_height)}</code></p>")
            return

        blocks = self.data.load_blocks()
        b = blocks.get(h)
        if not b:
            latest_h = max(blocks.keys()) if blocks else None
            extra = f" Latest known height: <code>{latest_h}</code>." if latest_h is not None else ""
            self._send_html(404, f"Block {h}", f"<h2>Block</h2><p><code>{h}</code></p><p class='bad'>Block not found from run/parallel-sanity.log or run/node*.log.{extra}</p>")
            return

        body = (
            f"<h2>Block</h2><p><code>{h}</code></p>"
            f"<div class='card'><b>height:</b> {h}<br /><b>state_root:</b> <code>{html.escape(str(b.get('state_root')))}</code><br /><b>source:</b> <code>{html.escape(str(b.get('source') or 'unknown'))}</code></div>"
            "<h3>Raw log line</h3>"
            f"<pre>{html.escape(str(b.get('raw') or ''))}</pre>"
        )
        self._send_html(200, f"Block {h}", body)


def main() -> None:
    parser = argparse.ArgumentParser(description="TRNM minimal local explorer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="TrillionniumChain repo root (default: auto detect)",
    )
    args = parser.parse_args()

    data = ExplorerData(Path(args.repo_root))
    Handler.data = data

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[min-explorer] serving at http://{args.host}:{args.port} (repo_root={args.repo_root})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

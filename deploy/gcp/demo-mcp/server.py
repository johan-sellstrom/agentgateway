"""A tiny MCP server (Streamable HTTP, JSON responses, stateless) for the HAPS lab.

Standard library only. Every tool echoes the arguments it actually received, so a caller can
see that what reached the tool is exactly what was approved, and `inspect_meta` shows the
`_meta` that reached the upstream (the HAPS credential must not).

Tools:
  echo         ungated by the guard
  transfer     gated: payment.transfer, exact binding
  rotate_key   gated: admin.rotate_key, challenge mode, spend on success
  inspect_meta gated: demo.inspect_meta, returns the `_meta` the upstream received
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER_INFO = {"name": "haps-demo-mcp", "version": "0.1.0"}
DEFAULT_PROTOCOL = "2025-06-18"

TOOLS = [
    {
        "name": "echo",
        "description": "Echo the arguments back. Not gated by HAPS.",
        "inputSchema": {
            "type": "object",
            "properties": {"msg": {"type": "string"}},
        },
    },
    {
        "name": "transfer",
        "description": "Pretend to transfer money (nothing is moved). Gated by HAPS as payment.transfer; amounts are strings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "string", "pattern": "^[0-9]+(\\.[0-9]{1,2})?$"},
                "currency": {"type": "string"},
                "payee": {"type": "string"},
            },
            "required": ["amount", "currency", "payee"],
        },
    },
    {
        "name": "rotate_key",
        "description": "Pretend to rotate a signing key. Gated by HAPS in challenge mode, spent on success.",
        "inputSchema": {
            "type": "object",
            "properties": {"keyId": {"type": "string"}},
            "required": ["keyId"],
        },
    },
    {
        "name": "inspect_meta",
        "description": "Return the _meta this upstream received. Gated by HAPS as demo.inspect_meta.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def text_result(value, is_error=False):
    return {
        "content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}],
        "isError": is_error,
    }


def call_tool(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    if name not in TOOL_NAMES:
        return None, {"code": -32602, "message": f"unknown tool: {name}"}
    if name == "inspect_meta":
        return text_result(params.get("_meta") or {}), None
    return text_result(args), None


def handle(msg):
    """Return the JSON-RPC response for one message, or None for a notification."""
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if mid is None:
        return None  # notification (e.g. notifications/initialized)
    result, error = None, None
    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", DEFAULT_PROTOCOL),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result, error = call_tool(params)
    else:
        error = {"code": -32601, "message": f"method not found: {method}"}
    resp = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        resp["error"] = error
    else:
        resp["result"] = result
    return resp


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"ok": True})
        else:
            # No server-initiated stream: allowed by Streamable HTTP.
            self._send(405)

    def do_DELETE(self):
        self._send(405)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length) or b"null")
        except json.JSONDecodeError:
            self._send(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}})
            return
        if isinstance(msg, list):
            out = [r for r in (handle(m) for m in msg) if r is not None]
            self._send(200, out) if out else self._send(202)
            return
        resp = handle(msg)
        self._send(202) if resp is None else self._send(200, resp)

    def log_message(self, fmt, *args):
        sys.stderr.write("demo-mcp: " + (fmt % args) + "\n")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

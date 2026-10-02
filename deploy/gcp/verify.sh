#!/usr/bin/env bash
# End-to-end check of the deployed lab, printing each request's outcome.
#
#   deploy/gcp/verify.sh
#   GATEWAY_URL=http://localhost:8080/mcp NO_AUTH=1 deploy/gcp/verify.sh   # a local run
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${PROJECT:-lab-mcp-johan}"
REGION="${REGION:-europe-west2}"
GCLOUD="${GCLOUD:-gcloud}"
if [[ -z "${GATEWAY_URL:-}" ]]; then
  GATEWAY_URL="$("$GCLOUD" --project "$PROJECT" run services describe haps-gateway --region "$REGION" --format 'value(status.url)')/mcp"
fi
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

AUTH=()
if [[ "${NO_AUTH:-0}" != 1 ]]; then
  AUTH=(-H "Authorization: Bearer $("$GCLOUD" auth print-identity-token)")
fi

# rpc FILE: POST a JSON-RPC body; print the JSON-RPC response (SSE framing removed).
rpc() {
  curl -sS "$GATEWAY_URL" ${AUTH[@]+"${AUTH[@]}"} -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' \
    --data-binary "@$1" |
    python3 -c '
import json, sys
raw = sys.stdin.read()
lines = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]
body = lines[-1] if lines else raw
try:
    print(json.dumps(json.loads(body)))
except ValueError:
    print(raw)
'
}
body() { printf '%s' "$2" > "$WORK/$1.json"; echo "$WORK/$1.json"; }
show() { python3 -c '
import json, sys
r = json.loads(sys.stdin.read())
if "error" in r:
    e = r["error"]; d = e.get("data") or {}
    out = {"error": {"code": e["code"], "message": e["message"]}}
    if d.get("elicitations"): out["elicitation_url"] = d["elicitations"][0]["url"][:110] + "..."
    if d.get("haps/challenge"): out["challengeId"] = d["haps/challenge"]["challengeId"]
    print(json.dumps(out))
else:
    res = r["result"]
    if "tools" in res: print(json.dumps({"tools": [t["name"] for t in res["tools"]]}))
    else: print(json.dumps({"isError": res.get("isError"), "text": res["content"][0]["text"]}))
'; }
step() { printf '\n--- %s\n' "$*"; }
call() { # call NAME TOOL ARGS_JSON [META_JSON]
  local meta="${4:-}"
  body "$1" "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3${meta:+,\"_meta\":$meta}}}"
}

echo "gateway: $GATEWAY_URL"

step "0. no identity token -> refused by Cloud Run IAM"
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' "$GATEWAY_URL" -H 'Content-Type: application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

step "1. initialize"
rpc "$(body init '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify.sh","version":"1"}}}')" |
  python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(json.dumps({"protocolVersion": r["protocolVersion"], "serverInfo": r["serverInfo"]}))'

step "2. tools/list"
rpc "$(body list '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')" | show

step "3. ungated tool (echo)"
rpc "$(call echo echo '{"msg":"hello"}')" | show

ARGS='{"amount":"250.00","currency":"GBP","payee":"Example Supplier Ltd"}'
step "4. gated tool (transfer) without approval -> -32042 + elicitation URL"
rpc "$(call noapproval transfer "$ARGS")" | show

step "5. minted approval for exactly these arguments -> tool runs"
"$HERE/mint.sh" approve --tool transfer --action-type payment.transfer --args "$ARGS" > "$WORK/approved.json"
rpc "$WORK/approved.json" | show

step "6. a fresh approval, but the amount tampered after approval -> refused"
"$HERE/mint.sh" approve --tool transfer --action-type payment.transfer --args "$ARGS" |
  python3 -c 'import json,sys; r=json.load(sys.stdin); r["params"]["arguments"]["amount"]="2500.00"; print(json.dumps(r))' > "$WORK/tampered.json"
rpc "$WORK/tampered.json" | show

step "7. replay of the approval from step 5 -> refused"
rpc "$WORK/approved.json" | show

step "8. challenge mode (rotate_key) without approval -> -32042 carrying a gateway challenge"
rpc "$(call chal rotate_key '{"keyId":"signing-key-1"}')" > "$WORK/challenge.json"
show < "$WORK/challenge.json"

step "9. an approval answering that challenge -> tool runs (and the use is spent on success)"
"$HERE/mint.sh" approve --tool rotate_key --challenge "$WORK/challenge.json" > "$WORK/answer.json"
rpc "$WORK/answer.json" | show

step "10. the same answer replayed -> refused (its use was spent when the tool succeeded)"
rpc "$WORK/answer.json" | show

step "11. a second, fresh credential for the same challenge -> refused"
"$HERE/mint.sh" approve --tool rotate_key --challenge "$WORK/challenge.json" > "$WORK/answer2.json"
rpc "$WORK/answer2.json" | show

step "12. the credential stops at the gateway; other _meta reaches the upstream"
"$HERE/mint.sh" approve --tool inspect_meta --action-type demo.inspect_meta --args '{}' |
  python3 -c 'import json,sys; r=json.load(sys.stdin); r["params"]["_meta"]["demo.example/trace"]="trace-1"; print(json.dumps(r))' > "$WORK/meta.json"
rpc "$WORK/meta.json" | show

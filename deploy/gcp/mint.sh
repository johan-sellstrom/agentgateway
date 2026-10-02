#!/usr/bin/env bash
# Mint a HAPS approval for one tool call, signed by the lab's TEST Presence Provider key.
# Prints a JSON-RPC tools/call request to send to the gateway.
#
#   deploy/gcp/mint.sh approve --tool transfer --action-type payment.transfer \
#       --args '{"amount":"250.00","currency":"GBP","payee":"Example Supplier Ltd"}'
#   deploy/gcp/mint.sh approve --tool rotate_key --challenge challenge.json
#
# The private key is read from deploy/gcp/.secrets/ (gitignored); if it is not there it is
# fetched from Secret Manager (haps-test-pp-private-key).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROJECT="${PROJECT:-lab-mcp-johan}"
GCLOUD="${GCLOUD:-gcloud}"

(cd "$ROOT" && cargo build --quiet --release -p haps-guard --example haps-mint)

if [[ ! -f "$HERE/.secrets/pp-test.pkcs8.pem" ]]; then
  mkdir -p "$HERE/.secrets" && chmod 700 "$HERE/.secrets"
  (umask 077 && "$GCLOUD" --project "$PROJECT" secrets versions access latest \
    --secret haps-test-pp-private-key > "$HERE/.secrets/pp-test.pkcs8.pem")
fi

exec "$ROOT/target/release/examples/haps-mint" "$@" --secrets "$HERE/.secrets" --trust "$HERE/trust"

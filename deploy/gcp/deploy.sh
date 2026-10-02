#!/usr/bin/env bash
# Deploy the HAPS-guarded agentgateway lab to Google Cloud. Idempotent: re-running converges.
#
#   deploy/gcp/deploy.sh            # build images, then deploy everything
#   SKIP_BUILD=1 deploy/gcp/deploy.sh   # reuse the images already tagged $TAG
#
# Needs gcloud (authenticated), python3, and cargo (only the first time, for `haps-mint init`).
set -euo pipefail

PROJECT="${PROJECT:-lab-mcp-johan}"
REGION="${REGION:-europe-west2}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-haps-run}"
SUBNET_RANGE="${SUBNET_RANGE:-10.60.0.0/24}"
REDIS_INSTANCE="${REDIS_INSTANCE:-haps-guard-state}"
AR_REPO="${AR_REPO:-haps}"
GATEWAY_SVC=haps-gateway
GUARD_SVC=haps-guard
DEMO_SVC=haps-demo-mcp

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SECRETS_DIR="$HERE/.secrets"   # gitignored: test private keys
OUT_DIR="$HERE/.out"           # gitignored: rendered configs (the guard's holds the Redis AUTH)
TRUST_DIR="$HERE/trust"        # committed: public JWKS, PCC, names
TAG="${TAG:-$(git -C "$ROOT" rev-parse --short=8 HEAD)}"

GCLOUD="${GCLOUD:-gcloud}"
gcloud() { command "$GCLOUD" --project "$PROJECT" --quiet "$@"; }
log() { printf '\n==> %s\n' "$*" >&2; }

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
REPO="$REGION-docker.pkg.dev/$PROJECT/$AR_REPO"
host_of() { echo "$1-$PROJECT_NUMBER.$REGION.run.app"; }
GATEWAY_HOST="$(host_of $GATEWAY_SVC)"
GUARD_HOST="$(host_of $GUARD_SVC)"
DEMO_HOST="$(host_of $DEMO_SVC)"
sa() { echo "$1@$PROJECT.iam.gserviceaccount.com"; }

log "APIs"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
  redis.googleapis.com secretmanager.googleapis.com compute.googleapis.com iam.googleapis.com

log "Artifact Registry repo $AR_REPO"
gcloud artifacts repositories describe "$AR_REPO" --location "$REGION" >/dev/null 2>&1 ||
  gcloud artifacts repositories create "$AR_REPO" --repository-format docker --location "$REGION" \
    --description "HAPS-guarded agentgateway lab"

log "Subnet $SUBNET (Direct VPC egress; Private Google Access so internal *.run.app is reachable)"
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" >/dev/null 2>&1 ||
  gcloud compute networks subnets create "$SUBNET" --network "$NETWORK" --region "$REGION" \
    --range "$SUBNET_RANGE" --enable-private-ip-google-access

log "Memorystore $REDIS_INSTANCE (Basic, 1 GB, AUTH on)"
gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" >/dev/null 2>&1 ||
  gcloud redis instances create "$REDIS_INSTANCE" --region "$REGION" --tier basic --size 1 \
    --redis-version redis_7_2 --network "$NETWORK" --enable-auth
REDIS_HOST="$(gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" --format='value(host)')"
REDIS_PORT="$(gcloud redis instances describe "$REDIS_INSTANCE" --region "$REGION" --format='value(port)')"
REDIS_AUTH="$(gcloud redis instances get-auth-string "$REDIS_INSTANCE" --region "$REGION" --format='value(authString)')"

log "Service accounts"
for s in $GATEWAY_SVC $GUARD_SVC $DEMO_SVC; do
  gcloud iam service-accounts describe "$(sa $s)" >/dev/null 2>&1 ||
    gcloud iam service-accounts create "$s" --display-name "HAPS lab: $s"
done

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  log "Cloud Build: images tagged $TAG"
  (cd "$ROOT" && gcloud builds submit --region "$REGION" --config deploy/gcp/cloudbuild.yaml \
    --ignore-file deploy/gcp/gcloudignore --substitutions "_REPO=$REPO,_TAG=$TAG" .)
fi

log "Test trust anchors"
if [[ ! -f "$TRUST_DIR/mint.json" ]]; then
  [[ -f "$SECRETS_DIR/pp-test.pkcs8.pem" ]] && { echo "keys exist but trust/ is missing; fix by hand" >&2; exit 1; }
  (cd "$ROOT" && cargo run --quiet --release -p haps-guard --example haps-mint -- init \
    --secrets "$SECRETS_DIR" --trust "$TRUST_DIR" --audience "did:web:$GATEWAY_HOST" \
    --audience-name "HAPS lab gateway" --agent did:web:agent.haps-lab.invalid --agent-name "HAPS lab agent")
fi

# put_secret NAME FILE: create the secret if needed; add a version only when the content changed.
put_secret() {
  local name="$1" file="$2"
  if ! gcloud secrets describe "$name" >/dev/null 2>&1; then
    gcloud secrets create "$name" --replication-policy automatic --labels app=haps-lab >/dev/null
  fi
  if ! cmp -s <(gcloud secrets versions access latest --secret "$name" 2>/dev/null) "$file"; then
    gcloud secrets versions add "$name" --data-file "$file" >/dev/null
    echo "  $name: new version" >&2
  else
    echo "  $name: unchanged" >&2
  fi
}
grant_secret() {
  gcloud secrets add-iam-policy-binding "$1" --member "serviceAccount:$2" \
    --role roles/secretmanager.secretAccessor >/dev/null
}

log "Test private keys -> Secret Manager (no service account is granted access)"
if [[ -f "$SECRETS_DIR/pp-test.pkcs8.pem" ]]; then
  put_secret haps-test-pp-private-key "$SECRETS_DIR/pp-test.pkcs8.pem"
  put_secret haps-test-certifier-private-key "$SECRETS_DIR/certifier-test.pkcs8.pem"
fi

log "Render configs"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
REDIS_URL="redis://:$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIS_AUTH")@$REDIS_HOST:$REDIS_PORT" \
GATEWAY_HOST="$GATEWAY_HOST" GUARD_HOST="$GUARD_HOST" DEMO_HOST="$DEMO_HOST" \
python3 - "$HERE/config" "$OUT_DIR" <<'EOF'
import os, string, sys
src, out = sys.argv[1], sys.argv[2]
for name in ("haps-guard.yaml", "agentgateway.yaml"):
    text = string.Template(open(os.path.join(src, name + ".tmpl")).read()).substitute(os.environ)
    path = os.path.join(out, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
EOF

log "Config and trust anchors -> Secret Manager"
put_secret haps-guard-config "$OUT_DIR/haps-guard.yaml"
put_secret haps-trust-pp-jwks "$TRUST_DIR/pp-test.jwks.json"
put_secret haps-trust-certifier-jwks "$TRUST_DIR/certifier-test.jwks.json"
put_secret haps-trust-pcc "$TRUST_DIR/pcc-test.jws"
put_secret haps-gateway-config "$OUT_DIR/agentgateway.yaml"
for s in haps-guard-config haps-trust-pp-jwks haps-trust-certifier-jwks haps-trust-pcc; do
  grant_secret "$s" "$(sa $GUARD_SVC)"
done
grant_secret haps-gateway-config "$(sa $GATEWAY_SVC)"

invoker() {
  gcloud run services add-iam-policy-binding "$1" --region "$REGION" \
    --member "serviceAccount:$(sa $GATEWAY_SVC)" --role roles/run.invoker >/dev/null
}

log "Cloud Run: $DEMO_SVC (internal, IAM-only)"
gcloud run deploy "$DEMO_SVC" --region "$REGION" --image "$REPO/demo-mcp:$TAG" \
  --service-account "$(sa $DEMO_SVC)" --ingress internal --no-allow-unauthenticated \
  --port 8080 --cpu 1 --memory 256Mi --min-instances 0 --max-instances 2
invoker "$DEMO_SVC"

log "Cloud Run: $GUARD_SVC (gRPC/h2c, internal, IAM-only, Direct VPC egress to Redis)"
gcloud run deploy "$GUARD_SVC" --region "$REGION" --image "$REPO/haps-guard:$TAG" \
  --service-account "$(sa $GUARD_SVC)" --ingress internal --no-allow-unauthenticated \
  --use-http2 --port 8080 --cpu 1 --memory 256Mi --min-instances 0 --max-instances 3 \
  --network "$NETWORK" --subnet "$SUBNET" --vpc-egress private-ranges-only \
  --set-env-vars RUST_LOG=info,haps_guard=debug,NO_COLOR=1 \
  --set-secrets "/etc/haps-guard/config/config.yaml=haps-guard-config:latest,/etc/haps-guard/trust-pp/pp-test.jwks.json=haps-trust-pp-jwks:latest,/etc/haps-guard/trust-certifier/certifier-test.jwks.json=haps-trust-certifier-jwks:latest,/etc/haps-guard/trust-pcc/pcc-test.jws=haps-trust-pcc:latest" \
  --args /etc/haps-guard/config/config.yaml
invoker "$GUARD_SVC"

log "Cloud Run: $GATEWAY_SVC (IAM-only; all egress via the VPC so internal services accept it)"
gcloud run deploy "$GATEWAY_SVC" --region "$REGION" --image "$REPO/agentgateway:$TAG" \
  --service-account "$(sa $GATEWAY_SVC)" --ingress all --no-allow-unauthenticated \
  --port 8080 --cpu 1 --memory 512Mi --min-instances 0 --max-instances 3 \
  --network "$NETWORK" --subnet "$SUBNET" --vpc-egress all-traffic \
  --set-secrets "/etc/agentgateway/config.yaml=haps-gateway-config:latest" \
  --args=-f,/etc/agentgateway/config.yaml

log "Done"
echo "gateway: https://$GATEWAY_HOST/mcp   (call with: Authorization: Bearer \$(gcloud auth print-identity-token))"

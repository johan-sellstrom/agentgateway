//! `haps-mint`: test trust anchors and approvals for the HAPS lab deployment.
//!
//! Built as an example of the `haps-guard` crate so it hashes, canonicalises and derives the
//! Signing View with the very code the guard verifies with. Run it through `deploy/gcp/mint.sh`.
//!
//! ```text
//! haps-mint init    --secrets DIR --trust DIR --audience DID --audience-name NAME
//!                   --agent DID --agent-name NAME
//! haps-mint approve --secrets DIR --trust DIR --tool NAME --action-type TYPE --args JSON
//!                   [--challenge FILE] [--jti ID] [--id N] [--ttl SECONDS]
//! ```
//!
//! `init` generates a test Presence Provider key and a test certifier key. The private keys go
//! to `--secrets` (keep it out of git); the guard's public inputs go to `--trust`: one JWKS per
//! key, the certifier-signed Provider Certification (PCC), and `mint.json` with the names.
//!
//! `approve` prints a JSON-RPC `tools/call` request whose `_meta` carries a credential signed by
//! the test Presence Provider and the AI-INTENT it approves. With `--challenge`, FILE is the
//! gateway's `-32042` response (or its `error.data`), and the credential answers that challenge:
//! the intent is the challenge's, and the arguments are the intent's parameters.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use haps_guard::{derive_signing_view, haps_canon, haps_hash};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

const PP_KEY: &str = "pp-test.pkcs8.pem";
const CERTIFIER_KEY: &str = "certifier-test.pkcs8.pem";
const PP_KID: &str = "pp-test-1";
const CERTIFIER_KID: &str = "certifier-test-1";
const LEVEL: &str = "HAPS-PoHP-2";
const METHOD: &str = "webauthn.uv";

fn usage() -> ! {
	eprintln!(
		"usage:\n  haps-mint init --secrets DIR --trust DIR --audience DID --audience-name NAME --agent DID --agent-name NAME\n  haps-mint approve --secrets DIR --trust DIR --tool NAME --action-type TYPE --args JSON [--challenge FILE] [--jti ID] [--id N] [--ttl SECONDS]"
	);
	std::process::exit(2)
}

fn main() -> anyhow::Result<()> {
	let mut argv = std::env::args().skip(1);
	let cmd = argv.next().unwrap_or_else(|| usage());
	let mut opts = HashMap::new();
	while let Some(k) = argv.next() {
		let Some(k) = k.strip_prefix("--") else {
			usage()
		};
		let v = argv.next().unwrap_or_else(|| usage());
		opts.insert(k.to_owned(), v);
	}
	let get = |k: &str| -> anyhow::Result<String> {
		opts
			.get(k)
			.cloned()
			.with_context(|| format!("missing --{k}"))
	};
	let secrets = PathBuf::from(get("secrets")?);
	let trust = PathBuf::from(get("trust")?);
	match cmd.as_str() {
		"init" => init(
			&secrets,
			&trust,
			&json!({
				"audience": {"id": get("audience")?, "name": get("audience-name")?},
				"agent": {"id": get("agent")?, "name": get("agent-name")?},
				"issuer": opts.get("issuer").cloned().unwrap_or("did:web:test-pp.haps-lab.invalid".into()),
				"certifier": opts.get("certifier").cloned().unwrap_or("did:web:test-certifier.haps-lab.invalid".into()),
				"providerId": "test-pp",
				"pccRef": "https://test-certifier.haps-lab.invalid/pcc/test-pp",
			}),
		),
		"approve" => {
			let settings: Value = serde_json::from_str(&read(&trust.join("mint.json"))?)?;
			let ttl: u64 = opts.get("ttl").map_or(Ok(300), |t| t.parse())?;
			let id: u64 = opts.get("id").map_or(Ok(1), |t| t.parse())?;
			let jti = opts
				.get("jti")
				.cloned()
				.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
			let tool = get("tool")?;
			let (intent, arguments, challenge_id) = match opts.get("challenge") {
				Some(file) => from_challenge(&read(Path::new(file))?)?,
				None => {
					let arguments: Value =
						serde_json::from_str(&get("args")?).context("--args is not JSON")?;
					let intent = intent(&settings, &get("action-type")?, &arguments, ttl);
					(intent, arguments, None)
				},
			};
			let pp = EncodingKey::from_ed_pem(read(&secrets.join(PP_KEY))?.as_bytes())?;
			let meta = approved_meta(&settings, &pp, &jti, &intent, challenge_id.as_ref(), ttl)?;
			let request = json!({
				"jsonrpc": "2.0",
				"id": id,
				"method": "tools/call",
				"params": {"name": tool, "arguments": arguments, "_meta": meta},
			});
			println!("{}", serde_json::to_string_pretty(&request)?);
			Ok(())
		},
		_ => usage(),
	}
}

fn read(p: &Path) -> anyhow::Result<String> {
	std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
}

fn write(p: &Path, contents: &str) -> anyhow::Result<()> {
	std::fs::write(p, contents).with_context(|| format!("writing {}", p.display()))
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
}

fn rfc3339(t: u64) -> String {
	chrono::DateTime::from_timestamp(t as i64, 0)
		.unwrap()
		.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fresh Ed25519 key: (PKCS#8 PEM, encoding key, public `x`).
fn keypair() -> anyhow::Result<(String, EncodingKey, String)> {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
		.map_err(|_| anyhow::anyhow!("key generation failed"))?;
	let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
		.map_err(|_| anyhow::anyhow!("generated key does not parse"))?;
	let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
	let body: Vec<&str> = b64
		.as_bytes()
		.chunks(64)
		.map(|c| std::str::from_utf8(c).unwrap())
		.collect();
	let pem = format!(
		"-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
		body.join("\n")
	);
	Ok((
		pem,
		EncodingKey::from_ed_der(pkcs8.as_ref()),
		haps_hash::base64url_unpadded(public.public_key().as_ref()),
	))
}

fn jwks(kid: &str, x: &str) -> Value {
	json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig", "x": x}]})
}

fn sign(key: &EncodingKey, kid: &str, claims: &Value) -> anyhow::Result<String> {
	let mut header = Header::new(Algorithm::EdDSA);
	header.kid = Some(kid.into());
	Ok(jsonwebtoken::encode(&header, claims, key)?)
}

fn canon(v: &Value) -> anyhow::Result<haps_canon::Value> {
	haps_canon::parse(&v.to_string()).map_err(|e| anyhow::anyhow!("not HAPS-canonicalisable: {e:?}"))
}

fn init(secrets: &Path, trust: &Path, settings: &Value) -> anyhow::Result<()> {
	for d in [secrets, trust] {
		std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
	}
	if secrets.join(PP_KEY).exists() || secrets.join(CERTIFIER_KEY).exists() {
		bail!(
			"{} already holds test keys; delete them first to rotate",
			secrets.display()
		);
	}
	let (pp_pem, _, pp_x) = keypair()?;
	let (cert_pem, cert_key, cert_x) = keypair()?;
	write(&secrets.join(PP_KEY), &pp_pem)?;
	write(&secrets.join(CERTIFIER_KEY), &cert_pem)?;
	#[cfg(unix)]
	for f in [PP_KEY, CERTIFIER_KEY] {
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(secrets.join(f), std::fs::Permissions::from_mode(0o600))?;
	}
	let now = now();
	let pcc = sign(
		&cert_key,
		CERTIFIER_KID,
		&json!({
			"providerId": settings["providerId"],
			"certifiedLevels": [LEVEL],
			"certifiedFactors": [METHOD],
			"issuer": settings["certifier"],
			"issuedAt": rfc3339(now),
			"expiresAt": rfc3339(now + 365 * 24 * 3600),
			"evaluation": {"lab": "HAPS lab (TEST FIXTURE, not a real evaluation)", "reportId": "TEST-1"},
		}),
	)?;
	write(
		&trust.join("pp-test.jwks.json"),
		&serde_json::to_string_pretty(&jwks(PP_KID, &pp_x))?,
	)?;
	write(
		&trust.join("certifier-test.jwks.json"),
		&serde_json::to_string_pretty(&jwks(CERTIFIER_KID, &cert_x))?,
	)?;
	write(&trust.join("pcc-test.jws"), &format!("{pcc}\n"))?;
	write(
		&trust.join("mint.json"),
		&format!("{}\n", serde_json::to_string_pretty(settings)?),
	)?;
	eprintln!(
		"private keys: {}/{{{PP_KEY},{CERTIFIER_KEY}}}\npublic trust anchors: {}",
		secrets.display(),
		trust.display()
	);
	Ok(())
}

/// A schema-shaped AI-INTENT for one action, addressed to the gateway (agent-initiated mode).
fn intent(settings: &Value, action_type: &str, arguments: &Value, ttl: u64) -> Value {
	let now = now();
	json!({
		"version": "0.4",
		"intentId": uuid::Uuid::new_v4().to_string(),
		"issuedAt": rfc3339(now),
		"audience": settings["audience"],
		"agent": settings["agent"],
		"action": {"type": action_type, "parameters": arguments},
		"constraints": {"expiresAt": rfc3339(now + ttl), "oneTime": true},
		"display": {"language": "en", "title": format!("Approve {action_type}"), "summary": format!("Approve {action_type} with these exact parameters")},
	})
}

/// The intent, arguments and challenge id from a gateway challenge (challenge mode).
fn from_challenge(text: &str) -> anyhow::Result<(Value, Value, Option<Value>)> {
	let v: Value = serde_json::from_str(text).context("challenge file is not JSON")?;
	let data = v.pointer("/error/data").unwrap_or(&v);
	let challenge = data
		.get("haps/challenge")
		.context("no haps/challenge in the challenge file")?;
	let intent = challenge["actionIntent"].clone();
	let arguments = intent
		.pointer("/action/parameters")
		.cloned()
		.unwrap_or(json!({}));
	Ok((intent, arguments, Some(challenge["challengeId"].clone())))
}

/// The `_meta` carrying a credential that approves `intent`. The Provider Certification is
/// referenced, not embedded: the guard has it provisioned under the same `ref`.
fn approved_meta(
	settings: &Value,
	pp: &EncodingKey,
	jti: &str,
	intent: &Value,
	challenge_id: Option<&Value>,
	ttl: u64,
) -> anyhow::Result<Value> {
	let now = now();
	let canonical = canon(intent)?;
	let view = derive_signing_view(&canonical);
	let mut claims = json!({
		"issuer": settings["issuer"],
		"intent_hash": haps_hash::hash_value(&canonical),
		"presentation_hash": haps_hash::hash_value(&view),
		"aud": settings["audience"]["id"],
		"jti": jti,
		"iat": now,
		"exp": now + ttl,
		"assurance": {"level": LEVEL, "verifiedAt": rfc3339(now), "method": METHOD},
		"providerCertification": {"ref": settings["pccRef"]},
	});
	if let Some(id) = challenge_id {
		claims["challengeId"] = id.clone();
	}
	let credential = sign(pp, PP_KID, &claims)?;
	Ok(json!({"haps/credential": credential, "haps/actionIntent": intent}))
}

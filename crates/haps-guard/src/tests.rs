use std::collections::HashMap;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Value, json};

use super::*;
use crate::envelope::{Pointer, RuleKind};
use crate::store::MemoryStore;

// The published HAPS v0.4 payment vector. Accepting a credential that carries the
// *published* hashes ties the guard to the specification rather than to its own hash code.
const INTENT: &str =
	include_str!("../testdata/haps-v0.4/action-intent.payment.transfer.sample.json");
const VIEW: &str = include_str!("../testdata/haps-v0.4/signing-view.payment.transfer.sample.json");
const INTENT_HASH: &str = include_str!("../testdata/haps-v0.4/expected_intent_hash.txt");
const VIEW_HASH: &str = include_str!("../testdata/haps-v0.4/expected_presentation_hash.txt");
const PCC_PROVIDER_B: &str =
	include_str!("../testdata/haps-v0.4/provider-certification.provider-b.sample.json");

const AUD: &str = "did:web:bank.example";
const ISSUER: &str = "did:web:pp.example";
const CERTIFIER: &str = "did:web:certifier.example";
const PROVIDER: &str = "provider-a";
const PCC_REF: &str = "https://certs.certifier.example/pcc/provider-a/2026-01";
const IAT: u64 = 1_767_916_800; // 2026-01-09T00:00:00Z, the vector's issuedAt
const EXP: u64 = 1_767_916_920; // 2026-01-09T00:02:00Z, the vector's constraints.expiresAt
const NOW: u64 = IAT + 30;
const SKEW: u64 = 60;
const TOOL: &str = "transfer_funds";

struct Signer {
	kid: String,
	x: String,
	key: EncodingKey,
}

fn signer(kid: &str) -> Signer {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
	let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pkcs8");
	Signer {
		kid: kid.to_owned(),
		x: haps_hash::base64url_unpadded(pair.public_key().as_ref()),
		key: EncodingKey::from_ed_der(pkcs8.as_ref()),
	}
}

fn jwks(signers: &[&Signer]) -> JwkSet {
	let keys: Vec<Value> = signers
		.iter()
		.map(|s| json!({"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "alg": "EdDSA", "use": "sig", "x": s.x}))
		.collect();
	serde_json::from_value(json!({ "keys": keys })).expect("jwks")
}

fn sign(s: &Signer, claims: &Value) -> String {
	let mut header = Header::new(Algorithm::EdDSA);
	header.kid = Some(s.kid.clone());
	jsonwebtoken::encode(&header, claims, &s.key).expect("sign")
}

fn hash_json(v: &Value) -> String {
	haps_hash::hash_value(&haps_canon::parse(&v.to_string()).unwrap())
}

fn view_of(intent: &Value) -> Value {
	let derived = derive_signing_view(&haps_canon::parse(&intent.to_string()).unwrap());
	serde_json::from_slice(&haps_canon::canonicalize(&derived)).unwrap()
}

fn intent() -> Value {
	serde_json::from_str(INTENT).unwrap()
}

/// The approved `action.parameters`, taken from the published intent.
fn approved_arguments() -> Value {
	intent()["action"]["parameters"].clone()
}

fn with(mut base: Value, key: &str, value: Value) -> Value {
	base[key] = value;
	base
}

/// The envelope vocabulary the published payment vector needs.
fn payment_rules() -> HashMap<String, EnvelopeRule> {
	HashMap::from([
		(
			"amountRange".to_owned(),
			EnvelopeRule {
				kind: RuleKind::DecimalRange,
				path: Pointer::parse("/amount").unwrap(),
			},
		),
		(
			"allowedPayees".to_owned(),
			EnvelopeRule {
				kind: RuleKind::AllowList,
				path: Pointer::parse("/to").unwrap(),
			},
		),
	])
}

fn policy(min_level: &str) -> ToolPolicy {
	let mut p = ToolPolicy::new("payment.transfer", PohpLevel::parse(min_level).unwrap());
	p.envelope_rules = payment_rules();
	p
}

/// A Presence Provider, the certifier that certified it, and the guard trusting both.
struct World {
	pp: Signer,
	certifier: Signer,
}

impl World {
	fn new() -> Self {
		Self {
			pp: signer("pp-1"),
			certifier: signer("cert-1"),
		}
	}

	fn config(&self, policy: ToolPolicy) -> GuardConfig {
		GuardConfig {
			tools: HashMap::from([(TOOL.to_owned(), policy)]),
			issuers: HashMap::from([(ISSUER.to_owned(), jwks(&[&self.pp]))]),
			audience: Party {
				id: AUD.into(),
				name: "Example Bank".into(),
			},
			agent: Party {
				id: "did:web:agent.example".into(),
				name: "Treasury Agent".into(),
			},
			elicitation_url: "https://pp.example/approve".into(),
			clock_skew_secs: SKEW,
			certification: CertificationConfig {
				certifiers: HashMap::from([(CERTIFIER.to_owned(), jwks(&[&self.certifier]))]),
				providers: HashMap::from([(ISSUER.to_owned(), PROVIDER.to_owned())]),
				provisioned: HashMap::new(),
			},
			agent_resistant_methods: Vec::new(),
			challenge_ttl_secs: 300,
			rp_signer: None,
		}
	}

	fn guard(&self, policy: ToolPolicy) -> Guard {
		Guard::new(self.config(policy), StateStore::memory())
	}

	fn pcc_claims(&self) -> Value {
		json!({
			"providerId": PROVIDER,
			"certifiedLevels": ["HAPS-PoHP-1", "HAPS-PoHP-2"],
			"certifiedFactors": ["webauthn.uv", "otp.delivered", "vendor.example/palm"],
			"issuer": CERTIFIER,
			"issuedAt": "2026-01-02T00:00:00Z",
			"expiresAt": "2027-01-02T00:00:00Z",
			"evaluation": {"lab": "Example Evaluation Lab", "reportId": "EEL-2026-0042"},
		})
	}

	fn pcc(&self, claims: &Value) -> String {
		sign(&self.certifier, claims)
	}

	/// Consent Credential claims for the published intent, with an embedded certification.
	fn claims(&self) -> Value {
		json!({
			"issuer": ISSUER,
			"subject": "urn:haps:subject:9f2c1e7a",
			"intent_hash": INTENT_HASH.trim(),
			"presentation_hash": VIEW_HASH.trim(),
			"aud": AUD,
			"jti": "jti-0001",
			"iat": IAT,
			"nbf": IAT,
			"exp": EXP,
			"assurance": {"level": "HAPS-PoHP-2", "verifiedAt": "2026-01-09T00:00:30Z", "method": "webauthn.uv"},
			"providerCertification": {"ref": PCC_REF, "embedded": self.pcc(&self.pcc_claims())},
		})
	}

	/// Claims approving `intent`, with hashes computed for it.
	fn claims_for(&self, intent: &Value) -> Value {
		let mut c = self.claims();
		c["intent_hash"] = hash_json(intent).into();
		c["presentation_hash"] = hash_json(&view_of(intent)).into();
		c
	}

	fn sign(&self, claims: &Value) -> String {
		sign(&self.pp, claims)
	}
}

fn meta_for(credential: &str, intent: &Value, view: Option<&Value>) -> Value {
	let mut m = json!({META_CREDENTIAL: credential, META_ACTION_INTENT: intent});
	if let Some(v) = view {
		m[META_SIGNING_VIEW] = v.clone();
	}
	m
}

fn meta(credential: &str) -> Value {
	meta_for(
		credential,
		&intent(),
		Some(&serde_json::from_str(VIEW).unwrap()),
	)
}

fn call(name: &str, arguments: Value, meta: Option<Value>) -> Vec<u8> {
	let mut params = json!({"name": name, "arguments": arguments});
	if let Some(m) = meta {
		params["_meta"] = m;
	}
	serde_json::to_vec(&params).unwrap()
}

fn approved_call(credential: &str) -> Vec<u8> {
	call(TOOL, approved_arguments(), Some(meta(credential)))
}

async fn check(g: &Guard, params: &[u8], now: u64) -> Decision {
	g.check("tools/call", Some(params), now).await
}

fn approved(d: Decision) -> (Vec<u8>, Audit) {
	match d {
		Decision::Approved { params, audit } => (params, audit),
		other => panic!("expected Approved, got {other:?}"),
	}
}

fn denied(d: Decision) -> Denial {
	match d {
		Decision::Denied(d) => d,
		other => panic!("expected Denied, got {other:?}"),
	}
}

fn elicited(d: Decision) -> (String, Value) {
	match d {
		Decision::ElicitationRequired {
			reason,
			elicitation,
		} => (reason, elicitation),
		other => panic!("expected ElicitationRequired, got {other:?}"),
	}
}

fn is_approved(d: &Decision) -> bool {
	matches!(d, Decision::Approved { .. })
}

// ------------------------------------------------------------------ the published vectors

#[test]
fn the_copied_vectors_reproduce_their_published_hashes() {
	// Guards the test data itself: an edit to a copied vector fails here.
	assert_eq!(
		haps_hash::parse_and_hash(INTENT).unwrap(),
		INTENT_HASH.trim()
	);
	assert_eq!(haps_hash::parse_and_hash(VIEW).unwrap(), VIEW_HASH.trim());
}

#[test]
fn the_signing_view_derived_from_the_published_intent_is_the_published_view() {
	let derived = derive_signing_view(&haps_canon::parse(INTENT).unwrap());
	assert_eq!(haps_hash::hash_value(&derived), VIEW_HASH.trim());
	assert_eq!(
		haps_canon::canonicalize(&derived),
		haps_canon::canonicalize(&haps_canon::parse(VIEW).unwrap())
	);
}

// ------------------------------------------------------------------ acceptance

#[tokio::test]
async fn a_credential_carrying_the_published_hashes_is_accepted() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let (params, audit) = approved(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await);
	assert_eq!(
		audit,
		Audit {
			jti: "jti-0001".into(),
			issuer: ISSUER.into(),
			level: "HAPS-PoHP-2".into(),
			method: "webauthn.uv".into(),
			action_type: "payment.transfer".into(),
			certifier: CERTIFIER.into(),
			provider_id: PROVIDER.into(),
			evaluation: "Example Evaluation Lab EEL-2026-0042".into(),
			challenge_id: None,
			varied_within_envelope: vec![],
		}
	);
	// The upstream receives exactly the approved arguments, and never the credential.
	let forwarded: Value = serde_json::from_slice(&params).unwrap();
	// Emptied but present: an absent `_meta` would tell the gateway to keep the original.
	assert_eq!(forwarded["_meta"], json!({}), "{forwarded}");
	assert_eq!(
		hash_json(&forwarded["arguments"]),
		hash_json(&approved_arguments())
	);
}

#[tokio::test]
async fn the_signing_view_may_be_omitted_because_the_guard_derives_it() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let m = meta_for(&w.sign(&w.claims()), &intent(), None);
	assert!(is_approved(
		&check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await
	));
}

#[tokio::test]
async fn other_meta_keys_survive_and_only_haps_keys_are_stripped() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut m = meta(&w.sign(&w.claims()));
	m["progressToken"] = json!("tok-7");
	let (params, _) = approved(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await);
	let forwarded: Value = serde_json::from_slice(&params).unwrap();
	assert_eq!(forwarded["_meta"], json!({"progressToken": "tok-7"}));
}

#[tokio::test]
async fn a_float_elsewhere_in_meta_does_not_make_the_request_unreadable() {
	// Only the arguments and the approval are parsed strictly.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut m = meta(&w.sign(&w.claims()));
	m["vendor.example/progress"] = json!(0.25);
	assert!(is_approved(
		&check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await
	));
}

#[tokio::test]
async fn skew_admits_a_credential_just_past_expiry() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&w.claims())), EXP + SKEW).await
	));
}

// ------------------------------------------------------------------ not gated

#[tokio::test]
async fn an_ungated_tool_passes_untouched() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	assert!(matches!(
		check(&g, &call("echo", json!({"hi": "world"}), None), NOW).await,
		Decision::NotGated
	));
}

#[tokio::test]
async fn methods_other_than_tools_call_are_not_gated() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	assert!(matches!(
		g.check("tools/list", None, NOW).await,
		Decision::NotGated
	));
}

// ------------------------------------------------------------------ elicitation

#[tokio::test]
async fn a_gated_call_without_approval_elicits_the_provider() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let (reason, e) = elicited(check(&g, &call(TOOL, approved_arguments(), None), NOW).await);
	assert_eq!(reason, "approval required for this call");
	let el = &e["elicitations"][0];
	assert_eq!(el["mode"], "url");
	let id = el["elicitationId"].as_str().unwrap();
	assert!(id.starts_with("sha256:"), "{id}");
	assert_eq!(
		el["url"].as_str().unwrap(),
		format!(
			"https://pp.example/approve?elicitationId={}",
			id.replace(':', "%3A")
		)
	);
}

#[tokio::test]
async fn the_elicitation_id_is_a_content_address_of_the_call() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let id = async |args: Value| {
		elicited(check(&g, &call(TOOL, args, None), NOW).await).1["elicitations"][0]["elicitationId"]
			.as_str()
			.unwrap()
			.to_owned()
	};
	let base = approved_arguments();
	let mut other = base.clone();
	other["reference"] = json!("Invoice 99999");
	assert_eq!(
		id(base.clone()).await,
		id(base.clone()).await,
		"same call, same id"
	);
	assert_ne!(
		id(base).await,
		id(other).await,
		"different call, different id"
	);
}

#[tokio::test]
async fn an_expired_approval_is_re_elicited_not_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let (reason, _) = elicited(check(&g, &approved_call(&w.sign(&w.claims())), EXP + SKEW + 1).await);
	assert_eq!(reason, "approval expired");
}

#[tokio::test]
async fn a_fractional_argument_is_rejected_before_anything_is_elicited() {
	// RP-CORE-04a: such a call can never be bound, so eliciting it would be pointless.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let args = json!({"amount": {"currency": "GBP", "value": 250.75}});
	assert!(matches!(
		denied(check(&g, &call(TOOL, args, None), NOW).await),
		Denial::MalformedArguments(_)
	));
}

// ------------------------------------------------------------------ binding

#[tokio::test]
async fn a_tampered_amount_is_denied() {
	// The case the whole integration exists for: approved £250.00, agent sends £2500.00. The
	// envelope catches it first; exact binding would catch it anyway.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut args = approved_arguments();
	args["amount"]["value"] = json!("2500.00");
	let params = call(TOOL, args, Some(meta(&w.sign(&w.claims()))));
	assert!(matches!(
		denied(check(&g, &params, NOW).await),
		Denial::Envelope(EnvelopeError::Outside { .. })
	));
}

#[tokio::test]
async fn a_changed_payee_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut args = approved_arguments();
	args["to"]["iban"] = json!("GB00ATTACKER000000000000000");
	let params = call(TOOL, args, Some(meta(&w.sign(&w.claims()))));
	assert!(matches!(
		denied(check(&g, &params, NOW).await),
		Denial::Envelope(EnvelopeError::Outside { .. })
	));
}

#[tokio::test]
async fn an_in_envelope_change_is_denied_under_exact_binding() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut args = approved_arguments();
	args["amount"]["value"] = json!("275.00");
	let params = call(TOOL, args, Some(meta(&w.sign(&w.claims()))));
	assert_eq!(
		denied(check(&g, &params, NOW).await),
		Denial::ArgumentsDoNotMatchApproval
	);
}

#[tokio::test]
async fn an_added_argument_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut args = approved_arguments();
	args["urgent"] = json!(true);
	let params = call(TOOL, args, Some(meta(&w.sign(&w.claims()))));
	assert_eq!(
		denied(check(&g, &params, NOW).await),
		Denial::ArgumentsDoNotMatchApproval
	);
}

#[tokio::test]
async fn key_order_and_whitespace_do_not_matter() {
	// Canonicalisation, not byte-equality of what the agent happened to send.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let reordered = json!({
		"reference": "Invoice 18372",
		"to": {"name": "Example Supplier Ltd", "iban": "GB00EXAMP1E00000000000000"},
		"amount": {"value": "250.00", "currency": "GBP"},
	});
	assert!(is_approved(
		&check(
			&g,
			&call(TOOL, reordered, Some(meta(&w.sign(&w.claims())))),
			NOW
		)
		.await
	));
}

#[tokio::test]
async fn an_approval_for_another_action_type_is_denied() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.action_type = "payee.create".into();
	let g = w.guard(p);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await),
		Denial::WrongActionType {
			expected: "payee.create".into()
		}
	);
}

#[tokio::test]
async fn an_intent_modified_after_signing_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut m = meta(&w.sign(&w.claims()));
	m[META_ACTION_INTENT]["display"]["summary"] = json!("Approve a £2,500.00 transfer");
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::IntentHashMismatch
	);
}

// ------------------------------------------------------------------ RP-CORE-05: the view

#[tokio::test]
async fn a_supplied_view_that_differs_from_the_derived_one_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut m = meta(&w.sign(&w.claims()));
	m[META_SIGNING_VIEW] = json!({"title": "Something else entirely"});
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::SigningViewNotDerived
	);
}

#[tokio::test]
async fn a_credential_not_covering_the_derived_view_is_denied_even_when_the_right_view_is_presented()
 {
	// Presenting the correct view must not stand in for the credential covering it.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(
		w.claims(),
		"presentation_hash",
		hash_json(&json!({"title": "Something else"})).into(),
	);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::PresentationHashMismatch
	);
}

#[tokio::test]
async fn an_approval_of_a_view_not_derived_from_the_intent_is_denied() {
	// A provider showed the human something other than the intent -- here a view without the
	// risk notice -- and the credential faithfully covers what was shown. The hash matches the
	// view presented, so only deriving the view catches it.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut shown = view_of(&intent());
	shown["display"]
		.as_object_mut()
		.unwrap()
		.remove("riskNotice");
	let c = with(w.claims(), "presentation_hash", hash_json(&shown).into());
	let m = meta_for(&w.sign(&c), &intent(), Some(&shown));
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::SigningViewNotDerived
	);
	// Without the view, the same credential simply does not cover the derived one.
	let m = meta_for(&w.sign(&c), &intent(), None);
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::PresentationHashMismatch
	);
}

// ------------------------------------------------------------------ the intent itself

#[tokio::test]
async fn an_intent_addressed_to_another_relying_party_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut i = intent();
	i["audience"]["id"] = json!("did:web:another-bank.example");
	let m = meta_for(&w.sign(&w.claims_for(&i)), &i, None);
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::IntentWrongAudience
	);
}

#[tokio::test]
async fn an_expired_intent_is_re_elicited_even_under_a_live_credential() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut i = intent();
	i["constraints"]["expiresAt"] = json!("2026-01-09T00:00:10Z");
	let c = with(w.claims_for(&i), "exp", json!(EXP + 600));
	let m = meta_for(&w.sign(&c), &i, None);
	let (reason, _) = elicited(
		check(
			&g,
			&call(TOOL, approved_arguments(), Some(m)),
			IAT + 10 + SKEW + 1,
		)
		.await,
	);
	assert_eq!(reason, "approved intent expired");
}

#[tokio::test]
async fn a_credential_older_than_the_tool_accepts_is_re_elicited() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.max_credential_age_secs = Some(10);
	let g = w.guard(p);
	let (reason, _) = elicited(
		check(
			&g,
			&approved_call(&w.sign(&w.claims())),
			IAT + 10 + SKEW + 1,
		)
		.await,
	);
	assert_eq!(reason, "approval is older than this tool accepts");
}

#[tokio::test]
async fn an_intent_of_another_version_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let i = with(intent(), "version", json!("0.3"));
	let m = meta_for(&w.sign(&w.claims_for(&i)), &i, None);
	assert!(matches!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW).await),
		Denial::MalformedIntent(_)
	));
}

// ------------------------------------------------------------------ signature and trust

#[tokio::test]
async fn a_signature_by_another_key_is_denied() {
	// Signed by an attacker's key but claiming the trusted provider's `kid`.
	let w = World::new();
	let attacker = Signer {
		kid: "pp-1".into(),
		..signer("attacker")
	};
	let g = w.guard(policy("HAPS-PoHP-2"));
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&attacker, &w.claims())), NOW).await),
		Denial::BadSignature
	);
}

#[tokio::test]
async fn an_unknown_key_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let stranger = signer("pp-unknown");
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&stranger, &w.claims())), NOW).await),
		Denial::UnknownKey
	);
}

#[tokio::test]
async fn a_symmetric_algorithm_is_rejected_before_key_lookup() {
	// HS256 would need the gateway to hold the provider's signing secret.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut header = Header::new(Algorithm::HS256);
	header.kid = Some("pp-1".into());
	let forged = jsonwebtoken::encode(
		&header,
		&w.claims(),
		&EncodingKey::from_secret(b"guessable"),
	)
	.unwrap();
	assert!(matches!(
		denied(check(&g, &approved_call(&forged), NOW).await),
		Denial::UnsupportedAlgorithm(_)
	));
}

#[tokio::test]
async fn an_untrusted_issuer_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(w.claims(), "issuer", json!("did:web:rogue.example"));
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::UntrustedIssuer("did:web:rogue.example".into())
	);
}

#[tokio::test]
async fn one_trusted_provider_cannot_sign_as_another() {
	// Both providers are trusted, each for itself. Provider two's valid signature on a
	// credential naming provider one must not pass: keys are scoped to their issuer.
	let w = World::new();
	let other = signer("pp-2");
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config
		.issuers
		.insert("did:web:pp-two.example".into(), jwks(&[&other]));
	let g = Guard::new(config, StateStore::memory());
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&other, &w.claims())), NOW).await),
		Denial::UntrustedIssuer(ISSUER.into())
	);
}

#[tokio::test]
async fn another_audience_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(w.claims(), "aud", json!("did:web:another-bank.example"));
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::WrongAudience
	);
}

#[tokio::test]
async fn an_audience_list_containing_this_gateway_is_accepted() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(w.claims(), "aud", json!(["did:web:other.example", AUD]));
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));
}

// ------------------------------------------------------------------ time

#[tokio::test]
async fn a_credential_not_yet_valid_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(w.claims(), "nbf", json!(NOW + SKEW + 1));
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::NotYetValid
	);
}

#[tokio::test]
async fn a_credential_issued_in_the_future_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(
		with(w.claims(), "iat", json!(NOW + SKEW + 1)),
		"nbf",
		json!(IAT),
	);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::IssuedInFuture
	);
}

// ------------------------------------------------------------------ assurance and factors

fn assurance(level: &str, method: &str) -> Value {
	json!({"level": level, "verifiedAt": "2026-01-09T00:00:30Z", "method": method})
}

#[tokio::test]
async fn assurance_below_the_tools_minimum_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-3"));
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await),
		Denial::AssuranceTooLow {
			required: PohpLevel::parse("HAPS-PoHP-3").unwrap(),
			presented: "HAPS-PoHP-2".into(),
		}
	);
}

#[tokio::test]
async fn an_unrecognised_assurance_level_is_denied() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-1"));
	let c = with(
		w.claims(),
		"assurance",
		assurance("HAPS-PoHP-9", "webauthn.uv"),
	);
	assert!(matches!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::AssuranceTooLow { .. }
	));
}

#[tokio::test]
async fn an_agent_accessible_factor_is_refused_from_pohp_2() {
	// FACTOR-RP-03 and FACTOR-PP-03: PoHP-2 requires human actuation, which an OTP cannot
	// supply, whatever level the provider asserts -- and even though it is certified for OTP.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with(
		w.claims(),
		"assurance",
		assurance("HAPS-PoHP-2", "otp.delivered"),
	);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::AgentAccessibleFactor("otp.delivered".into())
	);
}

#[tokio::test]
async fn an_agent_accessible_factor_is_accepted_at_pohp_1_when_policy_allows() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-1"));
	let c = with(
		w.claims(),
		"assurance",
		assurance("HAPS-PoHP-1", "otp.delivered"),
	);
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));
}

#[tokio::test]
async fn agent_resistance_can_be_required_below_pohp_2() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-1");
	p.require_agent_resistant = true;
	let g = w.guard(p);
	let c = with(
		w.claims(),
		"assurance",
		assurance("HAPS-PoHP-1", "otp.delivered"),
	);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::AgentAccessibleFactor("otp.delivered".into())
	);
}

#[tokio::test]
async fn an_unrecognised_factor_is_agent_accessible_unless_policy_says_otherwise() {
	// FACTOR-RP-02.
	let w = World::new();
	let c = with(
		w.claims(),
		"assurance",
		assurance("HAPS-PoHP-2", "vendor.example/palm"),
	);
	let g = w.guard(policy("HAPS-PoHP-2"));
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&c)), NOW).await),
		Denial::AgentAccessibleFactor("vendor.example/palm".into())
	);
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config.agent_resistant_methods = vec!["vendor.example/palm".into()];
	let g = Guard::new(config, StateStore::memory());
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));
}

#[tokio::test]
async fn a_factor_outside_the_accepted_list_is_refused() {
	// FACTOR-RP-01.
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.accepted_methods = Some(vec!["passkey.biometric".into()]);
	let g = w.guard(p);
	assert_eq!(
		denied(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await),
		Denial::FactorNotAccepted("webauthn.uv".into())
	);
}

// ------------------------------------------------------------------ certification

fn with_certification(claims: Value, pc: Value) -> Value {
	with(claims, "providerCertification", pc)
}

async fn certification_denial(w: &World, g: &Guard, claims: &Value) -> CertificationError {
	match denied(check(g, &approved_call(&w.sign(claims)), NOW).await) {
		Denial::Certification(e) => e,
		other => panic!("expected a certification denial, got {other:?}"),
	}
}

#[tokio::test]
async fn the_published_certification_covers_its_provider_level_and_factor() {
	// The vector README: a PoHP-2 webauthn.uv credential from provider-b is covered by the
	// published provider-b certification, and a liveness.active or PoHP-3 one is not.
	let w = World::new();
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config.certification.providers = HashMap::from([(ISSUER.to_owned(), "provider-b".to_owned())]);
	let g = Guard::new(config, StateStore::memory());
	let published: Value = serde_json::from_str(PCC_PROVIDER_B).unwrap();
	let pc = json!({"ref": "https://certs.certifier.example/pcc/provider-b/2026-01", "embedded": w.pcc(&published)});
	let c = with_certification(w.claims(), pc);
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));

	let c = with(c, "jti", json!("jti-0002"));
	let liveness = with(
		c.clone(),
		"assurance",
		assurance("HAPS-PoHP-2", "liveness.active"),
	);
	assert_eq!(
		certification_denial(&w, &g, &liveness).await,
		CertificationError::FactorNotCertified("liveness.active".into())
	);
	let level3 = with(c, "assurance", assurance("HAPS-PoHP-3", "webauthn.uv"));
	assert_eq!(
		certification_denial(&w, &g, &level3).await,
		CertificationError::LevelNotCertified("HAPS-PoHP-3".into())
	);
}

#[tokio::test]
async fn a_certification_neither_embedded_nor_provisioned_is_refused() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let c = with_certification(w.claims(), json!({"ref": PCC_REF}));
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::Unresolvable(PCC_REF.into())
	);
}

#[tokio::test]
async fn a_provisioned_certification_is_found_by_its_ref() {
	let w = World::new();
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config
		.certification
		.provisioned
		.insert(PCC_REF.into(), w.pcc(&w.pcc_claims()));
	let g = Guard::new(config, StateStore::memory());
	let c = with_certification(w.claims(), json!({"ref": PCC_REF}));
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));
}

#[tokio::test]
async fn a_certification_from_an_untrusted_certifier_is_refused() {
	// The provider certifying itself is the case certification exists to rule out.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let self_certified = sign(&w.pp, &w.pcc_claims());
	let c = with_certification(
		w.claims(),
		json!({"ref": PCC_REF, "embedded": self_certified}),
	);
	assert!(matches!(
		certification_denial(&w, &g, &c).await,
		CertificationError::Signature(_)
	));
}

#[tokio::test]
async fn a_certification_for_another_provider_is_refused() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let pcc = with(w.pcc_claims(), "providerId", json!("provider-z"));
	let c = with_certification(w.claims(), json!({"ref": PCC_REF, "embedded": w.pcc(&pcc)}));
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::WrongProvider {
			expected: PROVIDER.into(),
			certified: "provider-z".into()
		}
	);
}

#[tokio::test]
async fn an_issuer_with_no_provider_mapping_cannot_be_certified() {
	let w = World::new();
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config.certification.providers.clear();
	let g = Guard::new(config, StateStore::memory());
	assert_eq!(
		certification_denial(&w, &g, &w.claims()).await,
		CertificationError::UnknownProvider(ISSUER.into())
	);
}

#[tokio::test]
async fn an_expired_or_future_certification_is_refused() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let expired = with(w.pcc_claims(), "expiresAt", json!("2026-01-08T00:00:00Z"));
	let c = with_certification(
		w.claims(),
		json!({"ref": PCC_REF, "embedded": w.pcc(&expired)}),
	);
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::Expired
	);
	let future = with(w.pcc_claims(), "issuedAt", json!("2026-02-01T00:00:00Z"));
	let c = with_certification(
		w.claims(),
		json!({"ref": PCC_REF, "embedded": w.pcc(&future)}),
	);
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::NotYetValid
	);
}

#[tokio::test]
async fn a_certification_naming_no_evaluation_is_not_evidence() {
	// §16.1.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let mut pcc = w.pcc_claims();
	pcc.as_object_mut().unwrap().remove("evaluation");
	let c = with_certification(w.claims(), json!({"ref": PCC_REF, "embedded": w.pcc(&pcc)}));
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::NoEvaluation
	);
	let blank = with(w.pcc_claims(), "evaluation", json!({"lab": " "}));
	let c = with_certification(
		w.claims(),
		json!({"ref": PCC_REF, "embedded": w.pcc(&blank)}),
	);
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::NoEvaluation
	);
}

#[tokio::test]
async fn a_certification_hash_must_match_its_claims() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let embedded = w.pcc(&w.pcc_claims());
	let right = hash_json(&w.pcc_claims());
	let c = with_certification(
		w.claims(),
		json!({"ref": PCC_REF, "embedded": embedded, "hash": right}),
	);
	assert!(is_approved(
		&check(&g, &approved_call(&w.sign(&c)), NOW).await
	));
	let c = with_certification(
		with(w.claims(), "jti", json!("jti-0002")),
		json!({"ref": PCC_REF, "embedded": embedded, "hash": "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
	);
	assert_eq!(
		certification_denial(&w, &g, &c).await,
		CertificationError::HashMismatch
	);
}

// ------------------------------------------------------------------ RP-CORE-08: envelopes

#[tokio::test]
async fn an_envelope_the_tool_has_no_rules_for_cannot_be_honoured() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.envelope_rules.clear();
	let g = w.guard(p);
	assert!(matches!(
		denied(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await),
		Denial::Envelope(EnvelopeError::Unenforceable(_))
	));
}

fn envelope_policy() -> ToolPolicy {
	let mut p = policy("HAPS-PoHP-2");
	p.binding = ArgumentBinding::Envelope;
	p
}

#[tokio::test]
async fn envelope_binding_admits_variation_within_the_envelope() {
	let w = World::new();
	let g = w.guard(envelope_policy());
	let mut args = approved_arguments();
	args["amount"]["value"] = json!("275.00");
	let (params, audit) = approved(
		check(
			&g,
			&call(TOOL, args.clone(), Some(meta(&w.sign(&w.claims())))),
			NOW,
		)
		.await,
	);
	let mut varied = audit.varied_within_envelope;
	varied.sort();
	assert_eq!(varied, ["/amount", "/to"]);
	// What runs is the call as made, not the approved original.
	let forwarded: Value = serde_json::from_slice(&params).unwrap();
	assert_eq!(forwarded["arguments"]["amount"]["value"], "275.00");
}

#[tokio::test]
async fn envelope_binding_refuses_variation_outside_the_envelope() {
	let w = World::new();
	let g = w.guard(envelope_policy());
	let mut args = approved_arguments();
	args["amount"]["value"] = json!("300.01");
	assert!(matches!(
		denied(check(&g, &call(TOOL, args, Some(meta(&w.sign(&w.claims())))), NOW).await),
		Denial::Envelope(EnvelopeError::Outside { .. })
	));
}

#[tokio::test]
async fn envelope_binding_still_binds_everything_the_envelope_does_not_govern() {
	let w = World::new();
	let g = w.guard(envelope_policy());
	let mut args = approved_arguments();
	args["reference"] = json!("Invoice 99999");
	assert_eq!(
		denied(check(&g, &call(TOOL, args, Some(meta(&w.sign(&w.claims())))), NOW).await),
		Denial::ArgumentsDoNotMatchApproval
	);
}

// ------------------------------------------------------------------ RP-CORE-07: replay

#[tokio::test]
async fn an_approval_cannot_be_used_twice() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let params = approved_call(&w.sign(&w.claims()));
	assert!(is_approved(&check(&g, &params, NOW).await));
	assert_eq!(denied(check(&g, &params, NOW + 1).await), Denial::Replayed);
}

#[tokio::test]
async fn a_rejected_attempt_does_not_consume_the_approval() {
	// A tampered replay must not burn the legitimate approval it was copied from.
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let credential = w.sign(&w.claims());
	let mut tampered = approved_arguments();
	tampered["urgent"] = json!(true);
	assert_eq!(
		denied(check(&g, &call(TOOL, tampered, Some(meta(&credential))), NOW).await),
		Denial::ArgumentsDoNotMatchApproval
	);
	assert!(is_approved(
		&check(&g, &approved_call(&credential), NOW + 1).await
	));
}

#[tokio::test]
async fn distinct_approvals_are_independent() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let a = approved_call(&w.sign(&w.claims()));
	let b = approved_call(&w.sign(&with(w.claims(), "jti", json!("jti-0002"))));
	assert!(is_approved(&check(&g, &a, NOW).await));
	assert!(is_approved(&check(&g, &b, NOW).await));
}

fn multi_use_intent(max_uses: u32) -> Value {
	let mut i = intent();
	i["constraints"]["oneTime"] = json!(false);
	i["constraints"]["maxUses"] = json!(max_uses);
	i
}

#[tokio::test]
async fn max_uses_is_honoured_when_the_tool_allows_multi_use() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.allow_multi_use = true;
	let g = w.guard(p);
	let i = multi_use_intent(2);
	let params = call(
		TOOL,
		approved_arguments(),
		Some(meta_for(&w.sign(&w.claims_for(&i)), &i, None)),
	);
	assert!(is_approved(&check(&g, &params, NOW).await));
	assert!(is_approved(&check(&g, &params, NOW).await));
	assert_eq!(denied(check(&g, &params, NOW).await), Denial::Replayed);
}

#[tokio::test]
async fn every_approval_is_single_use_unless_the_tool_allows_more() {
	let w = World::new();
	let g = w.guard(policy("HAPS-PoHP-2"));
	let i = multi_use_intent(2);
	let params = call(
		TOOL,
		approved_arguments(),
		Some(meta_for(&w.sign(&w.claims_for(&i)), &i, None)),
	);
	assert!(is_approved(&check(&g, &params, NOW).await));
	assert_eq!(denied(check(&g, &params, NOW).await), Denial::Replayed);
}

#[tokio::test]
async fn one_time_wins_over_max_uses() {
	let w = World::new();
	let mut p = policy("HAPS-PoHP-2");
	p.allow_multi_use = true;
	let g = w.guard(p);
	let mut i = multi_use_intent(5);
	i["constraints"]["oneTime"] = json!(true);
	let params = call(
		TOOL,
		approved_arguments(),
		Some(meta_for(&w.sign(&w.claims_for(&i)), &i, None)),
	);
	assert!(is_approved(&check(&g, &params, NOW).await));
	assert_eq!(denied(check(&g, &params, NOW).await), Denial::Replayed);
}

// ------------------------------------------------------------------ RP-CORE-09: challenges

fn challenge_policy() -> ToolPolicy {
	let mut p = policy("HAPS-PoHP-2");
	p.challenge_mode = true;
	// Intents the guard builds carry no envelope.
	p.envelope_rules.clear();
	p
}

/// Ask for approval of `args` and return the challenge the guard issued.
async fn challenge_for(g: &Guard, args: &Value, now: u64) -> Value {
	let (_, e) = elicited(check(g, &call(TOOL, args.clone(), None), now).await);
	e["haps/challenge"].clone()
}

/// What a Presence Provider returns after the human approves `challenge`.
fn answer(w: &World, challenge: &Value, jti: &str) -> (String, Value) {
	let intent = challenge["actionIntent"].clone();
	let c = with(
		with(
			w.claims_for(&intent),
			"challengeId",
			challenge["challengeId"].clone(),
		),
		"jti",
		json!(jti),
	);
	(w.sign(&c), intent)
}

#[tokio::test]
async fn challenge_mode_issues_a_challenge_for_exactly_this_call() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = approved_arguments();
	let (reason, e) = elicited(check(&g, &call(TOOL, args.clone(), None), NOW).await);
	assert_eq!(reason, "approval required for this call");
	let ch = &e["haps/challenge"];
	let id = ch["challengeId"].as_str().unwrap();
	assert!(uuid::Uuid::parse_str(id).is_ok(), "{id}");
	assert_eq!(ch["version"], "0.4");
	assert_eq!(ch["expiresAt"], "2026-01-09T00:05:30Z");
	assert_eq!(ch["requirements"]["pohp"]["minLevel"], "HAPS-PoHP-2");
	let intent = &ch["actionIntent"];
	assert_eq!(intent["action"]["type"], "payment.transfer");
	assert_eq!(hash_json(&intent["action"]["parameters"]), hash_json(&args));
	assert_eq!(intent["audience"]["id"], AUD);
	assert_eq!(intent["agent"]["name"], "Treasury Agent");
	assert_eq!(intent["constraints"]["oneTime"], true);
	assert_eq!(intent["display"]["title"], "Approve transfer_funds");
	// The URL carries the challenge to the Presence Provider, canonical and base64url-encoded.
	let el = &e["elicitations"][0];
	assert_eq!(el["elicitationId"], id);
	let url = el["url"].as_str().unwrap();
	assert!(
		url.starts_with(&format!(
			"https://pp.example/approve?challengeId={id}&challenge="
		)),
		"{url}"
	);
	let encoded = url.rsplit("challenge=").next().unwrap();
	let decoded: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
	assert_eq!(&decoded, ch);
}

#[tokio::test]
async fn an_answered_challenge_is_approved_once() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = approved_arguments();
	let ch = challenge_for(&g, &args, NOW).await;
	let (credential, intent) = answer(&w, &ch, "jti-c1");
	let params = call(
		TOOL,
		args.clone(),
		Some(meta_for(&credential, &intent, None)),
	);
	let (_, audit) = approved(check(&g, &params, NOW + 5).await);
	assert_eq!(audit.challenge_id.as_deref(), ch["challengeId"].as_str());
	// A second credential for the same challenge finds it spent.
	let (credential, intent) = answer(&w, &ch, "jti-c2");
	let params = call(TOOL, args, Some(meta_for(&credential, &intent, None)));
	assert_eq!(
		denied(check(&g, &params, NOW + 6).await),
		Denial::ChallengeUnknown
	);
}

#[tokio::test]
async fn challenge_mode_re_elicits_an_agent_initiated_approval() {
	let w = World::new();
	let mut p = challenge_policy();
	p.envelope_rules = payment_rules();
	let g = w.guard(p);
	let (reason, e) = elicited(check(&g, &approved_call(&w.sign(&w.claims())), NOW).await);
	assert_eq!(
		reason,
		"this tool accepts only approvals issued for a gateway challenge"
	);
	assert!(e["haps/challenge"]["challengeId"].is_string());
}

#[tokio::test]
async fn a_challenge_the_guard_never_issued_is_refused() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let mut i = intent();
	i["constraints"].as_object_mut().unwrap().remove("envelope");
	let forged = json!({"challengeId": "6f1b9c36-4c3b-4e0b-8a78-83fd8c12c710", "actionIntent": i});
	let (credential, i) = answer(&w, &forged, "jti-c1");
	let params = call(
		TOOL,
		approved_arguments(),
		Some(meta_for(&credential, &i, None)),
	);
	assert_eq!(
		denied(check(&g, &params, NOW).await),
		Denial::ChallengeUnknown
	);
}

#[tokio::test]
async fn a_credential_must_answer_the_challenge_for_its_own_intent() {
	// Two challenges for the same call carry different intents. A credential naming one
	// challenge but approving the other's intent is refused.
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = approved_arguments();
	let first = challenge_for(&g, &args, NOW).await;
	let second = challenge_for(&g, &args, NOW).await;
	let intent = second["actionIntent"].clone();
	let c = with(
		w.claims_for(&intent),
		"challengeId",
		first["challengeId"].clone(),
	);
	let params = call(TOOL, args, Some(meta_for(&w.sign(&c), &intent, None)));
	assert_eq!(
		denied(check(&g, &params, NOW).await),
		Denial::ChallengeMismatch
	);
}

#[tokio::test]
async fn an_expired_challenge_cannot_be_answered() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = approved_arguments();
	let ch = challenge_for(&g, &args, NOW).await;
	let intent = ch["actionIntent"].clone();
	let c = with(
		with(
			w.claims_for(&intent),
			"challengeId",
			ch["challengeId"].clone(),
		),
		"exp",
		json!(NOW + 3600),
	);
	let params = call(TOOL, args, Some(meta_for(&w.sign(&c), &intent, None)));
	// Past the challenge's expiry, still inside the intent's expiry plus skew.
	assert_eq!(
		denied(check(&g, &params, NOW + 300 + 1).await),
		Denial::ChallengeUnknown
	);
}

#[tokio::test]
async fn a_refused_answer_does_not_spend_the_challenge() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = approved_arguments();
	let ch = challenge_for(&g, &args, NOW).await;
	let (credential, intent) = answer(&w, &ch, "jti-c1");
	let mut tampered = args.clone();
	tampered["reference"] = json!("Invoice 99999");
	let bad = call(TOOL, tampered, Some(meta_for(&credential, &intent, None)));
	assert_eq!(
		denied(check(&g, &bad, NOW).await),
		Denial::ArgumentsDoNotMatchApproval
	);
	let good = call(TOOL, args, Some(meta_for(&credential, &intent, None)));
	assert!(is_approved(&check(&g, &good, NOW).await));
}

#[tokio::test]
async fn a_signed_challenge_carries_a_verifiable_rp_proof() {
	let w = World::new();
	let rp = signer("rp-1");
	let mut config = w.config(challenge_policy());
	config.rp_signer = Some(RpSigner {
		kid: rp.kid.clone(),
		key: rp.key.clone(),
	});
	let g = Guard::new(config, StateStore::memory());
	let ch = challenge_for(&g, &approved_arguments(), NOW).await;
	let proof = &ch["rpProof"];
	assert_eq!(proof["kid"], "rp-1");
	let jwk = &jwks(&[&rp]).keys[0];
	let mut v = Validation::new(Algorithm::EdDSA);
	v.required_spec_claims.clear();
	v.validate_exp = false;
	let payload: Value = jsonwebtoken::decode(
		proof["jws"].as_str().unwrap(),
		&DecodingKey::from_jwk(jwk).unwrap(),
		&v,
	)
	.unwrap()
	.claims;
	let mut unsigned = ch.clone();
	unsigned.as_object_mut().unwrap().remove("rpProof");
	assert_eq!(payload, unsigned);
}

#[tokio::test]
async fn a_call_too_large_to_summarise_is_refused_rather_than_summarised_partially() {
	let w = World::new();
	let g = w.guard(challenge_policy());
	let args = json!({"note": "x".repeat(700)});
	assert!(matches!(
		denied(check(&g, &call(TOOL, args, None), NOW).await),
		Denial::ChallengeUnbuildable(_)
	));
}

// ------------------------------------------------------------------ the store

#[test]
fn a_jti_and_a_challenge_are_spent_together_or_not_at_all() {
	let m = MemoryStore::default();
	let s = StateStore::Memory(m);
	let rt = tokio::runtime::Builder::new_current_thread()
		.build()
		.unwrap();
	rt.block_on(async {
		let gone = Consume {
			jti: "j1".into(),
			max_uses: Some(1),
			retain_until: NOW + 100,
			challenge_id: Some("never-issued".into()),
		};
		assert_eq!(
			s.consume(&gone, NOW).await.unwrap(),
			ConsumeOutcome::ChallengeGone
		);
		// The failed consume did not spend the jti.
		let plain = Consume {
			challenge_id: None,
			..gone
		};
		assert_eq!(
			s.consume(&plain, NOW).await.unwrap(),
			ConsumeOutcome::Consumed
		);
		assert_eq!(
			s.consume(&plain, NOW).await.unwrap(),
			ConsumeOutcome::Replayed
		);
		// Retained until `retain_until`, then forgotten.
		assert_eq!(
			s.consume(&plain, NOW + 101).await.unwrap(),
			ConsumeOutcome::Consumed
		);
	});
}

#[test]
fn outstanding_challenges_are_capped() {
	let s = StateStore::memory();
	let rt = tokio::runtime::Builder::new_current_thread()
		.build()
		.unwrap();
	rt.block_on(async {
		let record = ChallengeRecord {
			tool: TOOL.into(),
			intent_hash: "sha256:x".into(),
			expires_at: NOW + 300,
		};
		for i in 0..crate::store::MAX_OUTSTANDING_CHALLENGES {
			s.put_challenge(&i.to_string(), &record, NOW).await.unwrap();
		}
		assert!(matches!(
			s.put_challenge("one-more", &record, NOW).await,
			Err(crate::store::StoreError::Full)
		));
		// Expired challenges make room.
		s.put_challenge("later", &record, NOW + 301).await.unwrap();
	});
}

mod redis_store;

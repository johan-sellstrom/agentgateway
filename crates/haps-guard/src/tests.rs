use std::collections::HashMap;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

use super::*;

// The published HAPS v0.4 payment vector. Accepting a credential that carries the
// *published* hashes ties the guard to the specification rather than to its own hash code.
const INTENT: &str = include_str!(
	"../../../../HAPP-reference/test_vectors/v0.4/action-intent.payment.transfer.sample.json"
);
const VIEW: &str = include_str!(
	"../../../../HAPP-reference/test_vectors/v0.4/signing-view.payment.transfer.sample.json"
);
const INTENT_HASH: &str =
	include_str!("../../../../HAPP-reference/test_vectors/v0.4/expected_intent_hash.txt");
const VIEW_HASH: &str =
	include_str!("../../../../HAPP-reference/test_vectors/v0.4/expected_presentation_hash.txt");

const AUD: &str = "did:web:bank.example";
const ISSUER: &str = "did:web:pp.example";
const IAT: u64 = 1_767_916_800;
const EXP: u64 = 1_767_916_920;
const NOW: u64 = IAT + 30;
const SKEW: u64 = 60;
const TOOL: &str = "transfer_funds";

struct Provider {
	kid: String,
	x: String,
	key: EncodingKey,
}

fn provider(kid: &str) -> Provider {
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
	let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pkcs8");
	Provider {
		kid: kid.to_owned(),
		x: haps_hash::base64url_unpadded(pair.public_key().as_ref()),
		key: EncodingKey::from_ed_der(pkcs8.as_ref()),
	}
}

fn jwks(providers: &[&Provider]) -> JwkSet {
	let keys: Vec<Value> = providers
		.iter()
		.map(|p| json!({"kty": "OKP", "crv": "Ed25519", "kid": p.kid, "alg": "EdDSA", "use": "sig", "x": p.x}))
		.collect();
	serde_json::from_value(json!({ "keys": keys })).expect("jwks")
}

fn claims() -> Value {
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
		"providerCertification": {"certifier": "did:web:certs.certifier.example", "id": "cert-1"},
	})
}

fn with(mut base: Value, key: &str, value: Value) -> Value {
	base[key] = value;
	base
}

fn sign(p: &Provider, claims: &Value) -> String {
	let mut header = Header::new(Algorithm::EdDSA);
	header.kid = Some(p.kid.clone());
	jsonwebtoken::encode(&header, claims, &p.key).expect("sign")
}

fn guard_with(keys: JwkSet, min_level: &str) -> Guard {
	Guard::new(GuardConfig {
		tools: HashMap::from([(
			TOOL.to_owned(),
			ToolPolicy {
				action_type: "payment.transfer".into(),
				min_level: PohpLevel::parse(min_level).unwrap(),
			},
		)]),
		keys,
		issuers: vec![ISSUER.into()],
		audience: AUD.into(),
		elicitation_url: "https://pp.example/approve".into(),
		clock_skew_secs: SKEW,
	})
}

/// The approved `action.parameters`, taken from the published intent.
fn approved_arguments() -> Value {
	serde_json::from_str::<Value>(INTENT).unwrap()["action"]["parameters"].clone()
}

fn meta(credential: &str) -> Value {
	json!({
		META_CREDENTIAL: credential,
		META_ACTION_INTENT: serde_json::from_str::<Value>(INTENT).unwrap(),
		META_SIGNING_VIEW: serde_json::from_str::<Value>(VIEW).unwrap(),
	})
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

fn check(g: &Guard, params: &[u8], now: u64) -> Decision {
	g.check("tools/call", Some(params), now)
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

// ------------------------------------------------------------------ acceptance

#[test]
fn a_credential_carrying_the_published_hashes_is_accepted() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let Decision::Approved { params, audit } = check(&g, &approved_call(&sign(&pp, &claims())), NOW)
	else {
		panic!("expected Approved");
	};
	assert_eq!(
		audit,
		Audit {
			jti: "jti-0001".into(),
			issuer: ISSUER.into(),
			level: "HAPS-PoHP-2".into(),
			action_type: "payment.transfer".into(),
		}
	);
	// The upstream receives exactly the approved arguments, and never the credential.
	let forwarded: Value = serde_json::from_slice(&params).unwrap();
	// Emptied but present: an absent `_meta` would tell the gateway to keep the original.
	assert_eq!(forwarded["_meta"], json!({}), "{forwarded}");
	let fwd_args = serde_json::to_string(&forwarded["arguments"]).unwrap();
	let appr_args = serde_json::to_string(&approved_arguments()).unwrap();
	assert_eq!(
		haps_canon::canonicalize(&haps_canon::parse(&fwd_args).unwrap()),
		haps_canon::canonicalize(&haps_canon::parse(&appr_args).unwrap()),
	);
}

#[test]
fn other_meta_keys_survive_and_only_haps_keys_are_stripped() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut m = meta(&sign(&pp, &claims()));
	m["progressToken"] = json!("tok-7");
	let Decision::Approved { params, .. } =
		check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW)
	else {
		panic!("expected Approved");
	};
	let forwarded: Value = serde_json::from_slice(&params).unwrap();
	assert_eq!(forwarded["_meta"], json!({"progressToken": "tok-7"}));
}

#[test]
fn a_float_elsewhere_in_meta_does_not_make_the_request_unreadable() {
	// Only the arguments and the approval are parsed strictly.
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut m = meta(&sign(&pp, &claims()));
	m["vendor.example/progress"] = json!(0.25);
	assert!(matches!(
		check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW),
		Decision::Approved { .. }
	));
}

#[test]
fn skew_admits_a_credential_just_past_expiry() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	assert!(matches!(
		check(&g, &approved_call(&sign(&pp, &claims())), EXP + SKEW),
		Decision::Approved { .. }
	));
}

// ------------------------------------------------------------------ not gated

#[test]
fn an_ungated_tool_passes_untouched() {
	let g = guard_with(jwks(&[]), "HAPS-PoHP-2");
	assert!(matches!(
		check(&g, &call("echo", json!({"hi": "world"}), None), NOW),
		Decision::NotGated
	));
}

#[test]
fn methods_other_than_tools_call_are_not_gated() {
	let g = guard_with(jwks(&[]), "HAPS-PoHP-2");
	assert!(matches!(
		g.check("tools/list", None, NOW),
		Decision::NotGated
	));
}

// ------------------------------------------------------------------ elicitation

#[test]
fn a_gated_call_without_approval_elicits_the_provider() {
	let g = guard_with(jwks(&[]), "HAPS-PoHP-2");
	let (reason, e) = elicited(check(&g, &call(TOOL, approved_arguments(), None), NOW));
	assert_eq!(reason, "approval required for this call");
	let el = &e["elicitations"][0];
	assert_eq!(el["mode"], "url");
	let id = el["elicitationId"].as_str().unwrap();
	assert!(id.starts_with("sha256:"), "{id}");
	assert_eq!(
		el["url"].as_str().unwrap(),
		format!("https://pp.example/approve?elicitationId={id}")
	);
}

#[test]
fn the_elicitation_id_is_a_content_address_of_the_call() {
	let g = guard_with(jwks(&[]), "HAPS-PoHP-2");
	let id = |args: Value| {
		elicited(check(&g, &call(TOOL, args, None), NOW)).1["elicitations"][0]["elicitationId"]
			.as_str()
			.unwrap()
			.to_owned()
	};
	let base = approved_arguments();
	let mut other = base.clone();
	other["reference"] = json!("Invoice 99999");
	assert_eq!(id(base.clone()), id(base.clone()), "same call, same id");
	assert_ne!(id(base), id(other), "different call, different id");
}

#[test]
fn an_expired_approval_is_re_elicited_not_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let (reason, _) = elicited(check(
		&g,
		&approved_call(&sign(&pp, &claims())),
		EXP + SKEW + 1,
	));
	assert_eq!(reason, "approval expired");
}

#[test]
fn a_fractional_argument_is_rejected_before_anything_is_elicited() {
	// RP-CORE-04a: such a call can never be bound, so eliciting it would be pointless.
	let g = guard_with(jwks(&[]), "HAPS-PoHP-2");
	let args = json!({"amount": {"currency": "GBP", "value": 250.75}});
	assert!(matches!(
		denied(check(&g, &call(TOOL, args, None), NOW)),
		Denial::MalformedArguments(_)
	));
}

// ------------------------------------------------------------------ binding

#[test]
fn a_tampered_argument_is_denied() {
	// The case the whole integration exists for: approved £250.00, agent sends £2500.00.
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut args = approved_arguments();
	args["amount"]["value"] = json!("2500.00");
	let params = call(TOOL, args, Some(meta(&sign(&pp, &claims()))));
	assert_eq!(
		denied(check(&g, &params, NOW)),
		Denial::ArgumentsDoNotMatchApproval
	);
}

#[test]
fn a_changed_payee_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut args = approved_arguments();
	args["to"]["iban"] = json!("GB00ATTACKER000000000000000");
	let params = call(TOOL, args, Some(meta(&sign(&pp, &claims()))));
	assert_eq!(
		denied(check(&g, &params, NOW)),
		Denial::ArgumentsDoNotMatchApproval
	);
}

#[test]
fn an_added_argument_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut args = approved_arguments();
	args["urgent"] = json!(true);
	let params = call(TOOL, args, Some(meta(&sign(&pp, &claims()))));
	assert_eq!(
		denied(check(&g, &params, NOW)),
		Denial::ArgumentsDoNotMatchApproval
	);
}

#[test]
fn key_order_and_whitespace_do_not_matter() {
	// Canonicalisation, not byte-equality of what the agent happened to send.
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let reordered = json!({
		"reference": "Invoice 18372",
		"to": {"name": "Example Supplier Ltd", "iban": "GB00EXAMP1E00000000000000"},
		"amount": {"value": "250.00", "currency": "GBP"},
	});
	assert!(matches!(
		check(
			&g,
			&call(TOOL, reordered, Some(meta(&sign(&pp, &claims())))),
			NOW
		),
		Decision::Approved { .. }
	));
}

#[test]
fn an_approval_for_another_action_type_is_denied() {
	let pp = provider("pp-1");
	let mut g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	g.config.tools.get_mut(TOOL).unwrap().action_type = "payee.create".into();
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &claims())), NOW)),
		Denial::WrongActionType {
			expected: "payee.create".into()
		}
	);
}

#[test]
fn an_intent_modified_after_signing_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut m = meta(&sign(&pp, &claims()));
	m[META_ACTION_INTENT]["display"]["summary"] = json!("Approve a £2,500.00 transfer");
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW)),
		Denial::IntentHashMismatch
	);
}

#[test]
fn a_signing_view_modified_after_signing_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut m = meta(&sign(&pp, &claims()));
	m[META_SIGNING_VIEW] = json!({"title": "Something else entirely"});
	assert_eq!(
		denied(check(&g, &call(TOOL, approved_arguments(), Some(m)), NOW)),
		Denial::PresentationHashMismatch
	);
}

// ------------------------------------------------------------------ signature and trust

#[test]
fn a_signature_by_another_key_is_denied() {
	// Signed by an attacker's key but claiming the trusted provider's `kid`.
	let pp = provider("pp-1");
	let attacker = Provider {
		kid: "pp-1".into(),
		..provider("attacker")
	};
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&attacker, &claims())), NOW)),
		Denial::BadSignature
	);
}

#[test]
fn an_unknown_key_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let stranger = provider("pp-unknown");
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&stranger, &claims())), NOW)),
		Denial::UnknownKey
	);
}

#[test]
fn a_symmetric_algorithm_is_rejected_before_key_lookup() {
	// HS256 would need the gateway to hold the provider's signing secret.
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let mut header = Header::new(Algorithm::HS256);
	header.kid = Some("pp-1".into());
	let forged =
		jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_secret(b"guessable")).unwrap();
	assert!(matches!(
		denied(check(&g, &approved_call(&forged), NOW)),
		Denial::UnsupportedAlgorithm(_)
	));
}

#[test]
fn an_untrusted_issuer_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let c = with(claims(), "issuer", json!("did:web:rogue.example"));
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &c)), NOW)),
		Denial::UntrustedIssuer("did:web:rogue.example".into())
	);
}

#[test]
fn another_audience_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let c = with(claims(), "aud", json!("did:web:another-bank.example"));
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &c)), NOW)),
		Denial::WrongAudience
	);
}

#[test]
fn an_audience_list_containing_this_gateway_is_accepted() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let c = with(claims(), "aud", json!(["did:web:other.example", AUD]));
	assert!(matches!(
		check(&g, &approved_call(&sign(&pp, &c)), NOW),
		Decision::Approved { .. }
	));
}

// ------------------------------------------------------------------ time

#[test]
fn a_credential_not_yet_valid_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let c = with(claims(), "nbf", json!(NOW + SKEW + 1));
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &c)), NOW)),
		Denial::NotYetValid
	);
}

#[test]
fn a_credential_issued_in_the_future_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let c = with(
		with(claims(), "iat", json!(NOW + SKEW + 1)),
		"nbf",
		json!(IAT),
	);
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &c)), NOW)),
		Denial::IssuedInFuture
	);
}

// ------------------------------------------------------------------ assurance

#[test]
fn assurance_below_the_tools_minimum_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-3");
	assert_eq!(
		denied(check(&g, &approved_call(&sign(&pp, &claims())), NOW)),
		Denial::AssuranceTooLow {
			required: PohpLevel::parse("HAPS-PoHP-3").unwrap(),
			presented: "HAPS-PoHP-2".into(),
		}
	);
}

#[test]
fn an_unrecognised_assurance_level_is_denied() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-1");
	let c = with(
		claims(),
		"assurance",
		json!({"level": "HAPS-PoHP-9", "verifiedAt": "x", "method": "y"}),
	);
	assert!(matches!(
		denied(check(&g, &approved_call(&sign(&pp, &c)), NOW)),
		Denial::AssuranceTooLow { .. }
	));
}

// ------------------------------------------------------------------ replay

#[test]
fn an_approval_cannot_be_used_twice() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let params = approved_call(&sign(&pp, &claims()));
	assert!(matches!(check(&g, &params, NOW), Decision::Approved { .. }));
	assert_eq!(denied(check(&g, &params, NOW + 1)), Denial::Replayed);
}

#[test]
fn a_rejected_attempt_does_not_consume_the_approval() {
	// A tampered replay must not burn the legitimate approval it was copied from.
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let credential = sign(&pp, &claims());
	let mut tampered = approved_arguments();
	tampered["amount"]["value"] = json!("2500.00");
	assert_eq!(
		denied(check(
			&g,
			&call(TOOL, tampered, Some(meta(&credential))),
			NOW
		)),
		Denial::ArgumentsDoNotMatchApproval
	);
	assert!(matches!(
		check(&g, &approved_call(&credential), NOW + 1),
		Decision::Approved { .. }
	));
}

#[test]
fn distinct_approvals_are_independent() {
	let pp = provider("pp-1");
	let g = guard_with(jwks(&[&pp]), "HAPS-PoHP-2");
	let a = approved_call(&sign(&pp, &claims()));
	let b = approved_call(&sign(&pp, &with(claims(), "jti", json!("jti-0002"))));
	assert!(matches!(check(&g, &a, NOW), Decision::Approved { .. }));
	assert!(matches!(check(&g, &b, NOW), Decision::Approved { .. }));
}

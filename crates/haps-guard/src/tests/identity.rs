//! HAPS-RP-ID-0.4: identity binding with an EUDI wallet presentation or a Google identity.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::*;
use crate::identity::{
	CredentialIssuer, EudiTrust, GoogleTrust, IdentityError, IdentityPolicy, IdentityTrust,
	KeySource, SCHEME_EUDI, SCHEME_GOOGLE, Scheme, thumbprint,
};

const GOOGLE_KEY: &str = include_str!("../../testdata/identity/google-test-key.pem");
const GOOGLE_JWKS: &str = include_str!("../../testdata/identity/google-test-jwks.json");
const CLIENT_ID: &str = "pp-client.apps.googleusercontent.com";
const PID_ISSUER: &str = "https://pid.example";
const PID_VCT: &str = "urn:eudi:pid:1";
/// The gateway metadata key carrying the caller's account.
const ACCOUNT: &str = "account";
const EMAIL: &str = "alice@example.com";

fn b64(bytes: &[u8]) -> String {
	URL_SAFE_NO_PAD.encode(bytes)
}

/// A P-256 key: a PID issuer's, or a wallet's device key.
struct Ec {
	kid: String,
	key: EncodingKey,
	jwk: Value,
}

fn ec(kid: &str) -> Ec {
	let pkcs8 =
		EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).unwrap();
	let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
	let point = pair.public_key().as_ref();
	Ec {
		kid: kid.into(),
		key: EncodingKey::from_ec_der(pkcs8.as_ref()),
		jwk: json!({"kty": "EC", "crv": "P-256", "x": b64(&point[1..33]), "y": b64(&point[33..65])}),
	}
}

fn sign_typed(
	key: &EncodingKey,
	alg: Algorithm,
	kid: Option<&str>,
	typ: &str,
	claims: &Value,
) -> String {
	let mut header = Header::new(alg);
	header.typ = Some(typ.into());
	header.kid = kid.map(Into::into);
	jsonwebtoken::encode(&header, claims, key).unwrap()
}

/// Who signs a credential, as whom, for what.
struct Minted<'a> {
	issuer: &'a Ec,
	iss: &'a str,
	vct: &'a str,
}

/// Parties: the guard's usual provider and certifier, a PID issuer, and a wallet.
struct IdWorld {
	w: World,
	pid_issuer: Ec,
	wallet: Ec,
}

impl IdWorld {
	fn new() -> Self {
		Self {
			w: World::new(),
			pid_issuer: ec("pid-1"),
			wallet: ec("device"),
		}
	}

	fn trust(&self) -> IdentityTrust {
		let mut issuer_jwk = self.pid_issuer.jwk.clone();
		issuer_jwk["kid"] = json!(self.pid_issuer.kid);
		issuer_jwk["alg"] = json!("ES256");
		IdentityTrust {
			google: Some(GoogleTrust {
				client_ids: vec![CLIENT_ID.into()],
				keys: Arc::new(KeySource::new(serde_json::from_str(GOOGLE_JWKS).unwrap())),
			}),
			eudi: Some(EudiTrust {
				issuers: HashMap::from([(
					PID_ISSUER.to_owned(),
					CredentialIssuer {
						keys: serde_json::from_value(json!({"keys": [issuer_jwk]})).unwrap(),
						vcts: vec![PID_VCT.into()],
					},
				)]),
				verifier_client_ids: HashMap::new(),
			}),
		}
	}

	fn guard(&self, identity: IdentityPolicy) -> Guard {
		let mut p = policy("HAPS-PoHP-2");
		p.identity = Some(identity);
		self.guard_with(p)
	}

	fn guard_with(&self, p: ToolPolicy) -> Guard {
		let mut config = self.w.config(p);
		config.identity = self.trust();
		Guard::new(config, StateStore::memory())
	}

	/// A call approved by a credential carrying `binding`.
	fn call(&self, binding: Option<Value>) -> Vec<u8> {
		let mut c = self.w.claims();
		if let Some(b) = binding {
			c["identityBinding"] = b;
		}
		approved_call(&self.w.sign(&c))
	}

	// -------------------------------------------------------------- Google

	fn id_token(&self, overrides: Value) -> String {
		let mut claims = json!({
			"iss": "https://accounts.google.com",
			"aud": CLIENT_ID,
			"sub": "1234567890",
			"email": "Alice@Example.com",
			"email_verified": true,
			// Bound to this approval: the credential's intent_hash, there being no challenge.
			"nonce": INTENT_HASH.trim(),
			"iat": IAT - 20,
			"exp": IAT + 3600,
			"auth_time": IAT - 30,
		});
		for (k, v) in overrides.as_object().unwrap() {
			claims[k] = v.clone();
		}
		sign_typed(
			&EncodingKey::from_rsa_pem(GOOGLE_KEY.as_bytes()).unwrap(),
			Algorithm::RS256,
			Some("google-test-1"),
			"JWT",
			&claims,
		)
	}

	fn google_binding(&self, token: Option<String>) -> Value {
		let mut b = json!({
			"mode": "verified",
			"scheme": SCHEME_GOOGLE,
			"idp": {"issuer": "https://accounts.google.com"},
			"subject": {"type": "google_email", "email": EMAIL, "sub": "1234567890"},
		});
		if let Some(t) = token {
			b["evidence"] = json!({"embedded": true, "idToken": t});
		}
		b
	}

	// -------------------------------------------------------------- EUDI wallet

	/// What the wallet presents: an SD-JWT VC PID with `disclosed` revealed and `withheld`
	/// kept back, and a key-binding JWT naming `aud` and `nonce`, signed by `device`.
	fn presentation(
		&self,
		disclosed: &[(&str, Value)],
		withheld: &[(&str, Value)],
		aud: &str,
		nonce: &str,
		device: &Ec,
	) -> String {
		self.presentation_from(
			Minted {
				issuer: &self.pid_issuer,
				iss: PID_ISSUER,
				vct: PID_VCT,
			},
			disclosed,
			withheld,
			&[],
			aud,
			nonce,
			device,
		)
	}

	/// As [`Self::presentation`], from any issuer, and with `injected` disclosures the holder
	/// adds that the issuer never signed digests for.
	#[allow(clippy::too_many_arguments)]
	fn presentation_from(
		&self,
		minted: Minted<'_>,
		disclosed: &[(&str, Value)],
		withheld: &[(&str, Value)],
		injected: &[(&str, Value)],
		aud: &str,
		nonce: &str,
		device: &Ec,
	) -> String {
		let disclosure = |i: usize, (name, value): &(&str, Value)| {
			b64(
				json!([format!("salt-{i}-{name}"), name, value])
					.to_string()
					.as_bytes(),
			)
		};
		let shown: Vec<String> = disclosed
			.iter()
			.enumerate()
			.map(|(i, c)| disclosure(i, c))
			.collect();
		let hidden: Vec<String> = withheld
			.iter()
			.enumerate()
			.map(|(i, c)| disclosure(i + 100, c))
			.collect();
		let digest = |d: &String| {
			haps_hash::sha256_prefixed(d.as_bytes())
				.trim_start_matches("sha256:")
				.to_owned()
		};
		let sd: Vec<String> = shown.iter().chain(&hidden).map(digest).collect();
		let issuer_jwt = sign_typed(
			&minted.issuer.key,
			Algorithm::ES256,
			Some(&minted.issuer.kid),
			"dc+sd-jwt",
			&json!({
				"iss": minted.iss,
				"vct": minted.vct,
				"_sd_alg": "sha-256",
				"_sd": sd,
				"cnf": {"jwk": self.wallet.jwk},
				"iat": IAT - 86_400,
				"exp": IAT + 86_400 * 365,
			}),
		);
		let forged: Vec<String> = injected
			.iter()
			.enumerate()
			.map(|(i, c)| disclosure(i + 200, c))
			.collect();
		let mut signed = issuer_jwt;
		for d in shown.iter().chain(&forged) {
			signed.push('~');
			signed.push_str(d);
		}
		signed.push('~');
		let sd_hash = haps_hash::sha256_prefixed(signed.as_bytes())
			.trim_start_matches("sha256:")
			.to_owned();
		let kb = sign_typed(
			&device.key,
			Algorithm::ES256,
			None,
			"kb+jwt",
			&json!({"aud": aud, "nonce": nonce, "iat": IAT - 5, "sd_hash": sd_hash}),
		);
		signed + &kb
	}

	fn default_presentation(&self) -> String {
		self.presentation(
			&[
				("email_address", json!(EMAIL)),
				("given_name", json!("Alice")),
			],
			&[("birthdate", json!("1990-01-01"))],
			ISSUER,
			INTENT_HASH.trim(),
			&self.wallet,
		)
	}

	fn eudi_binding(&self, presentation: Option<&str>) -> Value {
		let mut cp = json!({
			"source": "eudi_wallet",
			"protocol": "openid4vp",
			"issuer": {"id": PID_ISSUER},
		});
		if let Some(p) = presentation {
			cp["presentation"] = json!(p);
			cp["presentation_hash"] = json!(haps_hash::sha256_prefixed(p.as_bytes()));
		} else {
			cp["presentation_hash"] = json!("sha256:AAAAAAAAAAAAAAAAAAAAAA");
		}
		json!({
			"mode": "verified",
			"scheme": SCHEME_EUDI,
			"subject": {
				"type": "credential_holder",
				"binding_key_thumbprint": thumbprint(&self.wallet.jwk).unwrap(),
				"claims": {"email_address": EMAIL},
			},
			"evidence": {
				"type": "digital_credentials_portrait_liveness_evidence",
				"profile": "haps.profile.digital-credentials-portrait-liveness/v0.1",
				"mode": "plain_digital_credentials",
				"binding": {
					"challenge_id": INTENT_HASH.trim(),
					"approval_session_id": "session-0001",
					"audience": AUD,
					"action_hash": INTENT_HASH.trim(),
					"issued_at": "2026-01-09T00:00:00Z",
				},
				"credential_presentation": cp,
			},
		})
	}
}

fn google_policy() -> IdentityPolicy {
	let mut p = IdentityPolicy::new(true, vec![Scheme::Google]);
	p.account_attribute = Some(ACCOUNT.into());
	p.require_embedded_evidence = true;
	p
}

fn eudi_policy() -> IdentityPolicy {
	let mut p = IdentityPolicy::new(true, vec![Scheme::EudiWallet]);
	p.account_attribute = Some(ACCOUNT.into());
	p.require_embedded_evidence = true;
	p.eudi_subject_claim = Some("email_address".into());
	p
}

fn account(value: &str) -> serde_json::Map<String, Value> {
	serde_json::Map::from_iter([(ACCOUNT.to_owned(), json!(value))])
}

async fn check_as(g: &Guard, params: &[u8], who: Option<&str>) -> Decision {
	let meta = who.map(account);
	g.check_with("tools/call", Some(params), meta.as_ref(), NOW)
		.await
}

fn identity_denial(d: Decision) -> IdentityError {
	match denied(d) {
		Denial::Identity(e) => e,
		other => panic!("expected an identity denial, got {other:?}"),
	}
}

// ------------------------------------------------------------------ Google

#[tokio::test]
async fn a_verified_google_identity_matching_the_caller_is_accepted() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let call = iw.call(Some(iw.google_binding(Some(iw.id_token(json!({}))))));
	// Email comparison ignores case, as Google's addresses do.
	let (_, audit) = approved(check_as(&g, &call, Some("ALICE@example.com")).await);
	assert_eq!(
		audit.identity,
		Some(Bound {
			scheme: SCHEME_GOOGLE,
			subject: EMAIL.into(),
			reverified: true,
		})
	);
}

#[tokio::test]
async fn a_google_identity_that_is_not_the_caller_is_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let call = iw.call(Some(iw.google_binding(Some(iw.id_token(json!({}))))));
	assert_eq!(
		identity_denial(check_as(&g, &call, Some("mallory@example.com")).await),
		IdentityError::SubjectMismatch
	);
	// And with no authenticated caller there is nothing to match against.
	assert_eq!(
		identity_denial(check_as(&g, &call, None).await),
		IdentityError::NoAccount
	);
}

#[tokio::test]
async fn a_google_token_minted_for_another_approval_is_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let token = iw.id_token(json!({"nonce": "sha256:some-other-approval"}));
	let call = iw.call(Some(iw.google_binding(Some(token))));
	assert!(matches!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::NotBoundToApproval(_)
	));
}

#[tokio::test]
async fn google_tokens_failing_signature_audience_or_verification_are_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let forged = {
		// Signed by a key Google does not hold, under Google's kid.
		let other = ec("google-test-1");
		sign_typed(
			&other.key,
			Algorithm::ES256,
			Some("google-test-1"),
			"JWT",
			&json!({}),
		)
	};
	for token in [
		forged,
		iw.id_token(json!({"aud": "someone-else.apps.googleusercontent.com"})),
		iw.id_token(json!({"iss": "https://evil.example"})),
		iw.id_token(json!({"email_verified": false})),
		iw.id_token(json!({"email": "bob@example.com"})),
		iw.id_token(json!({"exp": IAT - 3600})),
	] {
		let call = iw.call(Some(iw.google_binding(Some(token))));
		assert!(
			matches!(
				identity_denial(check_as(&g, &call, Some(EMAIL)).await),
				IdentityError::Evidence(_)
			),
			"a bad token was accepted"
		);
	}
}

#[tokio::test]
async fn a_google_identity_outside_the_accepted_domains_is_refused() {
	let iw = IdWorld::new();
	let mut p = google_policy();
	p.google_domains = vec!["iproov.com".into()];
	let g = iw.guard(p);
	for token in [
		iw.id_token(json!({})),
		iw.id_token(json!({"hd": "example.com"})),
	] {
		let call = iw.call(Some(iw.google_binding(Some(token))));
		assert_eq!(
			identity_denial(check_as(&g, &call, Some(EMAIL)).await),
			IdentityError::DomainNotAccepted
		);
	}
}

#[tokio::test]
async fn an_old_google_authentication_is_refused_when_freshness_is_required() {
	let iw = IdWorld::new();
	let mut p = google_policy();
	p.max_auth_age_secs = Some(60);
	let g = iw.guard(p);
	let call = iw.call(Some(
		iw.google_binding(Some(iw.id_token(json!({"auth_time": IAT - 3600})))),
	));
	assert_eq!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::AuthenticationTooOld
	);
}

#[tokio::test]
async fn an_asserted_identity_is_refused_where_evidence_is_required_and_marked_otherwise() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let call = iw.call(Some(iw.google_binding(None)));
	assert_eq!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::EvidenceRequired
	);
	let mut lenient = google_policy();
	lenient.require_embedded_evidence = false;
	let g = iw.guard(lenient);
	let (_, audit) = approved(check_as(&g, &call, Some(EMAIL)).await);
	assert_eq!(audit.identity.map(|b| b.reverified), Some(false));
}

#[tokio::test]
async fn pohp_3_requires_reverifiable_identity_evidence_whatever_the_policy_says() {
	// RP-IDB-06, seen through the challenge the guard issues: the test certification covers
	// only PoHP-2, so a PoHP-3 credential would stop at certification first.
	let iw = IdWorld::new();
	let mut p = policy("HAPS-PoHP-3");
	p.challenge_mode = true;
	p.envelope_rules.clear();
	let mut ip = google_policy();
	ip.require_embedded_evidence = false;
	p.identity = Some(ip);
	let g = iw.guard_with(p);
	let ch = challenge_for(&g, &approved_arguments(), NOW).await;
	assert_eq!(
		ch["requirements"]["identity"]["policy"]["requireEmbeddedEvidence"],
		true
	);
}

#[tokio::test]
async fn a_missing_identity_is_re_elicited_when_required_and_ignored_when_preferred() {
	let iw = IdWorld::new();
	let g = iw.guard(google_policy());
	let (reason, _) = elicited(check_as(&g, &iw.call(None), Some(EMAIL)).await);
	assert_eq!(
		reason,
		"this tool requires an approval bound to your identity"
	);

	let mut preferred = google_policy();
	preferred.required = false;
	let g = iw.guard(preferred);
	let (_, audit) = approved(check_as(&g, &iw.call(None), Some(EMAIL)).await);
	assert_eq!(audit.identity, None);
}

#[tokio::test]
async fn an_identity_scheme_the_tool_does_not_accept_is_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let call = iw.call(Some(iw.google_binding(Some(iw.id_token(json!({}))))));
	assert_eq!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::SchemeNotAccepted(SCHEME_GOOGLE.into())
	);
}

#[tokio::test]
async fn a_challenge_asks_for_the_identity_and_binds_it_to_the_challenge() {
	let iw = IdWorld::new();
	let mut p = challenge_policy();
	p.identity = Some(google_policy());
	let g = iw.guard_with(p);
	let args = approved_arguments();
	let ch = challenge_for(&g, &args, NOW).await;
	assert_eq!(
		ch["requirements"]["identity"],
		json!({"mode": "required", "schemes": [SCHEME_GOOGLE], "policy": {"requireEmbeddedEvidence": true}})
	);
	// In challenge mode the evidence's nonce is the challenge id, not the intent hash.
	let intent = ch["actionIntent"].clone();
	let id = ch["challengeId"].as_str().unwrap();
	let binding = |nonce: &str| iw.google_binding(Some(iw.id_token(json!({"nonce": nonce}))));
	let answered = |nonce: &str, jti: &str| {
		let mut c = with(
			with(iw.w.claims_for(&intent), "challengeId", json!(id)),
			"jti",
			json!(jti),
		);
		c["identityBinding"] = binding(nonce);
		call(
			TOOL,
			args.clone(),
			Some(meta_for(&iw.w.sign(&c), &intent, None)),
		)
	};
	assert!(matches!(
		identity_denial(check_as(&g, &answered(&hash_json(&intent), "j1"), Some(EMAIL)).await),
		IdentityError::NotBoundToApproval(_)
	));
	assert!(is_approved(
		&check_as(&g, &answered(id, "j2"), Some(EMAIL)).await
	));
}

// ------------------------------------------------------------------ EUDI wallet

#[tokio::test]
async fn an_eudi_wallet_presentation_identifying_the_caller_is_accepted() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let call = iw.call(Some(iw.eudi_binding(Some(&iw.default_presentation()))));
	let (_, audit) = approved(check_as(&g, &call, Some(EMAIL)).await);
	assert_eq!(
		audit.identity,
		Some(Bound {
			scheme: SCHEME_EUDI,
			subject: EMAIL.into(),
			reverified: true,
		})
	);
}

#[tokio::test]
async fn without_a_subject_claim_the_wallet_key_is_the_subject() {
	let iw = IdWorld::new();
	let mut p = eudi_policy();
	p.eudi_subject_claim = None;
	let g = iw.guard(p);
	let call = iw.call(Some(iw.eudi_binding(Some(&iw.default_presentation()))));
	let key = thumbprint(&iw.wallet.jwk).unwrap();
	assert!(is_approved(&check_as(&g, &call, Some(&key)).await));
	assert_eq!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::SubjectMismatch
	);
}

#[tokio::test]
async fn a_presentation_made_for_another_approval_or_verifier_is_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let disclosed = [("email_address", json!(EMAIL))];
	for p in [
		iw.presentation(
			&disclosed,
			&[],
			ISSUER,
			"sha256:another-approval",
			&iw.wallet,
		),
		iw.presentation(
			&disclosed,
			&[],
			"https://other-verifier.example",
			INTENT_HASH.trim(),
			&iw.wallet,
		),
	] {
		let call = iw.call(Some(iw.eudi_binding(Some(&p))));
		assert!(matches!(
			identity_denial(check_as(&g, &call, Some(EMAIL)).await),
			IdentityError::NotBoundToApproval(_)
		));
	}
}

#[tokio::test]
async fn a_presentation_not_signed_by_the_wallet_key_is_refused() {
	// A key-binding JWT signed by another device: someone holding the credential but not the
	// wallet.
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let thief = ec("thief");
	let p = iw.presentation(
		&[("email_address", json!(EMAIL))],
		&[],
		ISSUER,
		INTENT_HASH.trim(),
		&thief,
	);
	let call = iw.call(Some(iw.eudi_binding(Some(&p))));
	assert!(matches!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::Evidence(_)
	));
}

#[tokio::test]
async fn a_credential_from_an_untrusted_issuer_is_refused() {
	let iw = IdWorld::new();
	let mut config = iw.w.config({
		let mut p = policy("HAPS-PoHP-2");
		p.identity = Some(eudi_policy());
		p
	});
	let mut trust = iw.trust();
	trust.eudi.as_mut().unwrap().issuers.clear();
	config.identity = trust;
	let g = Guard::new(config, StateStore::memory());
	let call = iw.call(Some(iw.eudi_binding(Some(&iw.default_presentation()))));
	assert!(matches!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::Evidence(_)
	));
}

#[tokio::test]
async fn tampered_disclosures_are_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let original = iw.default_presentation();
	let parts: Vec<&str> = original.split('~').collect();
	let kb = *parts.last().unwrap();
	// A forged disclosure, not among the credential's digests.
	let forged = b64(
		json!(["salt", "email_address", "mallory@example.com"])
			.to_string()
			.as_bytes(),
	);
	let with_forged = format!(
		"{}~{forged}~{kb}",
		parts[..parts.len() - 1].join("~").trim_end_matches('~')
	);
	// A genuine disclosure dropped after the wallet signed: the key binding no longer covers
	// what is presented.
	let dropped = format!("{}~{}~{kb}", parts[0], parts[1]);
	for p in [with_forged, dropped] {
		let call = iw.call(Some(iw.eudi_binding(Some(&p))));
		assert!(matches!(
			identity_denial(check_as(&g, &call, Some(EMAIL)).await),
			IdentityError::Evidence(_)
		));
	}
}

#[tokio::test]
async fn a_holder_cannot_inject_a_claim_the_issuer_never_signed() {
	// The wallet signs its key binding over a disclosure of its own making. Its signature is
	// genuine and covers the disclosure; the issuer's digests do not. The subject here is the
	// wallet key, so nothing depends on the injected claim: RFC 9901 requires refusing a
	// presentation with an unreferenced disclosure, not merely ignoring it.
	let iw = IdWorld::new();
	let mut p = eudi_policy();
	p.eudi_subject_claim = None;
	let g = iw.guard(p);
	let p = iw.presentation_from(
		Minted {
			issuer: &iw.pid_issuer,
			iss: PID_ISSUER,
			vct: PID_VCT,
		},
		&[("given_name", json!("Mallory"))],
		&[],
		&[("email_address", json!(EMAIL))],
		ISSUER,
		INTENT_HASH.trim(),
		&iw.wallet,
	);
	let call = iw.call(Some(iw.eudi_binding(Some(&p))));
	let key = thumbprint(&iw.wallet.jwk).unwrap();
	assert!(matches!(
		identity_denial(check_as(&g, &call, Some(&key)).await),
		IdentityError::Evidence(_)
	));
}

#[tokio::test]
async fn an_issuer_is_trusted_only_for_its_own_name_and_credential_types() {
	// A second trusted issuer, trusted only for loyalty cards. It can neither mint a PID under
	// its own name, nor sign one claiming to be the PID issuer.
	let iw = IdWorld::new();
	let loyalty = ec("loyalty-1");
	let mut config = iw.w.config({
		let mut p = policy("HAPS-PoHP-2");
		p.identity = Some(eudi_policy());
		p
	});
	let mut trust = iw.trust();
	let mut loyalty_jwk = loyalty.jwk.clone();
	loyalty_jwk["kid"] = json!(loyalty.kid);
	trust.eudi.as_mut().unwrap().issuers.insert(
		"https://loyalty.example".into(),
		CredentialIssuer {
			keys: serde_json::from_value(json!({"keys": [loyalty_jwk]})).unwrap(),
			vcts: vec!["urn:example:loyalty:1".into()],
		},
	);
	config.identity = trust;
	let g = Guard::new(config, StateStore::memory());
	for (iss, vct) in [("https://loyalty.example", PID_VCT), (PID_ISSUER, PID_VCT)] {
		let p = iw.presentation_from(
			Minted {
				issuer: &loyalty,
				iss,
				vct,
			},
			&[("email_address", json!(EMAIL))],
			&[],
			&[],
			ISSUER,
			INTENT_HASH.trim(),
			&iw.wallet,
		);
		let mut b = iw.eudi_binding(Some(&p));
		b["evidence"]["credential_presentation"]["issuer"]["id"] = json!(iss);
		assert!(
			matches!(
				identity_denial(check_as(&g, &iw.call(Some(b)), Some(EMAIL)).await),
				IdentityError::Evidence(_)
			),
			"{iss} minted a PID"
		);
	}
}

#[tokio::test]
async fn a_claim_the_wallet_withheld_cannot_identify_the_caller() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let p = iw.presentation(
		&[("given_name", json!("Alice"))],
		&[("email_address", json!(EMAIL))],
		ISSUER,
		INTENT_HASH.trim(),
		&iw.wallet,
	);
	let call = iw.call(Some(iw.eudi_binding(Some(&p))));
	assert!(matches!(
		identity_denial(check_as(&g, &call, Some(EMAIL)).await),
		IdentityError::Evidence(_)
	));
}

#[tokio::test]
async fn evidence_whose_recorded_binding_disagrees_is_refused() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let p = iw.default_presentation();
	let mut wrong_hash = iw.eudi_binding(Some(&p));
	wrong_hash["evidence"]["credential_presentation"]["presentation_hash"] =
		json!(haps_hash::sha256_prefixed(b"something else"));
	let mut wrong_audience = iw.eudi_binding(Some(&p));
	wrong_audience["evidence"]["binding"]["audience"] = json!("did:web:another-bank.example");
	let mut wrong_action = iw.eudi_binding(Some(&p));
	wrong_action["evidence"]["binding"]["action_hash"] = json!("sha256:another-action-hash");
	assert!(matches!(
		identity_denial(check_as(&g, &iw.call(Some(wrong_hash)), Some(EMAIL)).await),
		IdentityError::Evidence(_)
	));
	for b in [wrong_audience, wrong_action] {
		assert!(matches!(
			identity_denial(check_as(&g, &iw.call(Some(b)), Some(EMAIL)).await),
			IdentityError::NotBoundToApproval(_)
		));
	}
}

#[tokio::test]
async fn the_wallet_key_thumbprint_the_provider_records_must_be_the_wallets() {
	let iw = IdWorld::new();
	let g = iw.guard(eudi_policy());
	let mut b = iw.eudi_binding(Some(&iw.default_presentation()));
	b["subject"]["binding_key_thumbprint"] = json!(thumbprint(&ec("other").jwk).unwrap());
	assert!(matches!(
		identity_denial(check_as(&g, &iw.call(Some(b)), Some(EMAIL)).await),
		IdentityError::Evidence(_)
	));
}

#[test]
fn rfc_7638_thumbprint_matches_the_rfc_example() {
	// RFC 7638 §3.1.
	let jwk = json!({
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e": "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	});
	assert_eq!(
		thumbprint(&jwk).unwrap(),
		"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	);
}

//! The EUDI wallet presents, the guard verifies. The presentation is produced by EUWallet's own
//! OpenID4VP state machine with a device key, exactly as the wallet would answer a Presence
//! Provider's request; the guard's verifier then checks it as it would inside an approval.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use haps_guard::identity::{
	CredentialIssuer, IdentityError, thumbprint, verify_sd_jwt_presentation,
};
use oid4vp::{Env, Input, Output, ResolvedTrust, SelectedCredential, State, step};
use serde_json::{Value, json};

const PID_ISSUER: &str = "https://pid.example";
const PID_VCT: &str = "urn:eudi:pid:1";
/// The Presence Provider's OpenID4VP client id: the audience of the wallet's key binding.
const PP_CLIENT_ID: &str = "pp.example";
/// What the Presence Provider puts in the request nonce: the approval's challenge id.
const CHALLENGE_ID: &str = "6f1b9c36-4c3b-4e0b-8a78-83fd8c12c710";

fn b64(bytes: &[u8]) -> String {
	URL_SAFE_NO_PAD.encode(bytes)
}

/// A P-256 public key, raw `04||X||Y`, as a JWK.
fn jwk(raw: &[u8]) -> Value {
	json!({"kty": "EC", "crv": "P-256", "x": b64(&raw[1..33]), "y": b64(&raw[33..65])})
}

/// The PID issuer mints an SD-JWT VC bound to the wallet's device key.
fn issue_pid(issuer: &SoftwareSigner, device: &SoftwareSigner) -> (String, Vec<String>) {
	let claims = [
		("family_name", json!("Andersson")),
		("given_name", json!("Alice")),
		("email_address", json!("alice@example.com")),
	];
	let mut disclosures = Vec::new();
	let mut sd = Vec::new();
	for (i, (name, value)) in claims.iter().enumerate() {
		let raw = b64(
			json!([format!("salt{i}"), name, value])
				.to_string()
				.as_bytes(),
		);
		sd.push(json!(b64(&AwsLc.sha256(raw.as_bytes()))));
		disclosures.push(raw);
	}
	let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"pid-1"}"#);
	let payload = b64(
		json!({
			"iss": PID_ISSUER,
			"vct": PID_VCT,
			"_sd_alg": "sha-256",
			"_sd": sd,
			"cnf": {"jwk": jwk(device.public_key_raw())},
		})
		.to_string()
		.as_bytes(),
	);
	let signing_input = format!("{header}.{payload}");
	let sig = issuer
		.sign(
			&KeyRef("issuer".into()),
			Alg::Es256,
			signing_input.as_bytes(),
		)
		.unwrap();
	(format!("{signing_input}.{}", b64(&sig)), disclosures)
}

/// The Presence Provider's signed OpenID4VP request.
fn request(pp: &SoftwareSigner, nonce: &str) -> Vec<u8> {
	let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
	let payload = b64(
		json!({
			"client_id": PP_CLIENT_ID,
			"nonce": nonce,
			"aud": "wallet.example",
			"response_uri": "https://pp.example/response",
			"response_mode": "direct_post",
			"purpose": "Confirm who is approving this payment",
		})
		.to_string()
		.as_bytes(),
	);
	let signing_input = format!("{header}.{payload}");
	let sig = pp
		.sign(&KeyRef("pp".into()), Alg::Es256, signing_input.as_bytes())
		.unwrap();
	format!("{signing_input}.{}", b64(&sig)).into_bytes()
}

/// Drive the wallet: request in, consent, device signature, `vp_token` out.
fn wallet_presents(
	issuer_jwt: &str,
	disclosures: &[String],
	device: &SoftwareSigner,
	pp: &SoftwareSigner,
	nonce: &str,
) -> String {
	let seen: Vec<String> = vec![];
	let creds = [SelectedCredential::SdJwt {
		issuer_jwt: issuer_jwt.to_owned(),
		disclosures: disclosures.to_vec(),
		dcql_id: None,
	}];
	let env = Env {
		wallet_client_id: "wallet.example",
		seen_nonces: &seen,
		verifier: &AwsLc,
		digest: &AwsLc,
		now_epoch: 1_790_000_000,
		selected_credentials: &creds,
		device_key_ref: "device-key",
	};
	let (s, _) = step(
		&State::Idle,
		&Input::AuthorizationRequest(request(pp, nonce)),
		&env,
	);
	let trust = ResolvedTrust {
		registered: true,
		rp_public_key: pp.public_key_raw().to_vec(),
		registered_redirect_uris: vec!["https://pp.example/response".into()],
		leaf_dns_sans: vec![],
	};
	let (s, _) = step(&s, &Input::RpTrustResolved(trust), &env);
	let (s, out) = step(&s, &Input::ConsentGranted, &env);
	let signing_input = match out.as_slice() {
		[Output::SignKeyBinding { signing_input, .. }] => signing_input.clone(),
		other => panic!("expected SignKeyBinding, got {other:?}"),
	};
	let sig = device
		.sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
		.unwrap();
	let (_, out) = step(&s, &Input::DeviceSignatureProduced(sig), &env);
	match out.as_slice() {
		[Output::SendVpToken(body)] => String::from_utf8(body.clone())
			.unwrap()
			.strip_prefix("vp_token=")
			.and_then(|s| s.split('&').next())
			.expect("vp_token form field")
			.to_owned(),
		other => panic!("expected SendVpToken, got {other:?}"),
	}
}

fn trusted(issuer: &SoftwareSigner) -> HashMap<String, CredentialIssuer> {
	let mut key = jwk(issuer.public_key_raw());
	key["kid"] = json!("pid-1");
	HashMap::from([(
		PID_ISSUER.to_owned(),
		CredentialIssuer {
			keys: serde_json::from_value(json!({"keys": [key]})).unwrap(),
			vcts: vec![PID_VCT.into()],
		},
	)])
}

#[test]
fn the_guard_accepts_what_the_wallet_presents_for_this_approval() {
	let (issuer, device, pp) = (
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
	);
	let (issuer_jwt, disclosures) = issue_pid(&issuer, &device);
	let vp_token = wallet_presents(&issuer_jwt, &disclosures, &device, &pp, CHALLENGE_ID);

	let verified =
		verify_sd_jwt_presentation(&vp_token, &trusted(&issuer), PP_CLIENT_ID, CHALLENGE_ID)
			.expect("the guard must accept the wallet's presentation");
	assert_eq!(verified.issuer, PID_ISSUER);
	assert_eq!(verified.vct, PID_VCT);
	assert_eq!(verified.claims["email_address"], "alice@example.com");
	assert_eq!(verified.claims["family_name"], "Andersson");
	assert_eq!(
		verified.thumbprint,
		thumbprint(&jwk(device.public_key_raw())).unwrap()
	);

	// EUWallet's own verifier agrees on the same bytes.
	let sd = sdjwt::SdJwtVc::parse(&vp_token).unwrap();
	let claims = sd
		.verify_presentation(
			&AwsLc,
			&AwsLc,
			issuer.public_key_raw(),
			Alg::Es256,
			&sdjwt::KeyBindingCheck {
				device_public_key: device.public_key_raw(),
				expected_aud: PP_CLIENT_ID,
				expected_nonce: CHALLENGE_ID,
				device_alg: Alg::Es256,
			},
		)
		.expect("EUWallet's verifier accepts it too");
	assert_eq!(
		Value::Object(claims.clone())["email_address"],
		verified.claims["email_address"]
	);
}

#[test]
fn a_wallet_presentation_for_another_approval_is_refused() {
	let (issuer, device, pp) = (
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
	);
	let (issuer_jwt, disclosures) = issue_pid(&issuer, &device);
	let vp_token = wallet_presents(
		&issuer_jwt,
		&disclosures,
		&device,
		&pp,
		"another-challenge-id",
	);
	assert!(matches!(
		verify_sd_jwt_presentation(&vp_token, &trusted(&issuer), PP_CLIENT_ID, CHALLENGE_ID),
		Err(IdentityError::NotBoundToApproval(_))
	));
}

#[test]
fn a_wallet_credential_from_an_untrusted_issuer_is_refused() {
	let (issuer, rogue, device, pp) = (
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
		SoftwareSigner::generate_p256().unwrap(),
	);
	let (issuer_jwt, disclosures) = issue_pid(&rogue, &device);
	let vp_token = wallet_presents(&issuer_jwt, &disclosures, &device, &pp, CHALLENGE_ID);
	assert!(matches!(
		verify_sd_jwt_presentation(&vp_token, &trusted(&issuer), PP_CLIENT_ID, CHALLENGE_ID),
		Err(IdentityError::Evidence(_))
	));
}

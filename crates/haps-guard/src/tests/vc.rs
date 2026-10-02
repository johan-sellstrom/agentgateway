//! The `vc+json` format: the W3C Data Integrity vectors, then HAPS credentials issued as VCs.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair};

use super::*;
use crate::vc::{self, PublicKey, VcError, multibase_decode, multibase_encode};

const EDDSA_SIGNED: &str = include_str!("../../testdata/vc-di/eddsa-jcs-2022.signed.json");
const EDDSA_HASH: &str = include_str!("../../testdata/vc-di/eddsa-jcs-2022.combined-hash.txt");
const EDDSA_KEYS: &str = include_str!("../../testdata/vc-di/eddsa-jcs-2022.key-pair.json");
const ECDSA_SIGNED: &str = include_str!("../../testdata/vc-di/ecdsa-jcs-2019-p256.signed.json");
const ECDSA_HASH: &str = include_str!("../../testdata/vc-di/ecdsa-jcs-2019-p256.combined-hash.txt");
const ECDSA_KEYS: &str = include_str!("../../testdata/vc-di/ecdsa-jcs-2019-p256.key-pair.json");

fn object(s: &str) -> serde_json::Map<String, Value> {
	serde_json::from_str(s).unwrap()
}

fn vector_key(pair: &str) -> PublicKey {
	let v: Value = serde_json::from_str(pair).unwrap();
	PublicKey::from_multibase(v["publicKeyMultibase"].as_str().unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ the W3C vectors

#[test]
fn the_eddsa_jcs_2022_vector_verifies_and_its_hash_data_is_reproduced() {
	let signed = object(EDDSA_SIGNED);
	let (data, _) = vc::hash_data(&signed).unwrap();
	assert_eq!(hex(&data), EDDSA_HASH.trim());
	vc::verify_proof(&signed, &vector_key(EDDSA_KEYS)).unwrap();
}

#[test]
fn the_ecdsa_jcs_2019_p256_vector_verifies_and_its_hash_data_is_reproduced() {
	let signed = object(ECDSA_SIGNED);
	let (data, _) = vc::hash_data(&signed).unwrap();
	assert_eq!(hex(&data), ECDSA_HASH.trim());
	vc::verify_proof(&signed, &vector_key(ECDSA_KEYS)).unwrap();
}

#[test]
fn a_vector_changed_after_signing_fails() {
	for (signed, keys) in [(EDDSA_SIGNED, EDDSA_KEYS), (ECDSA_SIGNED, ECDSA_KEYS)] {
		let mut doc = object(signed);
		doc["credentialSubject"]["alumniOf"] = json!("Another School");
		assert_eq!(
			vc::verify_proof(&doc, &vector_key(keys)),
			Err(VcError::BadSignature)
		);
		let mut proof_changed = object(signed);
		proof_changed["proof"]["created"] = json!("2024-01-01T00:00:00Z");
		assert_eq!(
			vc::verify_proof(&proof_changed, &vector_key(keys)),
			Err(VcError::BadSignature)
		);
	}
}

#[test]
fn a_key_of_the_other_suite_is_refused() {
	assert!(matches!(
		vc::verify_proof(&object(EDDSA_SIGNED), &vector_key(ECDSA_KEYS)),
		Err(VcError::UnsupportedCryptosuite(_))
	));
}

#[test]
fn multibase_base58btc_round_trips() {
	for bytes in [
		vec![],
		vec![0],
		vec![0, 0, 1],
		vec![255; 40],
		(0..=255).collect(),
	] {
		assert_eq!(multibase_decode(&multibase_encode(&bytes)).unwrap(), bytes);
	}
	let key: Value = serde_json::from_str(EDDSA_KEYS).unwrap();
	let mb = key["publicKeyMultibase"].as_str().unwrap();
	assert_eq!(multibase_encode(&multibase_decode(mb).unwrap()), mb);
	assert!(multibase_decode("m0AA").is_err(), "only base58btc");
	assert!(multibase_decode("z0OIl").is_err(), "not in the alphabet");
}

// ------------------------------------------------------------------ HAPS credentials as VCs

enum VcSigner {
	Ed(Ed25519KeyPair),
	P256(EcdsaKeyPair),
}

impl VcSigner {
	fn ed() -> Self {
		let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
		VcSigner::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
	}

	fn p256() -> Self {
		let pkcs8 =
			EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).unwrap();
		VcSigner::P256(
			EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap(),
		)
	}

	fn suite(&self) -> &'static str {
		match self {
			VcSigner::Ed(_) => "eddsa-jcs-2022",
			VcSigner::P256(_) => "ecdsa-jcs-2019",
		}
	}

	fn jwk(&self, kid: &str) -> Value {
		match self {
			VcSigner::Ed(k) => {
				json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": haps_hash::base64url_unpadded(k.public_key().as_ref())})
			},
			VcSigner::P256(k) => {
				let p = k.public_key().as_ref();
				json!({"kty": "EC", "crv": "P-256", "kid": kid,
					"x": haps_hash::base64url_unpadded(&p[1..33]), "y": haps_hash::base64url_unpadded(&p[33..65])})
			},
		}
	}

	fn sign(&self, data: &[u8]) -> Vec<u8> {
		match self {
			VcSigner::Ed(k) => k.sign(data).as_ref().to_vec(),
			VcSigner::P256(k) => k
				.sign(&SystemRandom::new(), data)
				.unwrap()
				.as_ref()
				.to_vec(),
		}
	}
}

/// The HAPS claims of `World::claims`, issued by `ISSUER` as a VC signed with `signer`.
fn issue(claims: &Value, signer: &VcSigner, method: &str) -> Value {
	let mut subject = claims.clone();
	subject.as_object_mut().unwrap().remove("issuer");
	let mut doc = json!({
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential", "HapsConsentCredential"],
		"issuer": ISSUER,
		"credentialSubject": subject,
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": signer.suite(),
			"created": "2026-01-09T00:00:30Z",
			"verificationMethod": method,
			"proofPurpose": "assertionMethod",
			"proofValue": "z",
		},
	});
	let (data, _) = vc::hash_data(doc.as_object().unwrap()).unwrap();
	doc["proof"]["proofValue"] = json!(multibase_encode(&signer.sign(&data)));
	doc
}

/// Sign `doc` again, so that only what a test changed is wrong with it.
fn resign(mut doc: Value, signer: &VcSigner) -> Value {
	let (data, _) = vc::hash_data(doc.as_object().unwrap()).unwrap();
	doc["proof"]["proofValue"] = json!(multibase_encode(&signer.sign(&data)));
	doc
}

fn vc_guard(w: &World, signer: &VcSigner) -> Guard {
	let mut config = w.config(policy("HAPS-PoHP-2"));
	config.issuers = HashMap::from([(
		ISSUER.to_owned(),
		serde_json::from_value(json!({"keys": [signer.jwk("vc-key-1")]})).unwrap(),
	)]);
	Guard::new(config, StateStore::memory())
}

fn vc_call(credential: &Value) -> Vec<u8> {
	let mut m = meta("placeholder");
	m[META_CREDENTIAL] = credential.clone();
	call(TOOL, approved_arguments(), Some(m))
}

const METHOD: &str = "did:web:pp.example#vc-key-1";

#[tokio::test]
async fn a_haps_credential_as_an_eddsa_or_ecdsa_vc_is_accepted() {
	for signer in [VcSigner::ed(), VcSigner::p256()] {
		let w = World::new();
		let g = vc_guard(&w, &signer);
		let credential = issue(&w.claims(), &signer, METHOD);
		let (params, audit) = approved(check(&g, &vc_call(&credential), NOW).await);
		assert_eq!(audit.format, "vc+json");
		assert_eq!(audit.issuer, ISSUER);
		// The credential is stripped from what goes upstream, whatever its format.
		let forwarded: Value = serde_json::from_slice(&params).unwrap();
		assert_eq!(forwarded["_meta"], json!({}));
		// And it is one-time like any other.
		assert_eq!(
			denied(check(&g, &vc_call(&credential), NOW).await),
			Denial::Replayed
		);
	}
}

#[tokio::test]
async fn a_vc_whose_claims_changed_after_signing_is_refused() {
	let w = World::new();
	let signer = VcSigner::ed();
	let g = vc_guard(&w, &signer);
	let mut credential = issue(&w.claims(), &signer, METHOD);
	credential["credentialSubject"]["assurance"]["level"] = json!("HAPS-PoHP-4");
	assert_eq!(
		denied(check(&g, &vc_call(&credential), NOW).await),
		Denial::BadSignature
	);
}

#[tokio::test]
async fn a_vc_key_is_only_ever_its_issuers_trusted_key() {
	let w = World::new();
	let signer = VcSigner::ed();
	let g = vc_guard(&w, &signer);
	// A method under another controller, even with a kid the issuer happens to use.
	let other = issue(&w.claims(), &signer, "did:web:rogue.example#vc-key-1");
	assert_eq!(
		denied(check(&g, &vc_call(&other), NOW).await),
		Denial::UntrustedIssuer("did:web:rogue.example".into())
	);
	// A did:key method carrying its own key: never dereferenced, so never trusted.
	let did_key = issue(&w.claims(), &signer, "did:key:z6Mkexample#z6Mkexample");
	assert!(matches!(
		denied(check(&g, &vc_call(&did_key), NOW).await),
		Denial::UntrustedIssuer(_)
	));
	// A kid the issuer does not have.
	let unknown = issue(&w.claims(), &signer, "did:web:pp.example#vc-key-9");
	assert_eq!(
		denied(check(&g, &vc_call(&unknown), NOW).await),
		Denial::UnknownKey
	);
	// Signed by another key under the issuer's kid.
	let impostor = issue(&w.claims(), &VcSigner::ed(), METHOD);
	assert_eq!(
		denied(check(&g, &vc_call(&impostor), NOW).await),
		Denial::BadSignature
	);
}

#[tokio::test]
async fn a_vc_from_an_untrusted_issuer_or_naming_a_different_one_is_refused() {
	let w = World::new();
	let signer = VcSigner::ed();
	let g = vc_guard(&w, &signer);
	let mut rogue = issue(&w.claims(), &signer, METHOD);
	rogue["issuer"] = json!("did:web:rogue.example");
	assert_eq!(
		denied(check(&g, &vc_call(&rogue), NOW).await),
		Denial::UntrustedIssuer("did:web:rogue.example".into())
	);
	// Properly signed, but the HAPS claims name an issuer other than the VC's.
	let mut credential = issue(&w.claims(), &signer, METHOD);
	credential["credentialSubject"]["issuer"] = json!("did:web:someone-else.example");
	let credential = resign(credential, &signer);
	assert!(matches!(
		denied(check(&g, &vc_call(&credential), NOW).await),
		Denial::MalformedCredential(_)
	));
}

#[tokio::test]
async fn malformed_vcs_are_refused() {
	let w = World::new();
	let signer = VcSigner::ed();
	let g = vc_guard(&w, &signer);
	let good = issue(&w.claims(), &signer, METHOD);
	let mut proof_set = good.clone();
	proof_set["proof"] = json!([good["proof"].clone()]);
	let mut not_a_vc = good.clone();
	not_a_vc["type"] = json!(["HapsConsentCredential"]);
	let mut future = good.clone();
	future["proof"]["created"] = json!("2027-01-01T00:00:00Z");
	let mut expired = good.clone();
	expired["proof"]["expires"] = json!("2026-01-08T00:00:00Z");
	let mut wrong_purpose = good.clone();
	wrong_purpose["proof"]["proofPurpose"] = json!("authentication");
	let mut wrong_proof_type = good.clone();
	wrong_proof_type["proof"]["type"] = json!("Ed25519Signature2020");
	let resigned = [future, expired, wrong_purpose, wrong_proof_type].map(|d| resign(d, &signer));
	for bad in [proof_set, not_a_vc].into_iter().chain(resigned) {
		assert!(matches!(
			denied(check(&g, &vc_call(&bad), NOW).await),
			Denial::MalformedCredential(_)
		));
	}
	// A fractional number anywhere in the credential is refused before anything else.
	let mut fractional = good.clone();
	fractional["credentialSubject"]["score"] = json!(0.5);
	assert!(matches!(
		denied(check(&g, &vc_call(&fractional), NOW).await),
		Denial::MalformedCredential(_)
	));
}

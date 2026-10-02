//! The `vc+json` credential format (`haps-v0.4.0.md` §11): a HAPS Consent Credential as a W3C
//! Verifiable Credential secured with a Data Integrity proof.
//!
//! HAPS names the format but no proof suite. The guard accepts the two JCS-based suites, which
//! canonicalize with RFC 8785 exactly as HAPS hashes do, so no JSON-LD processing is involved:
//!
//! - `eddsa-jcs-2022` (W3C VC Data Integrity EdDSA Cryptosuites v1.0), Ed25519;
//! - `ecdsa-jcs-2019` (W3C VC Data Integrity ECDSA Cryptosuites v1.0), P-256.
//!
//! Mapping, the guard's choice: the HAPS claims are the VC's `credentialSubject`; the HAPS
//! `issuer` is the VC `issuer`; and the proof's `verificationMethod` must be `<issuer>#<kid>`,
//! naming a key in that issuer's trusted JWKS. A verification method is never dereferenced: a
//! credential that names where its key lives must not be able to supply the key.

use std::collections::HashMap;
use std::fmt;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::DateTime;
use haps_canon::Value as Canon;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use serde_json::{Map, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum VcError {
	Malformed(String),
	UnsupportedCryptosuite(String),
	UnknownKey,
	BadSignature,
	UntrustedIssuer(String),
	/// The proof's `created` is in the future, or it has `expires` in the past.
	ProofNotCurrent,
}

impl fmt::Display for VcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			VcError::Malformed(e) => write!(f, "credential is malformed: {e}"),
			VcError::UnsupportedCryptosuite(c) => write!(f, "cryptosuite {c} is not accepted"),
			VcError::UnknownKey => write!(f, "credential is signed by an unknown key"),
			VcError::BadSignature => write!(f, "credential proof is invalid"),
			VcError::UntrustedIssuer(i) => write!(f, "credential issuer {i} is not trusted"),
			VcError::ProofNotCurrent => write!(f, "credential proof is not currently valid"),
		}
	}
}

fn malformed(e: impl Into<String>) -> VcError {
	VcError::Malformed(e.into())
}

/// A public key a Data Integrity proof can be checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
	/// 32 bytes.
	Ed25519(Vec<u8>),
	/// SEC1, compressed or uncompressed.
	P256(Vec<u8>),
}

impl PublicKey {
	fn cryptosuite(&self) -> &'static str {
		match self {
			PublicKey::Ed25519(_) => "eddsa-jcs-2022",
			PublicKey::P256(_) => "ecdsa-jcs-2019",
		}
	}

	/// A multibase `publicKeyMultibase` (multicodec ed25519-pub or p256-pub), as in did:key.
	pub fn from_multibase(s: &str) -> Result<Self, VcError> {
		let bytes = multibase_decode(s)?;
		match bytes.as_slice() {
			[0xed, 0x01, rest @ ..] if rest.len() == 32 => Ok(PublicKey::Ed25519(rest.to_vec())),
			[0x80, 0x24, rest @ ..] if rest.len() == 33 => Ok(PublicKey::P256(rest.to_vec())),
			_ => Err(malformed("unsupported multicodec key")),
		}
	}

	fn from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Option<Self> {
		match &jwk.algorithm {
			AlgorithmParameters::OctetKeyPair(p) if p.curve == EllipticCurve::Ed25519 => {
				URL_SAFE_NO_PAD.decode(&p.x).ok().map(PublicKey::Ed25519)
			},
			AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
				let (x, y) = (
					URL_SAFE_NO_PAD.decode(&p.x).ok()?,
					URL_SAFE_NO_PAD.decode(&p.y).ok()?,
				);
				(x.len() == 32 && y.len() == 32).then(|| {
					let mut point = vec![0x04];
					point.extend(x);
					point.extend(y);
					PublicKey::P256(point)
				})
			},
			_ => None,
		}
	}
}

/// The bytes a JCS Data Integrity proof signs: `SHA-256(JCS(proof options)) ||
/// SHA-256(JCS(document))`, with the document's `@context` replaced by the proof's when the
/// proof carries one (and the proof's being a prefix of the document's, as both suites require).
pub fn hash_data(secured: &Map<String, Value>) -> Result<(Vec<u8>, Map<String, Value>), VcError> {
	let mut document = secured.clone();
	let mut proof = match document.remove("proof") {
		Some(Value::Object(p)) => p,
		Some(_) => {
			return Err(malformed(
				"proof is not a single object; proof sets are not accepted",
			));
		},
		None => return Err(malformed("no proof")),
	};
	if proof.remove("proofValue").is_none() {
		return Err(malformed("proof has no proofValue"));
	}
	if let Some(ctx) = proof.get("@context") {
		let theirs = ctx
			.as_array()
			.ok_or_else(|| malformed("proof @context is not an array"))?;
		let ours = document
			.get("@context")
			.and_then(Value::as_array)
			.ok_or_else(|| malformed("document has no @context array"))?;
		if ours.len() < theirs.len() || ours[..theirs.len()] != theirs[..] {
			return Err(malformed(
				"document @context does not start with the proof's",
			));
		}
		document.insert("@context".into(), ctx.clone());
	}
	let sha = |v: &Map<String, Value>| -> Result<Vec<u8>, VcError> {
		let canon = to_canon(&Value::Object(v.clone()))?;
		let hash = haps_hash::sha256_prefixed(&haps_canon::canonicalize(&canon));
		URL_SAFE_NO_PAD
			.decode(hash.trim_start_matches("sha256:"))
			.map_err(|e| malformed(e.to_string()))
	};
	let mut data = sha(&proof)?;
	data.extend(sha(&document)?);
	Ok((data, proof))
}

/// Verify a JCS Data Integrity proof on `secured` under `key`. Checks the proof is a
/// `DataIntegrityProof` of the cryptosuite matching the key, for `assertionMethod`.
pub fn verify_proof(secured: &Map<String, Value>, key: &PublicKey) -> Result<(), VcError> {
	let proof = secured
		.get("proof")
		.and_then(Value::as_object)
		.ok_or_else(|| malformed("no proof"))?;
	if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
		return Err(malformed("proof type is not DataIntegrityProof"));
	}
	let suite = proof
		.get("cryptosuite")
		.and_then(Value::as_str)
		.ok_or_else(|| malformed("proof has no cryptosuite"))?;
	if suite != key.cryptosuite() {
		return Err(VcError::UnsupportedCryptosuite(suite.to_owned()));
	}
	if proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
		return Err(malformed("proofPurpose is not assertionMethod"));
	}
	let signature = multibase_decode(
		proof
			.get("proofValue")
			.and_then(Value::as_str)
			.ok_or_else(|| malformed("proof has no proofValue"))?,
	)?;
	let (data, _) = hash_data(secured)?;
	let ok = match key {
		PublicKey::Ed25519(k) => UnparsedPublicKey::new(&ED25519, k).verify(&data, &signature),
		// The suite signs the hash data with ECDSA P-256 over SHA-256, P1363 (r || s) encoded.
		PublicKey::P256(k) => {
			UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, k).verify(&data, &signature)
		},
	};
	ok.map_err(|_| VcError::BadSignature)
}

/// A verified `vc+json` HAPS credential: the claims, ready for the checks every credential gets.
pub struct VerifiedVc {
	pub claims: Value,
	pub issuer: String,
}

/// Verify `raw`, a HAPS Consent Credential as a VC, against `trust` (issuer → keys). `now`
/// bounds the proof's own `created`/`expires`; the HAPS time claims are checked by the caller.
pub fn verify(
	raw: &str,
	trust: &HashMap<String, JwkSet>,
	now: u64,
	skew: u64,
) -> Result<VerifiedVc, VcError> {
	// Strict first: no fractional numbers, no duplicate members, as for every HAPS input.
	haps_canon::parse(raw).map_err(|e| malformed(format!("{e:?}")))?;
	let vc: Map<String, Value> = serde_json::from_str(raw).map_err(|e| malformed(e.to_string()))?;
	let types = vc.get("type").and_then(Value::as_array);
	if !types.is_some_and(|t| t.iter().any(|t| t == "VerifiableCredential")) {
		return Err(malformed("type does not include VerifiableCredential"));
	}
	let issuer = match vc.get("issuer") {
		Some(Value::String(s)) => s.clone(),
		Some(Value::Object(o)) => o
			.get("id")
			.and_then(Value::as_str)
			.ok_or_else(|| malformed("issuer has no id"))?
			.to_owned(),
		_ => return Err(malformed("no issuer")),
	};
	let keys = trust
		.get(&issuer)
		.ok_or_else(|| VcError::UntrustedIssuer(issuer.clone()))?;
	let proof = vc
		.get("proof")
		.and_then(Value::as_object)
		.ok_or_else(|| malformed("no proof"))?;
	let method = proof
		.get("verificationMethod")
		.and_then(Value::as_str)
		.ok_or_else(|| malformed("proof has no verificationMethod"))?;
	let (controller, kid) = method
		.split_once('#')
		.ok_or_else(|| malformed("verificationMethod is not <issuer>#<kid>"))?;
	if controller != issuer {
		return Err(VcError::UntrustedIssuer(controller.to_owned()));
	}
	let key = keys
		.find(kid)
		.and_then(PublicKey::from_jwk)
		.ok_or(VcError::UnknownKey)?;
	let at = |k: &str| -> Result<Option<i64>, VcError> {
		proof
			.get(k)
			.and_then(Value::as_str)
			.map(|s| {
				DateTime::parse_from_rfc3339(s)
					.map(|t| t.timestamp())
					.map_err(|e| malformed(format!("{k}: {e}")))
			})
			.transpose()
	};
	let (now, skew) = (now as i64, skew as i64);
	if at("created")?.is_some_and(|c| c > now + skew)
		|| at("expires")?.is_some_and(|e| e + skew < now)
	{
		return Err(VcError::ProofNotCurrent);
	}
	verify_proof(&vc, &key)?;

	let mut claims = match vc.get("credentialSubject") {
		Some(Value::Object(c)) => c.clone(),
		_ => return Err(malformed("credentialSubject is not one object")),
	};
	match claims.get("issuer") {
		None => {
			claims.insert("issuer".into(), Value::String(issuer.clone()));
		},
		Some(Value::String(s)) if *s == issuer => {},
		Some(_) => return Err(malformed("credentialSubject.issuer is not the VC issuer")),
	}
	Ok(VerifiedVc {
		claims: Value::Object(claims),
		issuer,
	})
}

fn to_canon(v: &Value) -> Result<Canon, VcError> {
	haps_canon::parse(&v.to_string()).map_err(|e| malformed(format!("{e:?}")))
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Multibase base58btc (`z` prefix), the only base Data Integrity proofs and did:key use.
pub fn multibase_decode(s: &str) -> Result<Vec<u8>, VcError> {
	let body = s
		.strip_prefix('z')
		.ok_or_else(|| malformed("not multibase base58btc"))?;
	if body.len() > 1024 {
		return Err(malformed("multibase value too long"));
	}
	let mut bytes: Vec<u8> = Vec::new();
	for c in body.bytes() {
		let mut carry = BASE58
			.iter()
			.position(|&b| b == c)
			.ok_or_else(|| malformed("invalid base58 character"))? as u32;
		for b in bytes.iter_mut().rev() {
			carry += u32::from(*b) * 58;
			*b = (carry & 0xff) as u8;
			carry >>= 8;
		}
		while carry > 0 {
			bytes.insert(0, (carry & 0xff) as u8);
			carry >>= 8;
		}
	}
	let zeros = body.bytes().take_while(|&c| c == b'1').count();
	let mut out = vec![0u8; zeros];
	out.extend(bytes);
	Ok(out)
}

/// Multibase base58btc encoding, for issuing in tests and tools.
pub fn multibase_encode(bytes: &[u8]) -> String {
	let mut digits: Vec<u8> = Vec::new();
	for &b in bytes {
		let mut carry = u32::from(b);
		for d in digits.iter_mut().rev() {
			carry += u32::from(*d) << 8;
			*d = (carry % 58) as u8;
			carry /= 58;
		}
		while carry > 0 {
			digits.insert(0, (carry % 58) as u8);
			carry /= 58;
		}
	}
	let zeros = bytes.iter().take_while(|&&b| b == 0).count();
	let mut s = String::from("z");
	s.extend(std::iter::repeat_n('1', zeros));
	s.extend(digits.iter().map(|&d| BASE58[d as usize] as char));
	s
}

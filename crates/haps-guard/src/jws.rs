//! Compact JWS verification against keys scoped to their issuer.
//!
//! Used for both Consent Credentials (keys per Presence Provider) and Provider Certification
//! Credentials (keys per certifier). A key is trusted only for the issuer it is configured
//! under: a credential verifies only if its signature is valid under one of that issuer's keys
//! *and* the payload names that issuer. One trusted provider can therefore not sign as another,
//! which a single shared key set plus an issuer allowlist would allow.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;

#[derive(Debug, PartialEq, Eq)]
pub enum JwsError {
	UnsupportedAlgorithm(String),
	UnknownKey,
	BadSignature,
	Malformed(String),
	/// Signed by a trusted key, but naming an issuer that key is not trusted for.
	UntrustedIssuer(String),
}

/// A verified JWS: its typed claims, and the payload bytes exactly as signed.
pub struct Verified<T> {
	pub claims: T,
	pub issuer: String,
	pub payload: Vec<u8>,
}

/// Verify `token` against `trust` (issuer → keys). `issuer_of` names the issuer the payload
/// claims. Only EdDSA and ES256 are accepted: asymmetric, so the verifier never holds a secret
/// that could also sign.
pub fn verify<T: DeserializeOwned>(
	token: &str,
	trust: &HashMap<String, JwkSet>,
	issuer_of: fn(&T) -> &str,
) -> Result<Verified<T>, JwsError> {
	let header =
		jsonwebtoken::decode_header(token).map_err(|e| JwsError::Malformed(e.to_string()))?;
	if !matches!(header.alg, Algorithm::EdDSA | Algorithm::ES256) {
		return Err(JwsError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
	}
	let kid = header.kid.ok_or(JwsError::UnknownKey)?;
	let mut validation = Validation::new(header.alg);
	// Every claim is checked by the caller against an injected clock.
	validation.validate_exp = false;
	validation.validate_nbf = false;
	validation.validate_aud = false;
	validation.required_spec_claims.clear();

	// Issuers are tried in a fixed order, so the outcome never depends on map iteration.
	let mut issuers: Vec<&String> = trust.keys().collect();
	issuers.sort();
	let mut result = Err(JwsError::UnknownKey);
	for issuer in issuers {
		let Some(jwk) = trust[issuer].find(&kid) else {
			continue;
		};
		// Defence against algorithm confusion: a key that names its algorithm must match.
		if let Some(key_alg) = jwk.common.key_algorithm
			&& format!("{key_alg:?}") != format!("{:?}", header.alg)
		{
			result = Err(JwsError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
			continue;
		}
		let Ok(key) = DecodingKey::from_jwk(jwk) else {
			continue;
		};
		match jsonwebtoken::decode::<T>(token, &key, &validation) {
			Ok(data) => {
				let claimed = issuer_of(&data.claims);
				if claimed != issuer.as_str() {
					result = Err(JwsError::UntrustedIssuer(claimed.to_owned()));
					continue;
				}
				return Ok(Verified {
					issuer: issuer.clone(),
					payload: payload_bytes(token)?,
					claims: data.claims,
				});
			},
			Err(e) => {
				result = Err(match e.kind() {
					jsonwebtoken::errors::ErrorKind::InvalidSignature => JwsError::BadSignature,
					_ => JwsError::Malformed(e.to_string()),
				});
			},
		}
	}
	result
}

fn payload_bytes(token: &str) -> Result<Vec<u8>, JwsError> {
	let segment = token
		.split('.')
		.nth(1)
		.ok_or_else(|| JwsError::Malformed("no payload segment".into()))?;
	URL_SAFE_NO_PAD
		.decode(segment)
		.map_err(|e| JwsError::Malformed(e.to_string()))
}

//! RP-CORE-06 and FACTOR-RP-04: provider certification.
//!
//! Without a verified HAPS Provider Certification Credential (HAPS-PCC), a credential's PoHP
//! level is asserted by whoever holds the signing key (`pohp-assurance-levels-v0.4.md` §4). The
//! guard therefore accepts a level only when a certifier it trusts has certified the issuing
//! provider for both that level and the factor that produced it.
//!
//! What HAPS leaves open, and how the guard settles it:
//!
//! - **Wire form.** `providerCertification.embedded` is a string; the guard reads it as a
//!   compact JWS whose payload is the PCC claims object, signed by the certifier.
//! - **Referenced only.** A `ref` alone is never fetched: fetching URLs named by a credential
//!   would let a presenter steer the gateway's requests. The operator provisions referenced
//!   certifications instead, keyed by `ref`, as HAPS anticipates ("core verification can run
//!   locally when keys, certifications ... are provisioned").
//! - **`hash`.** When present, it must equal `sha256:` + base64url of the JCS-canonical PCC
//!   claims, the same construction as `intent_hash`, so it is independent of JWS encoding.
//! - **Which provider.** A PCC names a `providerId`, a credential an `issuer`, and HAPS supplies
//!   no mapping between them. The operator configures it; an issuer with no mapping cannot be
//!   certified.
//!
//! Checking a certification establishes who issued it under the configured trust. It does not
//! reproduce the evaluator's work or show that the deployment still meets the evaluated
//! conditions (§4); and conformance of this guard is no evidence of any PoHP level (§16).

use std::collections::HashMap;
use std::fmt;

use chrono::DateTime;
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;

use crate::jws::{self, JwsError};

/// The operator's certification trust.
#[derive(Default)]
pub struct CertificationConfig {
	/// Trusted certifiers, `accepted_certifiers` in HAPS terms: certifier id → its keys.
	pub certifiers: HashMap<String, JwkSet>,
	/// Credential issuer → the `providerId` its certifications name.
	pub providers: HashMap<String, String>,
	/// Certifications provisioned out of band, by `providerCertification.ref`: compact JWS.
	pub provisioned: HashMap<String, String>,
}

/// `providerCertification` as a credential carries it.
#[derive(Debug, Deserialize)]
pub struct ProviderCertification {
	#[serde(rename = "ref")]
	pub reference: String,
	#[serde(default)]
	pub hash: Option<String>,
	#[serde(default)]
	pub embedded: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pcc {
	provider_id: String,
	certified_levels: Vec<String>,
	certified_factors: Vec<String>,
	issuer: String,
	issued_at: String,
	expires_at: String,
	#[serde(default)]
	evaluation: Option<Evaluation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Evaluation {
	#[serde(default)]
	lab: Option<String>,
	#[serde(default)]
	report_id: Option<String>,
}

/// What a valid certification established, for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certified {
	pub certifier: String,
	pub provider_id: String,
	/// The evaluation behind it: lab and/or report id.
	pub evaluation: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertificationError {
	/// Neither embedded nor provisioned for this `ref`.
	Unresolvable(String),
	Signature(JwsError),
	HashMismatch,
	/// The credential's issuer has no configured provider mapping.
	UnknownProvider(String),
	WrongProvider {
		expected: String,
		certified: String,
	},
	NotYetValid,
	Expired,
	Malformed(String),
	LevelNotCertified(String),
	FactorNotCertified(String),
	/// §16.1: a certification that names neither an evaluation nor an evaluator is not evidence.
	NoEvaluation,
}

impl fmt::Display for CertificationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			CertificationError::Unresolvable(r) => write!(
				f,
				"provider certification {r} is neither embedded nor provisioned"
			),
			CertificationError::Signature(e) => {
				write!(
					f,
					"provider certification is not from a trusted certifier ({e:?})"
				)
			},
			CertificationError::HashMismatch => {
				write!(f, "provider certification does not match its hash")
			},
			CertificationError::UnknownProvider(i) => {
				write!(f, "issuer {i} is not mapped to a certified provider")
			},
			CertificationError::WrongProvider {
				expected,
				certified,
			} => write!(
				f,
				"provider certification is for {certified}, not the issuing provider {expected}"
			),
			CertificationError::NotYetValid => write!(f, "provider certification is not yet valid"),
			CertificationError::Expired => write!(f, "provider certification has expired"),
			CertificationError::Malformed(e) => write!(f, "provider certification is malformed: {e}"),
			CertificationError::LevelNotCertified(l) => {
				write!(f, "provider is not certified for {l}")
			},
			CertificationError::FactorNotCertified(m) => {
				write!(f, "provider is not certified for the factor {m}")
			},
			CertificationError::NoEvaluation => write!(
				f,
				"provider certification names no evaluation, so it is not evidence"
			),
		}
	}
}

/// Validate that `pc` certifies `cc_issuer` for `level` and `method` at `now`.
pub fn validate(
	config: &CertificationConfig,
	pc: &ProviderCertification,
	cc_issuer: &str,
	level: &str,
	method: &str,
	now: u64,
	skew: u64,
) -> Result<Certified, CertificationError> {
	let token = pc
		.embedded
		.as_deref()
		.or_else(|| config.provisioned.get(&pc.reference).map(String::as_str))
		.ok_or_else(|| CertificationError::Unresolvable(pc.reference.clone()))?;
	let verified = jws::verify::<Pcc>(token, &config.certifiers, |p| &p.issuer)
		.map_err(CertificationError::Signature)?;

	if let Some(expected) = &pc.hash {
		let text = std::str::from_utf8(&verified.payload)
			.map_err(|_| CertificationError::Malformed("payload is not UTF-8".into()))?;
		let canon = haps_canon::parse(text)
			.map_err(|e| CertificationError::Malformed(format!("payload: {e:?}")))?;
		if &haps_hash::hash_value(&canon) != expected {
			return Err(CertificationError::HashMismatch);
		}
	}

	let pcc = verified.claims;
	let expected = config
		.providers
		.get(cc_issuer)
		.ok_or_else(|| CertificationError::UnknownProvider(cc_issuer.to_owned()))?;
	if &pcc.provider_id != expected {
		return Err(CertificationError::WrongProvider {
			expected: expected.clone(),
			certified: pcc.provider_id,
		});
	}

	let at = |s: &str| {
		DateTime::parse_from_rfc3339(s)
			.map(|t| t.timestamp())
			.map_err(|e| CertificationError::Malformed(format!("{s:?}: {e}")))
	};
	let (issued, expires) = (at(&pcc.issued_at)?, at(&pcc.expires_at)?);
	let (now, skew) = (now as i64, skew as i64);
	if issued > now + skew {
		return Err(CertificationError::NotYetValid);
	}
	if now > expires + skew {
		return Err(CertificationError::Expired);
	}

	if !pcc.certified_levels.iter().any(|l| l == level) {
		return Err(CertificationError::LevelNotCertified(level.to_owned()));
	}
	// The factor must be named exactly. An unrecognised value is uncertified for policy
	// purposes (PCC schema), which exact matching already gives.
	if !pcc.certified_factors.iter().any(|m| m == method) {
		return Err(CertificationError::FactorNotCertified(method.to_owned()));
	}
	fn named(s: &Option<String>) -> Option<&str> {
		s.as_deref().filter(|s| !s.trim().is_empty())
	}
	let evaluation = match pcc
		.evaluation
		.as_ref()
		.map(|e| (named(&e.lab), named(&e.report_id)))
	{
		Some((Some(lab), Some(report))) => format!("{lab} {report}"),
		Some((Some(only), None) | (None, Some(only))) => only.to_owned(),
		_ => return Err(CertificationError::NoEvaluation),
	};
	Ok(Certified {
		certifier: verified.issuer,
		provider_id: pcc.provider_id,
		evaluation,
	})
}

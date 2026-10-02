//! HAPS-RP-ID-0.4: identity binding.
//!
//! An approval says a human was present and approved; identity binding says *who*. The guard
//! checks it against two schemes:
//!
//! - **EUDI wallet** — `digital_credentials_portrait_liveness`, in its plain Digital
//!   Credentials mode, with an EUDI wallet presentation (`source: eudi_wallet`). The Presence
//!   Provider asks the wallet for a PID (or another attestation) over OpenID4VP; the wallet
//!   answers with an SD-JWT VC and a key-binding JWT signed by its device key. Embedded, the
//!   guard re-verifies all of it: issuer signature against a trusted PID issuer, disclosures,
//!   the device signature, and the binding of that signature to this approval.
//! - **Google** — `google_oidc`, a guard-defined adapter modelled on HAPS's `entra_oidc`: the
//!   Presence Provider signs the human in with Google, and the subject is their verified email.
//!   Embedded, the guard re-verifies the Google ID token.
//!
//! **Binding the evidence to the approval.** Identity evidence proves nothing about *this*
//! approval unless it was produced for it. The guard requires the evidence's freshness value to
//! be the approval's own: the HAPS-CHAL `challengeId` in challenge mode, otherwise the
//! credential's `intent_hash`. The Presence Provider uses that as the OpenID4VP request `nonce`
//! (EUDI) or the OIDC `nonce` (Google). HAPS leaves this construction open; this is the guard's.
//!
//! **Whose identity.** RP-IDB-03 requires the subject to match the relying party's own account
//! for the caller. The guard takes that account from gateway metadata: an operator maps, say,
//! the authenticated JWT's `email` claim into the guardrail metadata, and names the key here.
//!
//! An identity binding establishes who, not that a human approved (`haps-v0.4.0.md` §9.4), and
//! no authority to act. Revocation (EUDI Token Status Lists) is not checked.

use std::collections::HashMap;
use std::fmt;
use std::sync::{PoisonError, RwLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

pub const SCHEME_EUDI: &str = "digital_credentials_portrait_liveness";
pub const SCHEME_GOOGLE: &str = "google_oidc";
const DC_PROFILE: &str = "haps.profile.digital-credentials-portrait-liveness/v0.1";
const DC_EVIDENCE_TYPE: &str = "digital_credentials_portrait_liveness_evidence";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
/// Upper bound on an embedded presentation or token the guard will parse.
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
	EudiWallet,
	Google,
}

impl Scheme {
	pub fn wire_name(self) -> &'static str {
		match self {
			Scheme::EudiWallet => SCHEME_EUDI,
			Scheme::Google => SCHEME_GOOGLE,
		}
	}
}

/// Keys that rotate. Shared with whatever refreshes them.
#[derive(Default)]
pub struct KeySource(RwLock<JwkSet>);

impl KeySource {
	pub fn new(keys: JwkSet) -> Self {
		Self(RwLock::new(keys))
	}

	pub fn replace(&self, keys: JwkSet) {
		*self.0.write().unwrap_or_else(PoisonError::into_inner) = keys;
	}

	fn find(&self, kid: &str) -> Option<Jwk> {
		self
			.0
			.read()
			.unwrap_or_else(PoisonError::into_inner)
			.find(kid)
			.cloned()
	}
}

/// What the operator trusts for identity evidence.
#[derive(Default)]
pub struct IdentityTrust {
	pub google: Option<GoogleTrust>,
	pub eudi: Option<EudiTrust>,
}

pub struct GoogleTrust {
	/// The Presence Providers' Google OAuth client ids: an ID token must be addressed to one.
	pub client_ids: Vec<String>,
	/// Google's signing keys (https://www.googleapis.com/oauth2/v3/certs).
	pub keys: std::sync::Arc<KeySource>,
}

pub struct EudiTrust {
	/// Trusted credential issuers, by `iss`.
	pub issuers: HashMap<String, CredentialIssuer>,
	/// The OpenID4VP `client_id` each Presence Provider verifies as, by HAPS issuer: the
	/// audience its key-binding JWTs name. A provider not listed is taken to use its issuer id.
	pub verifier_client_ids: HashMap<String, String>,
}

pub struct CredentialIssuer {
	pub keys: JwkSet,
	/// The `vct` values this issuer is trusted for, e.g. `urn:eudi:pid:1`.
	pub vcts: Vec<String>,
}

/// Per-tool identity policy.
#[derive(Clone, Debug)]
pub struct IdentityPolicy {
	/// `required`: no approval without a binding. Otherwise `preferred`: a binding is checked
	/// when present.
	pub required: bool,
	/// Accepted schemes.
	pub schemes: Vec<Scheme>,
	/// Refuse a binding the provider marks `asserted` rather than `verified`.
	pub require_verified: bool,
	/// RP-IDB-04: the evidence must be embedded, so the guard re-verifies it rather than taking
	/// the provider's word. Always on from PoHP-3 (RP-IDB-06).
	pub require_embedded_evidence: bool,
	/// RP-IDB-03: the gateway metadata key holding the caller's account identity.
	pub account_attribute: Option<String>,
	/// EUDI: the disclosed claim that identifies the account, e.g. `email_address`. Without it,
	/// the wallet's key thumbprint (RFC 7638) is the subject.
	pub eudi_subject_claim: Option<String>,
	/// Google: accepted Workspace domains (`hd`). Empty accepts any verified email.
	pub google_domains: Vec<String>,
	/// RP-IDB-05: maximum age of the underlying authentication.
	pub max_auth_age_secs: Option<u64>,
	/// How long before the approval the evidence may have been produced.
	pub max_evidence_age_secs: u64,
}

impl IdentityPolicy {
	pub fn new(required: bool, schemes: Vec<Scheme>) -> Self {
		Self {
			required,
			schemes,
			require_verified: false,
			require_embedded_evidence: false,
			account_attribute: None,
			eudi_subject_claim: None,
			google_domains: Vec::new(),
			max_auth_age_secs: None,
			max_evidence_age_secs: 300,
		}
	}
}

/// What the approval itself says, that the evidence must agree with.
pub struct ApprovalContext<'a> {
	pub cc_issuer: &'a str,
	/// The credential's `iat`: evidence is judged as of the consent event.
	pub cc_iat: u64,
	pub intent_hash: &'a str,
	pub challenge_id: Option<&'a str>,
	/// This relying party.
	pub audience: &'a str,
	pub skew: u64,
}

impl ApprovalContext<'_> {
	/// The freshness value identity evidence must carry: see the module docs.
	pub fn expected_nonce(&self) -> &str {
		self.challenge_id.unwrap_or(self.intent_hash)
	}
}

/// A checked binding, for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
	pub scheme: &'static str,
	/// The value matched against the account.
	pub subject: String,
	/// Whether the guard re-verified the evidence, rather than relying on the provider.
	pub reverified: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
	/// RP-IDB-01.
	Missing,
	/// RP-IDB-02.
	SchemeNotAccepted(String),
	NotVerified,
	/// RP-IDB-04.
	EvidenceRequired,
	/// The scheme is accepted but nothing is configured to verify it.
	NotConfigured(&'static str),
	Malformed(String),
	/// A signature, issuer or audience check on the evidence failed.
	Evidence(String),
	/// The evidence was not produced for this approval.
	NotBoundToApproval(String),
	/// RP-IDB-03.
	NoAccount,
	SubjectMismatch,
	DomainNotAccepted,
	/// RP-IDB-05.
	AuthenticationTooOld,
}

impl fmt::Display for IdentityError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			IdentityError::Missing => write!(f, "this tool requires an approval bound to your identity"),
			IdentityError::SchemeNotAccepted(s) => {
				write!(f, "identity scheme {s} is not accepted for this tool")
			},
			IdentityError::NotVerified => write!(f, "identity was asserted, not verified"),
			IdentityError::EvidenceRequired => write!(
				f,
				"identity evidence must be embedded so it can be re-verified"
			),
			IdentityError::NotConfigured(s) => {
				write!(f, "identity scheme {s} is not configured on this gateway")
			},
			IdentityError::Malformed(e) => write!(f, "identity binding is malformed: {e}"),
			IdentityError::Evidence(e) => write!(f, "identity evidence failed verification: {e}"),
			IdentityError::NotBoundToApproval(e) => {
				write!(
					f,
					"identity evidence was not produced for this approval: {e}"
				)
			},
			IdentityError::NoAccount => write!(
				f,
				"the gateway has no authenticated account to match the identity against"
			),
			IdentityError::SubjectMismatch => {
				write!(
					f,
					"the approving identity is not the account making this call"
				)
			},
			IdentityError::DomainNotAccepted => write!(f, "the identity's domain is not accepted"),
			IdentityError::AuthenticationTooOld => {
				write!(
					f,
					"the identity authentication is older than this tool accepts"
				)
			},
		}
	}
}

fn malformed(e: impl Into<String>) -> IdentityError {
	IdentityError::Malformed(e.into())
}

fn evidence(e: impl Into<String>) -> IdentityError {
	IdentityError::Evidence(e.into())
}

fn unbound(e: impl Into<String>) -> IdentityError {
	IdentityError::NotBoundToApproval(e.into())
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
	v.get(key).and_then(Value::as_str)
}

/// Check `claims.identityBinding` against `policy`. `account` is the gateway metadata.
pub fn check(
	trust: &IdentityTrust,
	policy: &IdentityPolicy,
	min_level_3: bool,
	binding: Option<&Value>,
	ctx: &ApprovalContext<'_>,
	account: Option<&Map<String, Value>>,
) -> Result<Option<Bound>, IdentityError> {
	let Some(binding) = binding else {
		return if policy.required {
			Err(IdentityError::Missing)
		} else {
			Ok(None)
		};
	};
	let scheme_name = str_of(binding, "scheme").ok_or_else(|| malformed("no scheme"))?;
	let scheme = policy
		.schemes
		.iter()
		.copied()
		.find(|s| s.wire_name() == scheme_name)
		.ok_or_else(|| IdentityError::SchemeNotAccepted(scheme_name.to_owned()))?;
	match str_of(binding, "mode") {
		Some("verified") => {},
		Some("asserted") if !policy.require_verified => {},
		Some("asserted") => return Err(IdentityError::NotVerified),
		_ => return Err(malformed("mode must be asserted or verified")),
	}
	let subject = binding
		.get("subject")
		.filter(|s| s.is_object())
		.ok_or_else(|| malformed("no subject"))?;
	let require_embedded = policy.require_embedded_evidence || min_level_3;
	let bound = match scheme {
		Scheme::Google => google(trust, policy, binding, subject, ctx, require_embedded)?,
		Scheme::EudiWallet => eudi(trust, policy, binding, subject, ctx, require_embedded)?,
	};

	// RP-IDB-03: the approving identity is the account making the call.
	if let Some(attr) = &policy.account_attribute {
		let account = account
			.and_then(|a| a.get(attr))
			.and_then(Value::as_str)
			.ok_or(IdentityError::NoAccount)?;
		let matches = match scheme {
			// Email addresses compare case-insensitively in practice; Google lowercases them.
			Scheme::Google => account.eq_ignore_ascii_case(&bound.subject),
			Scheme::EudiWallet => account == bound.subject,
		};
		if !matches {
			return Err(IdentityError::SubjectMismatch);
		}
	}
	Ok(Some(bound))
}

// ------------------------------------------------------------------ Google

fn google(
	trust: &IdentityTrust,
	policy: &IdentityPolicy,
	binding: &Value,
	subject: &Value,
	ctx: &ApprovalContext<'_>,
	require_embedded: bool,
) -> Result<Bound, IdentityError> {
	let email = str_of(subject, "email").ok_or_else(|| malformed("subject.email missing"))?;
	let token = binding.get("evidence").and_then(|e| str_of(e, "idToken"));
	let Some(token) = token else {
		if require_embedded {
			return Err(IdentityError::EvidenceRequired);
		}
		// Asserted by the provider: its signature on the credential is all there is.
		if let Some(iss) = binding.get("idp").and_then(|i| str_of(i, "issuer"))
			&& !GOOGLE_ISSUERS.contains(&iss)
		{
			return Err(malformed("idp.issuer is not Google"));
		}
		if !policy.google_domains.is_empty() {
			let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
			if !policy
				.google_domains
				.iter()
				.any(|d| d.eq_ignore_ascii_case(domain))
			{
				return Err(IdentityError::DomainNotAccepted);
			}
		}
		return Ok(Bound {
			scheme: SCHEME_GOOGLE,
			subject: email.to_owned(),
			reverified: false,
		});
	};
	let trust = trust
		.google
		.as_ref()
		.ok_or(IdentityError::NotConfigured(SCHEME_GOOGLE))?;
	if token.len() > MAX_EVIDENCE_BYTES {
		return Err(malformed("ID token too large"));
	}
	let header = jsonwebtoken::decode_header(token).map_err(|e| malformed(e.to_string()))?;
	// Google signs ID tokens with RS256.
	if header.alg != Algorithm::RS256 {
		return Err(evidence(format!("ID token algorithm {:?}", header.alg)));
	}
	let kid = header.kid.ok_or_else(|| evidence("ID token has no kid"))?;
	let jwk = trust
		.keys
		.find(&kid)
		.ok_or_else(|| evidence("ID token signed by an unknown Google key"))?;
	let key = DecodingKey::from_jwk(&jwk).map_err(|e| evidence(e.to_string()))?;
	let mut v = Validation::new(Algorithm::RS256);
	v.validate_exp = false;
	v.validate_nbf = false;
	v.set_audience(&trust.client_ids);
	v.set_issuer(&GOOGLE_ISSUERS);
	v.set_required_spec_claims(&["iss", "aud", "exp", "iat"]);
	let claims: Value = jsonwebtoken::decode(token, &key, &v)
		.map_err(|e| evidence(e.to_string()))?
		.claims;

	if claims.get("email_verified").and_then(Value::as_bool) != Some(true) {
		return Err(evidence("email is not verified"));
	}
	let token_email = str_of(&claims, "email").ok_or_else(|| evidence("no email"))?;
	if !token_email.eq_ignore_ascii_case(email) {
		return Err(evidence("subject.email is not the token's email"));
	}
	if let Some(sub) = str_of(subject, "sub")
		&& str_of(&claims, "sub") != Some(sub)
	{
		return Err(evidence("subject.sub is not the token's sub"));
	}
	if !policy.google_domains.is_empty() {
		let hd = str_of(&claims, "hd").ok_or(IdentityError::DomainNotAccepted)?;
		if !policy
			.google_domains
			.iter()
			.any(|d| d.eq_ignore_ascii_case(hd))
		{
			return Err(IdentityError::DomainNotAccepted);
		}
	}
	if str_of(&claims, "nonce") != Some(ctx.expected_nonce()) {
		return Err(unbound("the ID token nonce is not this approval's"));
	}
	let num = |k: &str| claims.get(k).and_then(Value::as_u64);
	let (iat, exp) = (num("iat").unwrap_or(0), num("exp").unwrap_or(0));
	fresh(iat, exp, policy, ctx)?;
	if let (Some(max), Some(auth_time)) = (policy.max_auth_age_secs, num("auth_time"))
		&& ctx.cc_iat > auth_time.saturating_add(max).saturating_add(ctx.skew)
	{
		return Err(IdentityError::AuthenticationTooOld);
	}
	Ok(Bound {
		scheme: SCHEME_GOOGLE,
		subject: token_email.to_ascii_lowercase(),
		reverified: true,
	})
}

/// Evidence produced shortly before the consent event and still valid at it.
fn fresh(
	iat: u64,
	exp: u64,
	policy: &IdentityPolicy,
	ctx: &ApprovalContext<'_>,
) -> Result<(), IdentityError> {
	if iat > ctx.cc_iat.saturating_add(ctx.skew) {
		return Err(unbound("evidence issued after the approval"));
	}
	if ctx.cc_iat > iat.saturating_add(policy.max_evidence_age_secs) {
		return Err(unbound("evidence is older than the approval allows"));
	}
	if exp != 0 && exp.saturating_add(ctx.skew) < ctx.cc_iat {
		return Err(evidence("evidence had expired at the approval"));
	}
	Ok(())
}

// ------------------------------------------------------------------ EUDI wallet

fn eudi(
	trust: &IdentityTrust,
	policy: &IdentityPolicy,
	binding: &Value,
	subject: &Value,
	ctx: &ApprovalContext<'_>,
	require_embedded: bool,
) -> Result<Bound, IdentityError> {
	let ev = binding
		.get("evidence")
		.ok_or_else(|| malformed("no evidence"))?;
	if str_of(ev, "type") != Some(DC_EVIDENCE_TYPE) || str_of(ev, "profile") != Some(DC_PROFILE) {
		return Err(malformed(
			"evidence is not Digital Credentials profile evidence",
		));
	}
	let cp = ev
		.get("credential_presentation")
		.ok_or_else(|| malformed("no credential_presentation"))?;
	if str_of(cp, "source") != Some("eudi_wallet") {
		return Err(malformed(
			"credential_presentation.source is not eudi_wallet",
		));
	}
	// Session binding, as the provider records it (DCA-RP-02).
	let b = ev.get("binding").ok_or_else(|| malformed("no binding"))?;
	if str_of(b, "audience") != Some(ctx.audience) {
		return Err(unbound("evidence binding names another relying party"));
	}
	if str_of(b, "challenge_id") != Some(ctx.expected_nonce()) {
		return Err(unbound(
			"evidence binding.challenge_id is not this approval's",
		));
	}
	if let Some(action) = str_of(b, "action_hash")
		&& action != ctx.intent_hash
	{
		return Err(unbound(
			"evidence binding.action_hash is not the approved intent",
		));
	}

	let presentation = str_of(cp, "presentation");
	let Some(presentation) = presentation else {
		if require_embedded {
			return Err(IdentityError::EvidenceRequired);
		}
		let asserted = match &policy.eudi_subject_claim {
			Some(claim) => subject
				.get("claims")
				.and_then(|c| str_of(c, claim))
				.ok_or_else(|| malformed(format!("subject.claims.{claim} missing")))?,
			None => str_of(subject, "binding_key_thumbprint")
				.ok_or_else(|| malformed("subject.binding_key_thumbprint missing"))?,
		};
		return Ok(Bound {
			scheme: SCHEME_EUDI,
			subject: asserted.to_owned(),
			reverified: false,
		});
	};
	if str_of(ev, "mode") != Some("plain_digital_credentials") {
		return Err(evidence(
			"only plain Digital Credentials evidence can be re-verified here",
		));
	}
	let trust = trust
		.eudi
		.as_ref()
		.ok_or(IdentityError::NotConfigured(SCHEME_EUDI))?;
	if presentation.len() > MAX_EVIDENCE_BYTES {
		return Err(malformed("presentation too large"));
	}
	// DCA-RP-02: the recorded hash is of the presentation actually embedded.
	if str_of(cp, "presentation_hash")
		!= Some(haps_hash::sha256_prefixed(presentation.as_bytes()).as_str())
	{
		return Err(evidence(
			"presentation_hash does not match the presentation",
		));
	}
	let audience = trust
		.verifier_client_ids
		.get(ctx.cc_issuer)
		.map_or(ctx.cc_issuer, String::as_str);
	let verified =
		verify_sd_jwt_presentation(presentation, &trust.issuers, audience, ctx.expected_nonce())?;
	if let Some(id) = cp.get("issuer").and_then(|i| str_of(i, "id"))
		&& id != verified.issuer
	{
		return Err(evidence(
			"credential_presentation.issuer is not the credential's issuer",
		));
	}
	fresh(verified.kb_iat, verified.exp.unwrap_or(0), policy, ctx)?;
	if let Some(nbf) = verified.nbf
		&& nbf > ctx.cc_iat.saturating_add(ctx.skew)
	{
		return Err(evidence("credential was not yet valid at the approval"));
	}
	if let Some(t) = str_of(subject, "binding_key_thumbprint")
		&& t != verified.thumbprint
	{
		return Err(evidence(
			"subject.binding_key_thumbprint is not the wallet key",
		));
	}
	let subject = match &policy.eudi_subject_claim {
		Some(claim) => verified
			.claims
			.get(claim)
			.and_then(Value::as_str)
			.ok_or_else(|| evidence(format!("the wallet did not disclose {claim}")))?
			.to_owned(),
		None => verified.thumbprint,
	};
	Ok(Bound {
		scheme: SCHEME_EUDI,
		subject,
		reverified: true,
	})
}

/// A verified SD-JWT VC presentation.
#[derive(Debug)]
pub struct VerifiedPresentation {
	pub issuer: String,
	pub vct: String,
	/// The disclosed claims, with the disclosures applied.
	pub claims: Map<String, Value>,
	/// RFC 7638 thumbprint of the holder key (`cnf.jwk`).
	pub thumbprint: String,
	pub kb_iat: u64,
	pub exp: Option<u64>,
	pub nbf: Option<u64>,
}

/// Verify an SD-JWT VC presentation (`<issuer-jwt>~<disclosure>~...~<kb-jwt>`, RFC 9901 with
/// the SD-JWT VC profile): the issuer's signature under a trusted issuer's key and `vct`, every
/// disclosure, and the holder's key-binding JWT — signed by `cnf.jwk`, naming `audience` and
/// `nonce`, and covering exactly these disclosures (`sd_hash`).
pub fn verify_sd_jwt_presentation(
	presentation: &str,
	issuers: &HashMap<String, CredentialIssuer>,
	audience: &str,
	nonce: &str,
) -> Result<VerifiedPresentation, IdentityError> {
	let mut parts: Vec<&str> = presentation.split('~').collect();
	if parts.len() < 2 {
		return Err(malformed("not an SD-JWT presentation"));
	}
	let kb_jwt = parts.pop().unwrap_or("");
	if kb_jwt.is_empty() {
		return Err(evidence("presentation has no key-binding JWT"));
	}
	let issuer_jwt = parts[0];
	let disclosures = &parts[1..];
	if disclosures.iter().any(|d| d.is_empty()) {
		return Err(malformed("empty disclosure"));
	}

	// The issuer, chosen by the unverified `iss` and then authenticated by its signature.
	let header = jsonwebtoken::decode_header(issuer_jwt).map_err(|e| malformed(e.to_string()))?;
	if header.typ.as_deref() != Some("dc+sd-jwt") {
		return Err(evidence("issuer JWT typ is not dc+sd-jwt"));
	}
	if !matches!(header.alg, Algorithm::ES256 | Algorithm::EdDSA) {
		return Err(evidence(format!("issuer JWT algorithm {:?}", header.alg)));
	}
	let unverified = decode_payload(issuer_jwt)?;
	let iss = str_of(&unverified, "iss").ok_or_else(|| malformed("credential has no iss"))?;
	let trusted = issuers
		.get(iss)
		.ok_or_else(|| evidence(format!("credential issuer {iss} is not trusted")))?;
	let mut v = Validation::new(header.alg);
	v.validate_exp = false;
	v.validate_nbf = false;
	v.validate_aud = false;
	v.required_spec_claims.clear();
	let candidates: Vec<&Jwk> = match &header.kid {
		Some(kid) => trusted.keys.find(kid).into_iter().collect(),
		None => trusted.keys.keys.iter().collect(),
	};
	let payload: Value = candidates
		.iter()
		.find_map(|jwk| {
			let key = DecodingKey::from_jwk(jwk).ok()?;
			jsonwebtoken::decode::<Value>(issuer_jwt, &key, &v)
				.ok()
				.map(|d| d.claims)
		})
		.ok_or_else(|| evidence("credential signature does not verify under its issuer's keys"))?;
	let vct = str_of(&payload, "vct").ok_or_else(|| evidence("credential has no vct"))?;
	if !trusted.vcts.iter().any(|t| t == vct) {
		return Err(evidence(format!("issuer is not trusted for {vct}")));
	}
	match str_of(&payload, "_sd_alg") {
		None | Some("sha-256") => {},
		Some(other) => return Err(evidence(format!("unsupported _sd_alg {other}"))),
	}

	let claims = apply_disclosures(&payload, disclosures)?;

	// The holder's key binding.
	let cnf = payload
		.get("cnf")
		.and_then(|c| c.get("jwk"))
		.ok_or_else(|| evidence("credential has no cnf.jwk"))?;
	let holder: Jwk =
		serde_json::from_value(cnf.clone()).map_err(|e| evidence(format!("cnf.jwk: {e}")))?;
	let thumbprint = thumbprint(cnf)?;
	let kb_header = jsonwebtoken::decode_header(kb_jwt).map_err(|e| malformed(e.to_string()))?;
	if kb_header.typ.as_deref() != Some("kb+jwt") {
		return Err(evidence("key-binding JWT typ is not kb+jwt"));
	}
	if !matches!(kb_header.alg, Algorithm::ES256 | Algorithm::EdDSA) {
		return Err(evidence(format!(
			"key-binding algorithm {:?}",
			kb_header.alg
		)));
	}
	let holder_key = DecodingKey::from_jwk(&holder).map_err(|e| evidence(e.to_string()))?;
	let mut kv = Validation::new(kb_header.alg);
	kv.validate_exp = false;
	kv.validate_nbf = false;
	kv.validate_aud = false;
	kv.required_spec_claims.clear();
	let kb: Value = jsonwebtoken::decode(kb_jwt, &holder_key, &kv)
		.map_err(|_| evidence("key-binding JWT is not signed by the credential's holder key"))?
		.claims;
	if str_of(&kb, "aud") != Some(audience) {
		return Err(unbound("key-binding JWT names another verifier"));
	}
	if str_of(&kb, "nonce") != Some(nonce) {
		return Err(unbound("key-binding JWT nonce is not this approval's"));
	}
	let signed_part = &presentation[..presentation.len() - kb_jwt.len()];
	let sd_hash = haps_hash::sha256_prefixed(signed_part.as_bytes());
	if str_of(&kb, "sd_hash") != sd_hash.strip_prefix("sha256:") {
		return Err(evidence("key-binding JWT does not cover these disclosures"));
	}
	let kb_iat = kb
		.get("iat")
		.and_then(Value::as_u64)
		.ok_or_else(|| evidence("key-binding JWT has no iat"))?;
	Ok(VerifiedPresentation {
		issuer: iss.to_owned(),
		vct: vct.to_owned(),
		thumbprint,
		kb_iat,
		exp: payload.get("exp").and_then(Value::as_u64),
		nbf: payload.get("nbf").and_then(Value::as_u64),
		claims,
	})
}

fn decode_payload(jwt: &str) -> Result<Value, IdentityError> {
	let segment = jwt
		.split('.')
		.nth(1)
		.ok_or_else(|| malformed("not a JWT"))?;
	let bytes = URL_SAFE_NO_PAD
		.decode(segment)
		.map_err(|e| malformed(e.to_string()))?;
	serde_json::from_slice(&bytes).map_err(|e| malformed(e.to_string()))
}

/// RFC 9901 §7.1: replace each digest in `_sd` (objects) and `{"...": digest}` (arrays) with its
/// disclosure. Every presented disclosure must be used exactly once; a digest that matches none
/// is undisclosed and dropped.
fn apply_disclosures(payload: &Value, raw: &[&str]) -> Result<Map<String, Value>, IdentityError> {
	let mut by_digest: HashMap<String, Value> = HashMap::new();
	for d in raw {
		let digest = haps_hash::sha256_prefixed(d.as_bytes());
		let digest = digest.trim_start_matches("sha256:").to_owned();
		let bytes = URL_SAFE_NO_PAD
			.decode(d)
			.map_err(|_| malformed("disclosure is not base64url"))?;
		let parsed: Value =
			serde_json::from_slice(&bytes).map_err(|_| malformed("disclosure is not JSON"))?;
		if !parsed.is_array() {
			return Err(malformed("disclosure is not an array"));
		}
		if by_digest.insert(digest, parsed).is_some() {
			return Err(evidence("a disclosure is presented twice"));
		}
	}
	let mut used = 0usize;
	let processed = process(payload, &mut by_digest, &mut used, 0)?;
	if !by_digest.is_empty() {
		return Err(evidence("a disclosure matches no digest in the credential"));
	}
	let Value::Object(mut claims) = processed else {
		return Err(malformed("credential payload is not an object"));
	};
	claims.remove("_sd_alg");
	Ok(claims)
}

fn process(
	v: &Value,
	pending: &mut HashMap<String, Value>,
	used: &mut usize,
	depth: usize,
) -> Result<Value, IdentityError> {
	if depth > 16 {
		return Err(malformed("credential nests too deeply"));
	}
	match v {
		Value::Object(map) => {
			let mut out = Map::new();
			for (k, val) in map {
				if k == "_sd" {
					continue;
				}
				out.insert(k.clone(), process(val, pending, used, depth + 1)?);
			}
			if let Some(digests) = map.get("_sd") {
				let digests = digests
					.as_array()
					.ok_or_else(|| malformed("_sd is not an array"))?;
				for d in digests {
					let d = d
						.as_str()
						.ok_or_else(|| malformed("_sd digest is not a string"))?;
					let Some(disclosure) = pending.remove(d) else {
						continue;
					};
					let [_, Value::String(name), value] =
						disclosure.as_array().map(Vec::as_slice).unwrap_or(&[])
					else {
						return Err(malformed("object disclosure is not [salt, name, value]"));
					};
					if name == "_sd" || name == "..." || out.contains_key(name) {
						return Err(evidence(format!("disclosure for {name} collides")));
					}
					*used += 1;
					out.insert(name.clone(), process(value, pending, used, depth + 1)?);
				}
			}
			Ok(Value::Object(out))
		},
		Value::Array(items) => {
			let mut out = Vec::new();
			for item in items {
				if let Some(d) = item
					.as_object()
					.filter(|o| o.len() == 1)
					.and_then(|o| o.get("..."))
				{
					let d = d
						.as_str()
						.ok_or_else(|| malformed("array digest is not a string"))?;
					let Some(disclosure) = pending.remove(d) else {
						continue;
					};
					let [_, value] = disclosure.as_array().map(Vec::as_slice).unwrap_or(&[]) else {
						return Err(malformed("array disclosure is not [salt, value]"));
					};
					*used += 1;
					out.push(process(value, pending, used, depth + 1)?);
				} else {
					out.push(process(item, pending, used, depth + 1)?);
				}
			}
			Ok(Value::Array(out))
		},
		other => Ok(other.clone()),
	}
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url): the required members in lexicographic order.
pub fn thumbprint(jwk: &Value) -> Result<String, IdentityError> {
	let member = |k: &str| {
		str_of(jwk, k)
			.map(str::to_owned)
			.ok_or_else(|| evidence(format!("cnf.jwk has no {k}")))
	};
	let canonical = match str_of(jwk, "kty") {
		Some("EC") => serde_json::json!({
			"crv": member("crv")?, "kty": "EC", "x": member("x")?, "y": member("y")?,
		}),
		Some("OKP") => serde_json::json!({"crv": member("crv")?, "kty": "OKP", "x": member("x")?}),
		Some("RSA") => serde_json::json!({"e": member("e")?, "kty": "RSA", "n": member("n")?}),
		_ => return Err(evidence("cnf.jwk has an unsupported kty")),
	};
	// serde_json orders object keys, and these hold only short ASCII strings, so this is the
	// RFC 7638 serialization.
	let bytes = serde_json::to_vec(&canonical).map_err(|e| evidence(e.to_string()))?;
	Ok(
		haps_hash::sha256_prefixed(&bytes)
			.trim_start_matches("sha256:")
			.to_owned(),
	)
}

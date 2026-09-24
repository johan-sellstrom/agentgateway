//! HAPS guard: an agentgateway `mcpGuardrails` processor that requires a HAPS Consent
//! Credential (HAPS-CC) for configured MCP tools, and binds it to the exact call.
//!
//! Experimental and partial; not production-ready. The guard acts as the HAPS relying party
//! for `tools/call`. For a gated tool it requires three values in `params._meta`:
//!
//! - `haps/credential` — the HAPS-CC as a compact JWS;
//! - `haps/actionIntent` — the AI-INTENT the human approved;
//! - `haps/signingView` — the Signing View they were shown.
//!
//! The binding that a gateway alone cannot provide is the per-argument one: the approved
//! intent's `action.parameters` must canonicalise byte-for-byte to the call's `arguments`.
//! Change one argument after approval and the call is rejected.
//!
//! What this implements of `conformance-v0.4.md`, stated narrowly:
//!
//! | Requirement | Status |
//! | --- | --- |
//! | RP-CORE-01 signature, issuer trust | EdDSA or ES256 against a configured JWKS and issuer allowlist |
//! | RP-CORE-02 audience | exact match |
//! | RP-CORE-03 `exp`/`iat`/`nbf` with skew | against an injected clock |
//! | RP-CORE-04 `intent_hash` | recomputed with `haps-canon` / `haps-hash` |
//! | RP-CORE-04a fractional numbers | rejected by the strict parser, for intent and arguments |
//! | RP-CORE-05 `presentation_hash` | hash match only; whether the view faithfully renders the intent is the provider's responsibility and is not checked here |
//! | RP-CORE-06 PoHP level | minimum level enforced; `providerCertification` required but **not** validated against any certifier |
//! | RP-CORE-07 one-time `jti` | in-memory, atomic within one process, **not** shared across replicas |
//! | RP-CORE-08 envelope constraints | not interpreted; exact argument binding is stricter, so it can never authorise a value outside an envelope, but rejects in-envelope variations |
//! | RP-CORE-09 challenge mode | not implemented; agent-initiated mode only |
//! | RP-CORE-10 replay retention | until `exp + skew` |

pub mod server;

/// Re-exported so a caller computing `intent_hash` or `presentation_hash` uses the same
/// verified crates the guard checks against, rather than a second implementation.
pub use {haps_canon, haps_hash};

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use haps_canon::{ParseError, Value as Canon};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::value::RawValue;

/// `_meta` keys the guard reads, and strips before the call is forwarded upstream.
pub const META_CREDENTIAL: &str = "haps/credential";
pub const META_ACTION_INTENT: &str = "haps/actionIntent";
pub const META_SIGNING_VIEW: &str = "haps/signingView";
const HAPS_META_KEYS: [&str; 3] = [META_CREDENTIAL, META_ACTION_INTENT, META_SIGNING_VIEW];

/// A PoHP assurance level, `HAPS-PoHP-1` (weakest) to `HAPS-PoHP-4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PohpLevel(u8);

impl PohpLevel {
	pub fn parse(s: &str) -> Option<Self> {
		let n: u8 = s.strip_prefix("HAPS-PoHP-")?.parse().ok()?;
		(1..=4).contains(&n).then_some(Self(n))
	}
}

impl fmt::Display for PohpLevel {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "HAPS-PoHP-{}", self.0)
	}
}

/// Policy for one gated tool.
#[derive(Clone, Debug)]
pub struct ToolPolicy {
	/// The `action.type` an approved intent must carry to authorise this tool.
	pub action_type: String,
	pub min_level: PohpLevel,
}

/// Everything the guard is configured with.
pub struct GuardConfig {
	pub tools: HashMap<String, ToolPolicy>,
	pub keys: JwkSet,
	pub issuers: Vec<String>,
	pub audience: String,
	pub elicitation_url: String,
	pub clock_skew_secs: u64,
}

/// Why a presented approval was refused. Each maps to the requirement it enforces.
#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
	MalformedParams(String),
	/// RP-CORE-04a, applied to the call's arguments.
	MalformedArguments(ParseError),
	/// RP-CORE-04a, applied to the AI-INTENT or Signing View.
	MalformedIntent(String),
	/// RP-CORE-01.
	UnsupportedAlgorithm(String),
	UnknownKey,
	BadSignature,
	MalformedCredential(String),
	UntrustedIssuer(String),
	/// RP-CORE-02.
	WrongAudience,
	/// RP-CORE-03.
	NotYetValid,
	IssuedInFuture,
	/// RP-CORE-04.
	IntentHashMismatch,
	/// RP-CORE-05.
	PresentationHashMismatch,
	/// The approved action is not this tool's action.
	WrongActionType {
		expected: String,
	},
	/// The approved parameters are not the arguments of this call.
	ArgumentsDoNotMatchApproval,
	/// RP-CORE-06.
	AssuranceTooLow {
		required: PohpLevel,
		presented: String,
	},
	/// RP-CORE-07.
	Replayed,
}

impl fmt::Display for Denial {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Denial::MalformedParams(e) => write!(f, "tool call parameters are malformed: {e}"),
			Denial::MalformedArguments(e) => write!(
				f,
				"tool arguments cannot be bound to an approval ({e:?}); HAPS admits integers only, so amounts must be strings"
			),
			Denial::MalformedIntent(e) => write!(f, "approved intent or signing view is malformed: {e}"),
			Denial::UnsupportedAlgorithm(a) => write!(f, "credential algorithm {a} is not accepted"),
			Denial::UnknownKey => write!(f, "credential is signed by an unknown key"),
			Denial::BadSignature => write!(f, "credential signature is invalid"),
			Denial::MalformedCredential(e) => write!(f, "credential is malformed: {e}"),
			Denial::UntrustedIssuer(i) => write!(f, "credential issuer {i} is not trusted"),
			Denial::WrongAudience => write!(f, "credential was issued for a different audience"),
			Denial::NotYetValid => write!(f, "credential is not yet valid"),
			Denial::IssuedInFuture => write!(f, "credential was issued in the future"),
			Denial::IntentHashMismatch => write!(f, "credential does not cover the presented intent"),
			Denial::PresentationHashMismatch => {
				write!(f, "credential does not cover the presented signing view")
			},
			Denial::WrongActionType { expected } => {
				write!(
					f,
					"approval is for a different action; this tool requires {expected}"
				)
			},
			Denial::ArgumentsDoNotMatchApproval => write!(
				f,
				"tool arguments differ from the approved action; request a new approval for this call"
			),
			Denial::AssuranceTooLow {
				required,
				presented,
			} => write!(
				f,
				"approval assurance {presented} is below the required {required}"
			),
			Denial::Replayed => write!(f, "this approval has already been used"),
		}
	}
}

/// What to do with one MCP request.
#[derive(Debug)]
pub enum Decision {
	/// Not a gated call: forward it untouched.
	NotGated,
	/// Approved. Forward `params`, from which the HAPS `_meta` keys have been removed.
	Approved { params: Vec<u8>, audit: Audit },
	/// No usable approval: ask the host to send the human to the Presence Provider.
	ElicitationRequired {
		reason: String,
		elicitation: serde_json::Value,
	},
	/// A presented approval failed a check.
	Denied(Denial),
}

/// What an approved call carried, for audit and downstream policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
	pub jti: String,
	pub issuer: String,
	pub level: String,
	pub action_type: String,
}

pub struct Guard {
	config: GuardConfig,
	replay: ReplayStore,
}

impl Guard {
	pub fn new(config: GuardConfig) -> Self {
		Self {
			config,
			replay: ReplayStore::default(),
		}
	}

	/// Decide one request. `now` is seconds since the Unix epoch.
	pub fn check(&self, method: &str, raw_params: Option<&[u8]>, now: u64) -> Decision {
		if method != "tools/call" {
			return Decision::NotGated;
		}
		let Some(raw) = raw_params else {
			return Decision::Denied(Denial::MalformedParams("tools/call without params".into()));
		};
		// The envelope is parsed leniently: only the arguments and the approval need to be
		// strict, and a float elsewhere in `_meta` must not make the request unreadable.
		let call: CallParams = match serde_json::from_slice(raw) {
			Ok(c) => c,
			Err(e) => return Decision::Denied(Denial::MalformedParams(e.to_string())),
		};
		let Some(policy) = self.config.tools.get(&call.name) else {
			return Decision::NotGated;
		};
		// RP-CORE-04a on the call itself. A call that cannot be canonicalised can never be
		// bound to an approval, so there is no point eliciting one.
		let arguments = match call.arguments {
			Some(a) => match haps_canon::parse(a.get()) {
				Ok(v) => v,
				Err(e) => return Decision::Denied(Denial::MalformedArguments(e)),
			},
			None => Canon::Object(Vec::new()),
		};
		let meta = call.meta.unwrap_or_default();
		let (Some(credential), Some(intent), Some(view)) =
			(meta.credential, meta.action_intent, meta.signing_view)
		else {
			return self.elicit(&call.name, &arguments, "approval required for this call");
		};
		match self.verify(
			policy,
			&credential,
			intent.get(),
			view.get(),
			&arguments,
			now,
		) {
			Ok(audit) => match strip_haps_meta(raw) {
				Ok(params) => Decision::Approved { params, audit },
				Err(e) => Decision::Denied(Denial::MalformedParams(e)),
			},
			Err(Verdict::Expired) => self.elicit(&call.name, &arguments, "approval expired"),
			Err(Verdict::Deny(d)) => Decision::Denied(d),
		}
	}

	fn verify(
		&self,
		policy: &ToolPolicy,
		credential: &str,
		intent_raw: &str,
		view_raw: &str,
		arguments: &Canon,
		now: u64,
	) -> Result<Audit, Verdict> {
		let claims = self.verify_signature(credential)?;
		let skew = self.config.clock_skew_secs;

		// RP-CORE-03. An expired approval is not an attack, so it is re-elicited, not denied.
		if now > claims.exp.saturating_add(skew) {
			return Err(Verdict::Expired);
		}
		if claims.nbf.is_some_and(|nbf| now.saturating_add(skew) < nbf) {
			return Err(Verdict::Deny(Denial::NotYetValid));
		}
		if claims.iat > now.saturating_add(skew) {
			return Err(Verdict::Deny(Denial::IssuedInFuture));
		}
		// RP-CORE-02.
		if !claims.aud.contains(&self.config.audience) {
			return Err(Verdict::Deny(Denial::WrongAudience));
		}
		// RP-CORE-04 and 04a.
		let intent = haps_canon::parse(intent_raw)
			.map_err(|e| Verdict::Deny(Denial::MalformedIntent(format!("intent: {e:?}"))))?;
		if haps_hash::hash_value(&intent) != claims.intent_hash {
			return Err(Verdict::Deny(Denial::IntentHashMismatch));
		}
		// RP-CORE-05: the hash only. Faithful rendering is the provider's to establish.
		let view = haps_canon::parse(view_raw)
			.map_err(|e| Verdict::Deny(Denial::MalformedIntent(format!("signing view: {e:?}"))))?;
		if haps_hash::hash_value(&view) != claims.presentation_hash {
			return Err(Verdict::Deny(Denial::PresentationHashMismatch));
		}
		// The binding a gateway cannot supply on its own.
		let action = member(&intent, "action");
		if action.and_then(|a| member(a, "type"))
			!= Some(&Canon::Str(policy.action_type.as_bytes().to_vec()))
		{
			return Err(Verdict::Deny(Denial::WrongActionType {
				expected: policy.action_type.clone(),
			}));
		}
		let empty = Canon::Object(Vec::new());
		let approved = action
			.and_then(|a| member(a, "parameters"))
			.unwrap_or(&empty);
		if haps_canon::canonicalize(approved) != haps_canon::canonicalize(arguments) {
			return Err(Verdict::Deny(Denial::ArgumentsDoNotMatchApproval));
		}
		// RP-CORE-06: the level only; certification is required by the claims type but
		// not validated, since there is no agreed certifier registry to validate against.
		let presented = PohpLevel::parse(&claims.assurance.level);
		if presented.is_none_or(|l| l < policy.min_level) {
			return Err(Verdict::Deny(Denial::AssuranceTooLow {
				required: policy.min_level,
				presented: claims.assurance.level.clone(),
			}));
		}
		// RP-CORE-07 and 10, deliberately last: a credential that fails any other check must
		// not consume its `jti`, or tampered replays could burn a legitimate approval.
		if !self
			.replay
			.consume(&claims.jti, claims.exp.saturating_add(skew), now)
		{
			return Err(Verdict::Deny(Denial::Replayed));
		}
		Ok(Audit {
			jti: claims.jti,
			issuer: claims.issuer,
			level: claims.assurance.level,
			action_type: policy.action_type.clone(),
		})
	}

	/// RP-CORE-01: signature, algorithm and issuer. Every other claim is checked in `verify`
	/// against the injected clock, so jsonwebtoken's own time and audience checks are off.
	fn verify_signature(&self, credential: &str) -> Result<Claims, Verdict> {
		let deny = |d| Verdict::Deny(d);
		let header = jsonwebtoken::decode_header(credential)
			.map_err(|e| deny(Denial::MalformedCredential(e.to_string())))?;
		if !matches!(header.alg, Algorithm::EdDSA | Algorithm::ES256) {
			return Err(deny(Denial::UnsupportedAlgorithm(format!(
				"{:?}",
				header.alg
			))));
		}
		let kid = header.kid.ok_or(deny(Denial::UnknownKey))?;
		let jwk = self
			.config
			.keys
			.find(&kid)
			.ok_or(deny(Denial::UnknownKey))?;
		// Defence against algorithm confusion: a key that names its algorithm must match.
		if let Some(key_alg) = jwk.common.key_algorithm
			&& format!("{key_alg:?}") != format!("{:?}", header.alg)
		{
			return Err(deny(Denial::UnsupportedAlgorithm(format!(
				"{:?}",
				header.alg
			))));
		}
		let key = DecodingKey::from_jwk(jwk).map_err(|_| deny(Denial::UnknownKey))?;
		let mut validation = Validation::new(header.alg);
		validation.validate_exp = false;
		validation.validate_nbf = false;
		validation.validate_aud = false;
		validation.required_spec_claims.clear();
		let claims = jsonwebtoken::decode::<Claims>(credential, &key, &validation)
			.map_err(|e| match e.kind() {
				jsonwebtoken::errors::ErrorKind::InvalidSignature => deny(Denial::BadSignature),
				_ => deny(Denial::MalformedCredential(e.to_string())),
			})?
			.claims;
		if !self.config.issuers.iter().any(|i| i == &claims.issuer) {
			return Err(deny(Denial::UntrustedIssuer(claims.issuer)));
		}
		Ok(claims)
	}

	/// `-32042`: send the human to the Presence Provider. `elicitationId` is a content
	/// address of the call, so it correlates the elicitation with exactly what needs
	/// approving; it is not a secret and this is not challenge mode.
	fn elicit(&self, tool: &str, arguments: &Canon, reason: &str) -> Decision {
		let call = Canon::Object(vec![
			(b"arguments".to_vec(), arguments.clone()),
			(b"name".to_vec(), Canon::Str(tool.as_bytes().to_vec())),
		]);
		let id = haps_hash::hash_value(&call);
		let url = format!("{}?elicitationId={}", self.config.elicitation_url, id);
		Decision::ElicitationRequired {
			reason: reason.to_owned(),
			elicitation: serde_json::json!({
				"elicitations": [{
					"mode": "url",
					"elicitationId": id,
					"url": url,
					"message": format!("Approve the call to {tool}"),
				}]
			}),
		}
	}
}

enum Verdict {
	Expired,
	Deny(Denial),
}

/// The member `key` of a canonical object. Parser output has no duplicate keys.
fn member<'a>(v: &'a Canon, key: &str) -> Option<&'a Canon> {
	match v {
		Canon::Object(members) => members
			.iter()
			.find(|(k, _)| k == key.as_bytes())
			.map(|(_, v)| v),
		_ => None,
	}
}

/// Remove the HAPS keys from `_meta` so the upstream never receives the credential. Other keys
/// -- progress tokens, trace context, a modern client's protocol envelope -- are kept.
///
/// This holds only on a gateway that honours a processor's `_meta` edits. Upstream
/// agentgateway, without the change in this fork, discards them and forwards the original
/// `_meta`, credential included -- and never shows it to the guard in the first place.
///
/// `_meta` is left present even when nothing remains. To the gateway an absent `_meta` in a
/// mutation means "not edited", which keeps the original -- credential included -- while an
/// empty one means "cleared". Arguments were already verified to contain only integers and
/// strings, which `serde_json` round-trips exactly.
fn strip_haps_meta(raw: &[u8]) -> Result<Vec<u8>, String> {
	let mut params: serde_json::Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
	if let Some(obj) = params.as_object_mut()
		&& let Some(serde_json::Value::Object(meta)) = obj.get_mut("_meta")
	{
		for k in HAPS_META_KEYS {
			meta.remove(k);
		}
	}
	serde_json::to_vec(&params).map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct CallParams<'a> {
	name: String,
	#[serde(borrow, default)]
	arguments: Option<&'a RawValue>,
	#[serde(borrow, default, rename = "_meta")]
	meta: Option<HapsMeta<'a>>,
}

#[derive(Deserialize, Default)]
struct HapsMeta<'a> {
	#[serde(rename = "haps/credential", default)]
	credential: Option<String>,
	#[serde(borrow, rename = "haps/actionIntent", default)]
	action_intent: Option<&'a RawValue>,
	#[serde(borrow, rename = "haps/signingView", default)]
	signing_view: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Claims {
	issuer: String,
	intent_hash: String,
	presentation_hash: String,
	aud: Audience,
	jti: String,
	iat: u64,
	#[serde(default)]
	nbf: Option<u64>,
	exp: u64,
	assurance: Assurance,
	/// Required by the schema. Present-only: see RP-CORE-06 above.
	#[serde(rename = "providerCertification")]
	#[allow(dead_code)]
	provider_certification: serde_json::Value,
}

#[derive(Deserialize)]
struct Assurance {
	level: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
	One(String),
	Many(Vec<String>),
}

impl Audience {
	fn contains(&self, aud: &str) -> bool {
		match self {
			Audience::One(a) => a == aud,
			Audience::Many(all) => all.iter().any(|a| a == aud),
		}
	}
}

/// Consumed `jti` values, each retained until its credential could no longer be accepted.
/// Atomic within one process only: replicas behind a load balancer each keep their own, so
/// a deployment with more than one needs a shared store.
#[derive(Default)]
struct ReplayStore {
	seen: Mutex<HashMap<String, u64>>,
}

impl ReplayStore {
	/// Consume `jti`, returning `false` if it was already consumed and is still retained.
	fn consume(&self, jti: &str, retain_until: u64, now: u64) -> bool {
		let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
		seen.retain(|_, until| *until >= now);
		if seen.contains_key(jti) {
			return false;
		}
		seen.insert(jti.to_owned(), retain_until);
		true
	}
}

#[cfg(test)]
mod tests;

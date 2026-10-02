//! HAPS guard: an agentgateway `mcpGuardrails` processor that requires a HAPS Consent
//! Credential (HAPS-CC) for configured MCP tools, and binds it to the exact call.
//!
//! Experimental; not production-ready. The guard acts as the HAPS relying party for
//! `tools/call`. For a gated tool it requires two values in `params._meta`, and accepts a third:
//!
//! - `haps/credential` — the HAPS-CC as a compact JWS;
//! - `haps/actionIntent` — the AI-INTENT the human approved;
//! - `haps/signingView` — optional: the Signing View they were shown. The guard derives the view
//!   from the intent itself; a supplied one must equal the derived one.
//!
//! The binding that a gateway alone cannot provide is the per-argument one: the approved
//! intent's `action.parameters` must canonicalise byte-for-byte to the call's `arguments`, or,
//! where the tool allows it and the intent carries an envelope, may differ only in the members
//! the envelope governs, and only within its bounds.
//!
//! What this implements of `conformance-v0.4.md`, stated narrowly:
//!
//! | Requirement | Status |
//! | --- | --- |
//! | RP-CORE-01 signature, issuer trust | EdDSA or ES256; keys scoped per issuer, so one provider cannot sign as another |
//! | RP-CORE-02 audience | exact match, on the credential and on the intent's `audience.id` |
//! | RP-CORE-03 `exp`/`iat`/`nbf` with skew | against an injected clock; plus per-tool max credential age (§12.3) and the intent's own `constraints.expiresAt` |
//! | RP-CORE-04 `intent_hash` | recomputed with `haps-canon` / `haps-hash` |
//! | RP-CORE-04a fractional numbers | rejected by the strict parser, for intent, view and arguments |
//! | RP-CORE-05 `presentation_hash` | recomputed from the Signing View the guard derives from the intent (see [`derive_signing_view`]) |
//! | RP-CORE-06 PoHP level and certification | minimum level; HAPS-PCC verified against trusted certifiers, see [`certification`] |
//! | RP-CORE-07 one-time `jti` | atomic consume; in-memory, or Redis shared across replicas; `oneTime`/`maxUses` honoured when the tool allows multi-use |
//! | RP-CORE-08 envelope constraints | enforced with a guard-defined vocabulary, see [`envelope`]; a member the guard cannot enforce is refused |
//! | RP-CORE-09 challenge mode | per tool: the guard issues the HAPS-CHAL, optionally signed (`rpProof`), and consumes `challengeId` atomically with the `jti` |
//! | RP-CORE-10 replay retention | until `exp + skew` |
//! | FACTOR-RP-01..05 | accepted-method list; agent-accessible factors refused from PoHP-2 or on request; method in audit |
//!
//! Not implemented: identity binding (the separate HAPS-RP-ID-0.4 class), and the `vc+json`
//! credential format. Where HAPS v0.4 leaves a choice open — the Signing View derivation, the
//! envelope vocabulary, the PCC wire form — the guard's choice is documented where it is made,
//! and is an interpretation, not specification text.
//!
//! A passing check is evidence about data, not about the world: a matching `presentation_hash`
//! does not show what was rendered, and a valid certification does not reproduce the
//! evaluation behind it (`haps-v0.4.0.md` §7.2, §16).

pub mod certification;
pub mod envelope;
mod jws;
pub mod server;
pub mod store;

/// Re-exported so a caller computing `intent_hash` or `presentation_hash` uses the same
/// verified crates the guard checks against, rather than a second implementation.
pub use {haps_canon, haps_hash};

use std::collections::HashMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat};
use haps_canon::{ParseError, Value as Canon};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::certification::{CertificationConfig, CertificationError, ProviderCertification};
use crate::envelope::{EnvelopeError, EnvelopeRule};
use crate::jws::JwsError;
use crate::store::{ChallengeRecord, Consume, ConsumeOutcome, StateStore};

/// `_meta` keys the guard reads, and strips before the call is forwarded upstream.
pub const META_CREDENTIAL: &str = "haps/credential";
pub const META_ACTION_INTENT: &str = "haps/actionIntent";
pub const META_SIGNING_VIEW: &str = "haps/signingView";
const HAPS_META_KEYS: [&str; 3] = [META_CREDENTIAL, META_ACTION_INTENT, META_SIGNING_VIEW];

/// Factors registered as agent-accessible (`factors-v0.1.md` §3): an agent with the user's
/// mailbox, device or session can complete them.
pub const AGENT_ACCESSIBLE_METHODS: [&str; 3] = ["otp.delivered", "push.approval", "acknowledge"];
/// Registered factors whose agent resistance is conditional on the implementation. They are
/// eligible where agent resistance is required; whether a provider's implementation actually
/// resists is what its certification for the factor is meant to attest (RP-CORE-06).
pub const CONDITIONAL_METHODS: [&str; 6] = [
	"hardware.actuated",
	"smartcard.signature",
	"passkey.biometric",
	"webauthn.uv",
	"liveness.passive",
	"liveness.active",
];

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

/// How the call's arguments must relate to the approved `action.parameters`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentBinding {
	/// Byte-for-byte equal after canonicalisation.
	Exact,
	/// Equal except in the members the intent's envelope governs, which must be within its
	/// bounds. Without an envelope this is `Exact`.
	Envelope,
}

/// Display text for the AI-INTENT the guard builds in challenge mode. `{tool}`, `{agent}`,
/// `{audience}` and `{arguments}` (canonical JSON) are substituted.
#[derive(Clone, Debug)]
pub struct ChallengeDisplay {
	pub title: String,
	pub summary: String,
}

impl Default for ChallengeDisplay {
	fn default() -> Self {
		Self {
			title: "Approve {tool}".into(),
			summary: "{agent} asks to call {tool} at {audience} with {arguments}".into(),
		}
	}
}

/// Policy for one gated tool.
#[derive(Clone, Debug)]
pub struct ToolPolicy {
	/// The `action.type` an approved intent must carry to authorise this tool.
	pub action_type: String,
	pub min_level: PohpLevel,
	/// FACTOR-RP-01: if set, the only `assurance.method` values accepted.
	pub accepted_methods: Option<Vec<String>>,
	/// FACTOR-RP-03: refuse agent-accessible factors. Always on from PoHP-2, where property H
	/// is required; this turns it on below that too.
	pub require_agent_resistant: bool,
	pub binding: ArgumentBinding,
	/// RP-CORE-08: the envelope members this tool can enforce.
	pub envelope_rules: HashMap<String, EnvelopeRule>,
	/// §12.3: reject a credential older than this, relative to `iat`.
	pub max_credential_age_secs: Option<u64>,
	/// Honour an intent's `oneTime: false` and `maxUses`. Off, every approval is single use.
	pub allow_multi_use: bool,
	/// RP-CORE-09: accept only credentials answering a challenge this guard issued.
	pub challenge_mode: bool,
	pub display: ChallengeDisplay,
}

impl ToolPolicy {
	/// The strictest policy: exact binding, single use, no challenge mode.
	pub fn new(action_type: impl Into<String>, min_level: PohpLevel) -> Self {
		Self {
			action_type: action_type.into(),
			min_level,
			accepted_methods: None,
			require_agent_resistant: false,
			binding: ArgumentBinding::Exact,
			envelope_rules: HashMap::new(),
			max_credential_age_secs: None,
			allow_multi_use: false,
			challenge_mode: false,
			display: ChallengeDisplay::default(),
		}
	}

	fn agent_resistance_required(&self) -> bool {
		self.require_agent_resistant || self.min_level >= PohpLevel(2)
	}
}

/// An `{id, name}` pair, as AI-INTENT names its audience and agent.
#[derive(Clone, Debug)]
pub struct Party {
	pub id: String,
	pub name: String,
}

/// The relying party's key for signing challenges (`rpProof`). EdDSA.
pub struct RpSigner {
	pub kid: String,
	pub key: EncodingKey,
}

/// Everything the guard is configured with.
pub struct GuardConfig {
	pub tools: HashMap<String, ToolPolicy>,
	/// Trusted Presence Providers: issuer → its keys.
	pub issuers: HashMap<String, JwkSet>,
	/// This relying party. `id` is the `aud` an approval must carry.
	pub audience: Party,
	/// The agent named in intents the guard builds in challenge mode.
	pub agent: Party,
	/// Presence Provider URL the host is sent to when approval is needed.
	pub elicitation_url: String,
	pub clock_skew_secs: u64,
	pub certification: CertificationConfig,
	/// Unregistered `assurance.method` values policy treats as eligible where agent resistance
	/// is required (FACTOR-RP-02: unrecognised methods are agent-accessible unless policy says
	/// otherwise).
	pub agent_resistant_methods: Vec<String>,
	pub challenge_ttl_secs: u64,
	pub rp_signer: Option<RpSigner>,
}

/// Why a presented approval was refused. Each maps to the requirement it enforces.
#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
	MalformedParams(String),
	/// RP-CORE-04a, applied to the call's arguments.
	MalformedArguments(ParseError),
	/// RP-CORE-04a and schema checks, applied to the AI-INTENT or Signing View.
	MalformedIntent(String),
	/// RP-CORE-01.
	UnsupportedAlgorithm(String),
	UnknownKey,
	BadSignature,
	MalformedCredential(String),
	UntrustedIssuer(String),
	/// RP-CORE-02.
	WrongAudience,
	/// The approved intent names another relying party.
	IntentWrongAudience,
	/// RP-CORE-03.
	NotYetValid,
	IssuedInFuture,
	/// RP-CORE-04.
	IntentHashMismatch,
	/// RP-CORE-05.
	PresentationHashMismatch,
	/// The supplied Signing View is not the one derived from the approved intent.
	SigningViewNotDerived,
	/// The approved action is not this tool's action.
	WrongActionType {
		expected: String,
	},
	/// The approved parameters are not the arguments of this call.
	ArgumentsDoNotMatchApproval,
	/// RP-CORE-08.
	Envelope(EnvelopeError),
	/// RP-CORE-06.
	AssuranceTooLow {
		required: PohpLevel,
		presented: String,
	},
	Certification(CertificationError),
	/// FACTOR-RP-01.
	FactorNotAccepted(String),
	/// FACTOR-RP-02/03.
	AgentAccessibleFactor(String),
	/// RP-CORE-09.
	ChallengeUnknown,
	ChallengeMismatch,
	/// RP-CORE-07.
	Replayed,
	/// Challenge mode could not build an intent for this call.
	ChallengeUnbuildable(String),
	/// The state store failed. The guard fails closed.
	Unavailable(String),
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
			Denial::IntentWrongAudience => {
				write!(
					f,
					"approved intent is addressed to a different relying party"
				)
			},
			Denial::NotYetValid => write!(f, "credential is not yet valid"),
			Denial::IssuedInFuture => write!(f, "credential was issued in the future"),
			Denial::IntentHashMismatch => write!(f, "credential does not cover the presented intent"),
			Denial::PresentationHashMismatch => {
				write!(
					f,
					"credential does not cover the signing view derived from the intent"
				)
			},
			Denial::SigningViewNotDerived => write!(
				f,
				"the presented signing view is not the one derived from the approved intent"
			),
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
			Denial::Envelope(e) => write!(f, "{e}"),
			Denial::AssuranceTooLow {
				required,
				presented,
			} => write!(
				f,
				"approval assurance {presented} is below the required {required}"
			),
			Denial::Certification(e) => write!(f, "{e}"),
			Denial::FactorNotAccepted(m) => {
				write!(f, "approval factor {m} is not accepted for this tool")
			},
			Denial::AgentAccessibleFactor(m) => write!(
				f,
				"approval factor {m} can be completed by an agent, and this tool requires a human"
			),
			Denial::ChallengeUnknown => write!(
				f,
				"the approval answers an unknown, spent or expired challenge; request a new approval"
			),
			Denial::ChallengeMismatch => {
				write!(
					f,
					"the approval's challenge was issued for a different call"
				)
			},
			Denial::Replayed => write!(f, "this approval has already been used"),
			Denial::ChallengeUnbuildable(e) => {
				write!(f, "cannot request an approval for this call: {e}")
			},
			Denial::Unavailable(e) => write!(f, "approval cannot be checked right now: {e}"),
		}
	}
}

impl From<JwsError> for Denial {
	fn from(e: JwsError) -> Self {
		match e {
			JwsError::UnsupportedAlgorithm(a) => Denial::UnsupportedAlgorithm(a),
			JwsError::UnknownKey => Denial::UnknownKey,
			JwsError::BadSignature => Denial::BadSignature,
			JwsError::Malformed(m) => Denial::MalformedCredential(m),
			JwsError::UntrustedIssuer(i) => Denial::UntrustedIssuer(i),
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

/// What an approved call carried, for audit and downstream policy (FACTOR-RP-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
	pub jti: String,
	pub issuer: String,
	pub level: String,
	pub method: String,
	pub action_type: String,
	pub certifier: String,
	pub provider_id: String,
	pub evaluation: String,
	pub challenge_id: Option<String>,
	/// The envelope members the call's arguments were allowed to vary in; empty for an exact
	/// match.
	pub varied_within_envelope: Vec<String>,
}

pub struct Guard {
	config: GuardConfig,
	store: StateStore,
}

impl Guard {
	pub fn new(config: GuardConfig, store: StateStore) -> Self {
		Self { config, store }
	}

	/// Decide one request. `now` is seconds since the Unix epoch.
	pub async fn check(&self, method: &str, raw_params: Option<&[u8]>, now: u64) -> Decision {
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
		let (Some(credential), Some(intent)) = (meta.credential, meta.action_intent) else {
			return self
				.elicit(
					&call.name,
					policy,
					&arguments,
					"approval required for this call",
					now,
				)
				.await;
		};
		let presented = Presented {
			tool: &call.name,
			credential: &credential,
			intent: intent.get(),
			view: meta.signing_view.map(RawValue::get),
			arguments: &arguments,
		};
		match self.verify(policy, presented, now).await {
			Ok(audit) => match strip_haps_meta(raw) {
				Ok(params) => Decision::Approved { params, audit },
				Err(e) => Decision::Denied(Denial::MalformedParams(e)),
			},
			Err(Verdict::Elicit(reason)) => {
				self
					.elicit(&call.name, policy, &arguments, reason, now)
					.await
			},
			Err(Verdict::Deny(d)) => Decision::Denied(d),
		}
	}

	async fn verify(
		&self,
		policy: &ToolPolicy,
		p: Presented<'_>,
		now: u64,
	) -> Result<Audit, Verdict> {
		let deny = Verdict::Deny;
		// RP-CORE-01.
		let claims = jws::verify::<Claims>(p.credential, &self.config.issuers, |c| &c.issuer)
			.map_err(|e| deny(e.into()))?
			.claims;
		let skew = self.config.clock_skew_secs;

		// RP-CORE-03. A lapsed approval is not an attack, so it is re-elicited, not denied.
		if now > claims.exp.saturating_add(skew) {
			return Err(Verdict::Elicit("approval expired"));
		}
		if claims.nbf.is_some_and(|nbf| now.saturating_add(skew) < nbf) {
			return Err(deny(Denial::NotYetValid));
		}
		if claims.iat > now.saturating_add(skew) {
			return Err(deny(Denial::IssuedInFuture));
		}
		if let Some(max) = policy.max_credential_age_secs
			&& now > claims.iat.saturating_add(max).saturating_add(skew)
		{
			return Err(Verdict::Elicit("approval is older than this tool accepts"));
		}
		// RP-CORE-02.
		if !claims.aud.contains(&self.config.audience.id) {
			return Err(deny(Denial::WrongAudience));
		}

		// RP-CORE-04 and 04a.
		let intent = haps_canon::parse(p.intent)
			.map_err(|e| deny(Denial::MalformedIntent(format!("intent: {e:?}"))))?;
		if haps_hash::hash_value(&intent) != claims.intent_hash {
			return Err(deny(Denial::IntentHashMismatch));
		}
		let fields = IntentFields::read(&intent).map_err(|e| deny(Denial::MalformedIntent(e)))?;
		if fields.audience_id != self.config.audience.id.as_bytes() {
			return Err(deny(Denial::IntentWrongAudience));
		}
		if now > fields.expires_at.saturating_add(skew as i64).max(0) as u64 {
			return Err(Verdict::Elicit("approved intent expired"));
		}
		if fields.action_type != policy.action_type.as_bytes() {
			return Err(deny(Denial::WrongActionType {
				expected: policy.action_type.clone(),
			}));
		}

		// RP-CORE-05: against the view derived from the intent, not merely the one presented.
		let derived = derive_signing_view(&intent);
		let derived_hash = haps_hash::hash_value(&derived);
		let supplied = p
			.view
			.map(|v| {
				haps_canon::parse(v)
					.map_err(|e| deny(Denial::MalformedIntent(format!("signing view: {e:?}"))))
			})
			.transpose()?;
		if derived_hash != claims.presentation_hash {
			// Say which: a view that was approved but not derived from the intent is a
			// different failure from a credential that covers neither.
			let approved_other_view = supplied
				.as_ref()
				.is_some_and(|v| haps_hash::hash_value(v) == claims.presentation_hash);
			return Err(deny(if approved_other_view {
				Denial::SigningViewNotDerived
			} else {
				Denial::PresentationHashMismatch
			}));
		}
		if supplied.is_some_and(|v| haps_canon::canonicalize(&v) != haps_canon::canonicalize(&derived))
		{
			return Err(deny(Denial::SigningViewNotDerived));
		}

		// RP-CORE-06: the level.
		let level = PohpLevel::parse(&claims.assurance.level);
		if level.is_none_or(|l| l < policy.min_level) {
			return Err(deny(Denial::AssuranceTooLow {
				required: policy.min_level,
				presented: claims.assurance.level.clone(),
			}));
		}
		// FACTOR-RP-01..03.
		let method = claims.assurance.method.as_str();
		if let Some(accepted) = &policy.accepted_methods
			&& !accepted.iter().any(|m| m == method)
		{
			return Err(deny(Denial::FactorNotAccepted(method.to_owned())));
		}
		if policy.agent_resistance_required() && !self.agent_resistant_eligible(method) {
			return Err(deny(Denial::AgentAccessibleFactor(method.to_owned())));
		}
		// RP-CORE-06 and FACTOR-RP-04: the certification behind the level and the factor.
		let certified = certification::validate(
			&self.config.certification,
			&claims.provider_certification,
			&claims.issuer,
			&claims.assurance.level,
			method,
			now,
			skew,
		)
		.map_err(|e| deny(Denial::Certification(e)))?;

		// The binding a gateway cannot supply on its own, and RP-CORE-08.
		let empty = Canon::Object(Vec::new());
		let approved = fields.parameters.unwrap_or(&empty);
		let governed = match fields.envelope {
			Some(env) => envelope::enforce(env, p.arguments, &policy.envelope_rules)
				.map_err(|e| deny(Denial::Envelope(e)))?,
			None => Vec::new(),
		};
		let varied = match policy.binding {
			ArgumentBinding::Exact => Vec::new(),
			ArgumentBinding::Envelope => governed,
		};
		if haps_canon::canonicalize(&envelope::without(approved, &varied))
			!= haps_canon::canonicalize(&envelope::without(p.arguments, &varied))
		{
			return Err(deny(Denial::ArgumentsDoNotMatchApproval));
		}

		// RP-CORE-09.
		match (&claims.challenge_id, policy.challenge_mode) {
			(None, true) => {
				return Err(Verdict::Elicit(
					"this tool accepts only approvals issued for a gateway challenge",
				));
			},
			(None, false) => {},
			(Some(id), _) => {
				let record = self
					.store
					.get_challenge(id, now)
					.await
					.map_err(|e| deny(Denial::Unavailable(e.to_string())))?
					.ok_or(deny(Denial::ChallengeUnknown))?;
				if record.tool != p.tool || record.intent_hash != claims.intent_hash {
					return Err(deny(Denial::ChallengeMismatch));
				}
			},
		}

		// RP-CORE-07 and 10, deliberately last: a credential that fails any other check must
		// not consume its `jti`, or tampered replays could burn a legitimate approval.
		let max_uses = if !policy.allow_multi_use || fields.one_time {
			Some(1)
		} else {
			fields.max_uses
		};
		let consume = Consume {
			jti: claims.jti.clone(),
			max_uses,
			retain_until: claims.exp.saturating_add(skew),
			challenge_id: claims.challenge_id.clone(),
		};
		match self.store.consume(&consume, now).await {
			Ok(ConsumeOutcome::Consumed) => {},
			Ok(ConsumeOutcome::Replayed) => return Err(deny(Denial::Replayed)),
			Ok(ConsumeOutcome::ChallengeGone) => return Err(deny(Denial::ChallengeUnknown)),
			Err(e) => return Err(deny(Denial::Unavailable(e.to_string()))),
		}

		Ok(Audit {
			jti: claims.jti,
			issuer: claims.issuer,
			level: claims.assurance.level,
			method: claims.assurance.method,
			action_type: policy.action_type.clone(),
			certifier: certified.certifier,
			provider_id: certified.provider_id,
			evaluation: certified.evaluation,
			challenge_id: claims.challenge_id,
			varied_within_envelope: varied.iter().map(ToString::to_string).collect(),
		})
	}

	fn agent_resistant_eligible(&self, method: &str) -> bool {
		if AGENT_ACCESSIBLE_METHODS.contains(&method) {
			return false;
		}
		CONDITIONAL_METHODS.contains(&method)
			|| self
				.config
				.agent_resistant_methods
				.iter()
				.any(|m| m == method)
	}

	/// `-32042`: send the human to the Presence Provider.
	async fn elicit(
		&self,
		tool: &str,
		policy: &ToolPolicy,
		arguments: &Canon,
		reason: &str,
		now: u64,
	) -> Decision {
		if policy.challenge_mode {
			return match self
				.issue_challenge(tool, policy, arguments, reason, now)
				.await
			{
				Ok(d) => d,
				Err(d) => Decision::Denied(d),
			};
		}
		// Agent-initiated mode. `elicitationId` is a content address of the call, so it
		// correlates the elicitation with exactly what needs approving; it is not a secret.
		let call = Canon::Object(vec![
			(b"arguments".to_vec(), arguments.clone()),
			(b"name".to_vec(), Canon::Str(tool.as_bytes().to_vec())),
		]);
		let id = haps_hash::hash_value(&call);
		let url = with_query(&self.config.elicitation_url, &[("elicitationId", &id)]);
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

	/// RP-CORE-09, issuing side (`haps-v0.4.0.md` §10): build the AI-INTENT for exactly this
	/// call, wrap it in a HAPS-CHAL, remember it, and send the human to approve it. The
	/// challenge travels to the Presence Provider in the URL, canonical and base64url-encoded,
	/// and in the error data for a host that wants to show it.
	async fn issue_challenge(
		&self,
		tool: &str,
		policy: &ToolPolicy,
		arguments: &Canon,
		reason: &str,
		now: u64,
	) -> Result<Decision, Denial> {
		let unbuildable = |e: &str| Denial::ChallengeUnbuildable(e.to_owned());
		let challenge_id = uuid::Uuid::new_v4().to_string();
		let expires_at = now.saturating_add(self.config.challenge_ttl_secs);
		let timestamp = |t: u64| {
			DateTime::from_timestamp(t as i64, 0)
				.map(|d| d.to_rfc3339_opts(SecondsFormat::Secs, true))
				.ok_or_else(|| unbuildable("clock out of range"))
		};
		let arguments_json = String::from_utf8(haps_canon::canonicalize(arguments))
			.map_err(|_| unbuildable("arguments are not UTF-8"))?;
		let fill = |template: &str| {
			template
				.replace("{tool}", tool)
				.replace("{agent}", &self.config.agent.name)
				.replace("{audience}", &self.config.audience.name)
				.replace("{arguments}", &arguments_json)
		};
		let (title, summary) = (fill(&policy.display.title), fill(&policy.display.summary));
		// The AI-INTENT schema's display limits. The full parameters are in the Signing View
		// whatever the summary says, so a call too large to summarise is refused rather than
		// summarised with something left out.
		if title.chars().count() > 120 {
			return Err(unbuildable("display title exceeds 120 characters"));
		}
		if summary.chars().count() > 600 {
			return Err(unbuildable(
				"display summary exceeds 600 characters; configure a shorter summary for this tool",
			));
		}
		let parameters: serde_json::Value =
			serde_json::from_str(&arguments_json).map_err(|e| unbuildable(&e.to_string()))?;
		let intent = serde_json::json!({
			"version": "0.4",
			"intentId": uuid::Uuid::new_v4().to_string(),
			"issuedAt": timestamp(now)?,
			"audience": {"id": self.config.audience.id, "name": self.config.audience.name},
			"agent": {"id": self.config.agent.id, "name": self.config.agent.name},
			"action": {"type": policy.action_type, "parameters": parameters},
			// The intent lapses with the challenge: the call it describes must happen while
			// the challenge is outstanding.
			"constraints": {"expiresAt": timestamp(expires_at)?, "oneTime": true},
			"display": {"language": "en", "title": title, "summary": summary},
		});
		let intent_hash = haps_hash::hash_value(&to_canon(&intent).map_err(|e| unbuildable(&e))?);

		let mut pohp = serde_json::json!({"minLevel": policy.min_level.to_string()});
		if let Some(max) = policy.max_credential_age_secs {
			pohp["maxCredentialAgeSeconds"] = max.into();
		}
		let mut challenge = serde_json::json!({
			"version": "0.4",
			"challengeId": challenge_id,
			"expiresAt": timestamp(expires_at)?,
			"requirements": {"pohp": pohp},
			"actionIntent": intent,
		});
		if let Some(signer) = &self.config.rp_signer {
			// A JWS whose payload is the challenge without `rpProof`. The Presence Provider
			// verifies it and compares the payload with the challenge it was given (§10).
			let mut header = Header::new(Algorithm::EdDSA);
			header.kid = Some(signer.kid.clone());
			let jws = jsonwebtoken::encode(&header, &challenge, &signer.key)
				.map_err(|e| unbuildable(&format!("signing the challenge: {e}")))?;
			challenge["rpProof"] = serde_json::json!({"alg": "EdDSA", "kid": signer.kid, "jws": jws});
		}

		self
			.store
			.put_challenge(
				&challenge_id,
				&ChallengeRecord {
					tool: tool.to_owned(),
					intent_hash,
					expires_at,
				},
				now,
			)
			.await
			.map_err(|e| Denial::Unavailable(e.to_string()))?;

		let encoded = URL_SAFE_NO_PAD.encode(haps_canon::canonicalize(
			&to_canon(&challenge).map_err(|e| unbuildable(&e))?,
		));
		let url = with_query(
			&self.config.elicitation_url,
			&[("challengeId", &challenge_id), ("challenge", &encoded)],
		);
		Ok(Decision::ElicitationRequired {
			reason: reason.to_owned(),
			elicitation: serde_json::json!({
				"elicitations": [{
					"mode": "url",
					"elicitationId": challenge_id,
					"url": url,
					"message": format!("Approve the call to {tool}"),
				}],
				"haps/challenge": challenge,
			}),
		})
	}
}

/// The Signing View the guard derives from an AI-INTENT (§7.1), for RP-CORE-05.
///
/// HAPS v0.4 requires the relying party to recompute `presentation_hash` from the view derived
/// from the intent, but defines no executable derivation, and its Generic Profile rules list the
/// view's contents without fixing its shape. The one executable reference is the published
/// VEC-01 pair, whose Signing View is the intent without `version`, `intentId` and `issuedAt`
/// — the members that identify the intent rather than describe the action. The guard uses that
/// rule for every intent, whatever its `profile`, because it knows no profile with another one.
/// A provider deriving its view differently produces credentials this guard refuses.
pub fn derive_signing_view(intent: &Canon) -> Canon {
	const NOT_DISPLAYED: [&[u8]; 3] = [b"version", b"intentId", b"issuedAt"];
	match intent {
		Canon::Object(members) => Canon::Object(
			members
				.iter()
				.filter(|(k, _)| !NOT_DISPLAYED.contains(&k.as_slice()))
				.cloned()
				.collect(),
		),
		other => other.clone(),
	}
}

enum Verdict {
	Elicit(&'static str),
	Deny(Denial),
}

struct Presented<'a> {
	tool: &'a str,
	credential: &'a str,
	intent: &'a str,
	view: Option<&'a str>,
	arguments: &'a Canon,
}

/// The members of an AI-INTENT the guard acts on, read from its strictly parsed form.
struct IntentFields<'a> {
	audience_id: &'a [u8],
	action_type: &'a [u8],
	parameters: Option<&'a Canon>,
	/// Unix seconds.
	expires_at: i64,
	one_time: bool,
	max_uses: Option<u32>,
	envelope: Option<&'a Canon>,
}

impl<'a> IntentFields<'a> {
	fn read(intent: &'a Canon) -> Result<Self, String> {
		let str_at = |path: &[&str]| -> Result<&'a [u8], String> {
			match at(intent, path) {
				Some(Canon::Str(s)) => Ok(s.as_slice()),
				_ => Err(format!("{} must be a string", path.join("."))),
			}
		};
		if str_at(&["version"])? != b"0.4" {
			return Err("version must be \"0.4\"".into());
		}
		let expires = std::str::from_utf8(str_at(&["constraints", "expiresAt"])?)
			.ok()
			.and_then(|s| DateTime::parse_from_rfc3339(s).ok())
			.ok_or("constraints.expiresAt must be an RFC 3339 date-time")?
			.timestamp();
		let one_time = match at(intent, &["constraints", "oneTime"]) {
			Some(Canon::Bool(b)) => *b,
			_ => return Err("constraints.oneTime must be a boolean".into()),
		};
		let max_uses = match at(intent, &["constraints", "maxUses"]) {
			None => None,
			Some(Canon::Int(n)) if *n >= 1 => Some(u32::try_from(*n).unwrap_or(u32::MAX)),
			Some(_) => return Err("constraints.maxUses must be a positive integer".into()),
		};
		let parameters = at(intent, &["action", "parameters"]);
		if parameters.is_some_and(|p| !matches!(p, Canon::Object(_))) {
			return Err("action.parameters must be an object".into());
		}
		Ok(Self {
			audience_id: str_at(&["audience", "id"])?,
			action_type: str_at(&["action", "type"])?,
			parameters,
			expires_at: expires,
			one_time,
			max_uses,
			envelope: at(intent, &["constraints", "envelope"]),
		})
	}
}

/// The value at `path` in a canonical object. Parser output has no duplicate keys.
fn at<'a>(mut v: &'a Canon, path: &[&str]) -> Option<&'a Canon> {
	for key in path {
		v = match v {
			Canon::Object(members) => members
				.iter()
				.find(|(k, _)| k == key.as_bytes())
				.map(|(_, v)| v)?,
			_ => return None,
		};
	}
	Some(v)
}

fn to_canon(v: &serde_json::Value) -> Result<Canon, String> {
	haps_canon::parse(&v.to_string()).map_err(|e| format!("{e:?}"))
}

/// `base` with query parameters appended. Values are base64url, UUIDs or `sha256:` hashes;
/// only `:` needs escaping.
fn with_query(base: &str, params: &[(&str, &str)]) -> String {
	let mut url = base.to_owned();
	for (i, (k, v)) in params.iter().enumerate() {
		let sep = if i == 0 && !base.contains('?') {
			'?'
		} else {
			'&'
		};
		url.push(sep);
		url.push_str(k);
		url.push('=');
		url.push_str(&v.replace(':', "%3A"));
	}
	url
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
	#[serde(rename = "providerCertification")]
	provider_certification: ProviderCertification,
	#[serde(rename = "challengeId", default)]
	challenge_id: Option<String>,
}

#[derive(Deserialize)]
struct Assurance {
	level: String,
	method: String,
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

#[cfg(test)]
mod tests;

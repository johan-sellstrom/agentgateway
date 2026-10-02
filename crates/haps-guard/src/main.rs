//! `haps-guard <config.yaml>`: serve the HAPS guard as an mcpGuardrails processor.
//!
//! Relative paths in the config are resolved against the config file's directory.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use haps_guard::certification::CertificationConfig;
use haps_guard::envelope::{EnvelopeRule, Pointer, RuleKind};
use haps_guard::identity::{
	CredentialIssuer, EudiTrust, GoogleTrust, IdentityPolicy, IdentityTrust, KeySource, Scheme,
};
use haps_guard::server::HapsGuardService;
use haps_guard::store::{RedisOptions, RedisTopology, StateStore};
use haps_guard::{
	ArgumentBinding, ChallengeDisplay, Guard, GuardConfig, Party, PohpLevel, RpSigner, SpendOn,
	ToolPolicy,
};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::JwkSet;
use protos::ext_mcp::ext_mcp_server::ExtMcpServer;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
	listen: SocketAddr,
	/// This relying party: `id` is the `aud` an approval must carry.
	audience: PartyConfig,
	/// The agent named in intents built in challenge mode.
	agent: PartyConfig,
	/// Trusted Presence Providers: issuer → JWKS file. Must not be empty.
	issuers: HashMap<String, PathBuf>,
	/// Presence Provider URL the host is sent to when approval is needed.
	elicitation_url: String,
	#[serde(default = "default_skew")]
	clock_skew_seconds: u64,
	#[serde(default = "default_challenge_ttl")]
	challenge_ttl_seconds: u64,
	/// Signs challenges (`rpProof`). Optional.
	#[serde(default)]
	rp_signing_key: Option<RpKeyConfig>,
	certification: CertificationFileConfig,
	/// Unregistered factor names to treat as agent-resistant where that is required.
	#[serde(default)]
	agent_resistant_methods: Vec<String>,
	#[serde(default)]
	state: StateConfig,
	/// Trust for identity evidence (HAPS-RP-ID-0.4).
	#[serde(default)]
	identity: IdentityTrustConfig,
	tools: HashMap<String, ToolConfig>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityTrustConfig {
	#[serde(default)]
	google: Option<GoogleConfig>,
	#[serde(default)]
	eudi: Option<EudiConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GoogleConfig {
	/// The Presence Providers' Google OAuth client ids.
	client_ids: Vec<String>,
	/// Google's keys as a JWKS file, and/or a URL to fetch them from and refresh hourly
	/// (normally https://www.googleapis.com/oauth2/v3/certs). Google rotates its keys, so a
	/// file alone goes stale.
	#[serde(default)]
	jwks_file: Option<PathBuf>,
	#[serde(default)]
	jwks_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EudiConfig {
	/// Trusted credential issuers, by `iss`.
	issuers: HashMap<String, CredentialIssuerConfig>,
	/// HAPS issuer → the OpenID4VP client_id its key-binding JWTs name.
	#[serde(default)]
	verifier_client_ids: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialIssuerConfig {
	jwks: PathBuf,
	vcts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolIdentityConfig {
	mode: IdentityModeConfig,
	schemes: Vec<SchemeConfig>,
	/// The gateway metadata key holding the caller's account identity. Required: an identity
	/// that is not matched against the caller only says that *someone* approved.
	account_attribute: String,
	#[serde(default)]
	require_verified: bool,
	#[serde(default)]
	require_embedded_evidence: bool,
	#[serde(default)]
	eudi_subject_claim: Option<String>,
	#[serde(default)]
	google_domains: Vec<String>,
	#[serde(default)]
	max_auth_age_seconds: Option<u64>,
	#[serde(default = "default_evidence_age")]
	max_evidence_age_seconds: u64,
}

fn default_evidence_age() -> u64 {
	300
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum IdentityModeConfig {
	Required,
	Preferred,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum SchemeConfig {
	EudiWallet,
	Google,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartyConfig {
	id: String,
	name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpKeyConfig {
	kid: String,
	/// An Ed25519 private key, PKCS#8 PEM.
	pem: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CertificationFileConfig {
	/// Trusted certifiers: certifier id → JWKS file. Must not be empty.
	certifiers: HashMap<String, PathBuf>,
	/// Credential issuer → the `providerId` its certifications name.
	providers: HashMap<String, String>,
	/// Certifications provisioned out of band: `providerCertification.ref` → compact JWS file.
	#[serde(default)]
	provisioned: HashMap<String, PathBuf>,
}

#[derive(Deserialize, Default)]
#[serde(tag = "backend", rename_all = "camelCase", deny_unknown_fields)]
enum StateConfig {
	/// Atomic within one process. Fine for a single replica.
	#[default]
	Memory,
	/// Shared by every replica pointed at the same Redis. Exactly one of `url` (a single
	/// node), `nodes` (a Cluster) or `sentinels` with `service` (Sentinel).
	#[serde(rename_all = "camelCase")]
	Redis {
		#[serde(default)]
		url: Option<String>,
		#[serde(default)]
		nodes: Option<Vec<String>>,
		#[serde(default)]
		sentinels: Option<Vec<String>>,
		#[serde(default)]
		service: Option<String>,
		#[serde(default = "default_prefix")]
		key_prefix: String,
		/// Replicas that must confirm each spend before an approval is honoured.
		#[serde(default)]
		min_replica_acks: u32,
		#[serde(default = "default_ack_timeout")]
		replica_ack_timeout_ms: u64,
	},
}

fn default_ack_timeout() -> u64 {
	500
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
enum SpendOnConfig {
	#[default]
	Forward,
	Success,
}

fn default_reservation_ttl() -> u64 {
	120
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolConfig {
	action_type: String,
	min_level: String,
	#[serde(default)]
	accepted_methods: Option<Vec<String>>,
	#[serde(default)]
	require_agent_resistant: bool,
	#[serde(default)]
	binding: BindingConfig,
	#[serde(default)]
	envelope_rules: HashMap<String, RuleConfig>,
	#[serde(default)]
	max_credential_age_seconds: Option<u64>,
	#[serde(default)]
	allow_multi_use: bool,
	#[serde(default)]
	challenge_mode: bool,
	#[serde(default)]
	display: Option<DisplayConfig>,
	/// `forward` (default) or `success`.
	#[serde(default)]
	spend_on: SpendOnConfig,
	/// With `spendOn: success`: how long a reserved use waits for the tool's result. Longer
	/// than the tool can take, or a slow success lapses into a reusable approval.
	#[serde(default = "default_reservation_ttl")]
	reservation_ttl_seconds: u64,
	#[serde(default)]
	identity: Option<ToolIdentityConfig>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
enum BindingConfig {
	#[default]
	Exact,
	Envelope,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleConfig {
	kind: RuleKindConfig,
	path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum RuleKindConfig {
	DecimalRange,
	AllowList,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayConfig {
	title: String,
	summary: String,
}

fn default_skew() -> u64 {
	60
}

fn default_challenge_ttl() -> u64 {
	300
}

fn default_prefix() -> String {
	// The hash tag keeps every key in one Redis Cluster slot, so one script can spend a jti
	// and a challenge together.
	"haps-guard:{haps}:".into()
}

fn read(base: &Path, path: &Path) -> anyhow::Result<String> {
	let full = base.join(path);
	std::fs::read_to_string(&full).with_context(|| format!("reading {}", full.display()))
}

fn jwks_map(
	base: &Path,
	files: &HashMap<String, PathBuf>,
) -> anyhow::Result<HashMap<String, JwkSet>> {
	files
		.iter()
		.map(|(id, path)| {
			let jwks = serde_json::from_str(&read(base, path)?)
				.with_context(|| format!("parsing {} as a JWKS", path.display()))?;
			Ok((id.clone(), jwks))
		})
		.collect()
}

/// Google's keys: from the file, then from the URL, refreshed hourly in the background. A
/// failed refresh keeps the last good keys.
async fn google_keys(base: &Path, g: &GoogleConfig) -> anyhow::Result<Arc<KeySource>> {
	let source = Arc::new(KeySource::default());
	match (&g.jwks_file, &g.jwks_url) {
		(None, None) => bail!("identity.google needs jwksFile, jwksUrl or both"),
		(Some(file), _) => source.replace(
			serde_json::from_str(&read(base, file)?)
				.with_context(|| format!("parsing {} as a JWKS", file.display()))?,
		),
		(None, Some(_)) => {},
	}
	if let Some(url) = g.jwks_url.clone() {
		let fetch = {
			let url = url.clone();
			move || {
				let url = url.clone();
				async move {
					let keys: JwkSet = reqwest::get(&url).await?.error_for_status()?.json().await?;
					anyhow::Ok(keys)
				}
			}
		};
		match fetch().await {
			Ok(keys) => source.replace(keys),
			Err(e) if g.jwks_file.is_some() => {
				tracing::warn!(%url, error = %e, "haps-guard: Google keys not fetched; using jwksFile")
			},
			Err(e) => return Err(e.context(format!("fetching Google keys from {url}"))),
		}
		let refreshed = source.clone();
		tokio::spawn(async move {
			let mut every = tokio::time::interval(std::time::Duration::from_secs(3600));
			every.tick().await;
			loop {
				every.tick().await;
				match fetch().await {
					Ok(keys) => refreshed.replace(keys),
					Err(e) => {
						tracing::warn!(error = %e, "haps-guard: Google key refresh failed; keeping the last keys")
					},
				}
			}
		});
	}
	Ok(source)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt::init();
	let path = std::env::args()
		.nth(1)
		.context("usage: haps-guard <config.yaml>")?;
	let path = PathBuf::from(path);
	let base = path.parent().unwrap_or(Path::new(".")).to_owned();
	let text = read(Path::new("."), &path)?;
	let config: Config =
		serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

	// Empty allowlists would trust no one or, worse, be misread as trusting everyone.
	if config.issuers.is_empty() {
		bail!("issuers must not be empty");
	}
	if config.certification.certifiers.is_empty() {
		bail!(
			"certification.certifiers must not be empty: without a trusted certifier every PoHP level is self-asserted (RP-CORE-06)"
		);
	}
	for issuer in config.issuers.keys() {
		if !config.certification.providers.contains_key(issuer) {
			bail!(
				"issuer {issuer} has no entry in certification.providers, so none of its credentials could be certified"
			);
		}
	}

	let mut tools = HashMap::new();
	for (name, t) in config.tools {
		let min_level = PohpLevel::parse(&t.min_level).with_context(|| {
			format!(
				"tool {name}: minLevel {:?} is not HAPS-PoHP-1..4",
				t.min_level
			)
		})?;
		let mut envelope_rules = HashMap::new();
		for (member, rule) in t.envelope_rules {
			let path = Pointer::parse(&rule.path)
				.map_err(anyhow::Error::msg)
				.with_context(|| format!("tool {name}: envelope rule {member}"))?;
			let kind = match rule.kind {
				RuleKindConfig::DecimalRange => RuleKind::DecimalRange,
				RuleKindConfig::AllowList => RuleKind::AllowList,
			};
			envelope_rules.insert(member, EnvelopeRule { kind, path });
		}
		let mut policy = ToolPolicy::new(t.action_type, min_level);
		policy.accepted_methods = t.accepted_methods;
		policy.require_agent_resistant = t.require_agent_resistant;
		policy.binding = match t.binding {
			BindingConfig::Exact => ArgumentBinding::Exact,
			BindingConfig::Envelope => ArgumentBinding::Envelope,
		};
		policy.envelope_rules = envelope_rules;
		policy.max_credential_age_secs = t.max_credential_age_seconds;
		policy.allow_multi_use = t.allow_multi_use;
		policy.challenge_mode = t.challenge_mode;
		if let Some(ic) = t.identity {
			let embedded =
				ic.require_embedded_evidence || min_level >= PohpLevel::parse("HAPS-PoHP-3").unwrap();
			for scheme in &ic.schemes {
				let configured = match scheme {
					SchemeConfig::Google => config.identity.google.is_some(),
					SchemeConfig::EudiWallet => config.identity.eudi.is_some(),
				};
				if embedded && !configured {
					bail!(
						"tool {name}: identity evidence must be re-verified, but identity.{} is not configured",
						match scheme {
							SchemeConfig::Google => "google",
							SchemeConfig::EudiWallet => "eudi",
						}
					);
				}
			}
			let mut ip = IdentityPolicy::new(
				matches!(ic.mode, IdentityModeConfig::Required),
				ic.schemes
					.iter()
					.map(|s| match s {
						SchemeConfig::Google => Scheme::Google,
						SchemeConfig::EudiWallet => Scheme::EudiWallet,
					})
					.collect(),
			);
			ip.account_attribute = Some(ic.account_attribute);
			ip.require_verified = ic.require_verified;
			ip.require_embedded_evidence = ic.require_embedded_evidence;
			ip.eudi_subject_claim = ic.eudi_subject_claim;
			ip.google_domains = ic.google_domains;
			ip.max_auth_age_secs = ic.max_auth_age_seconds;
			ip.max_evidence_age_secs = ic.max_evidence_age_seconds;
			policy.identity = Some(ip);
		}
		policy.spend_on = match t.spend_on {
			SpendOnConfig::Forward => SpendOn::Forward,
			SpendOnConfig::Success => SpendOn::Success {
				ttl_secs: t.reservation_ttl_seconds,
			},
		};
		if let Some(d) = t.display {
			policy.display = ChallengeDisplay {
				title: d.title,
				summary: d.summary,
			};
		}
		tools.insert(name, policy);
	}

	let rp_signer = config
		.rp_signing_key
		.map(|k| -> anyhow::Result<RpSigner> {
			let pem = read(&base, &k.pem)?;
			let key = EncodingKey::from_ed_pem(pem.as_bytes())
				.with_context(|| format!("{} is not an Ed25519 PKCS#8 PEM key", k.pem.display()))?;
			Ok(RpSigner { kid: k.kid, key })
		})
		.transpose()?;
	let provisioned = config
		.certification
		.provisioned
		.iter()
		.map(|(r, p)| Ok((r.clone(), read(&base, p)?.trim().to_owned())))
		.collect::<anyhow::Result<_>>()?;
	let store = match &config.state {
		StateConfig::Memory => StateStore::memory(),
		StateConfig::Redis {
			url,
			nodes,
			sentinels,
			service,
			key_prefix,
			min_replica_acks,
			replica_ack_timeout_ms,
		} => {
			let topology = match (url, nodes, sentinels, service) {
				(Some(url), None, None, None) => RedisTopology::Single { url: url.clone() },
				(None, Some(nodes), None, None) if !nodes.is_empty() => RedisTopology::Cluster {
					nodes: nodes.clone(),
				},
				(None, None, Some(sentinels), Some(service)) if !sentinels.is_empty() => {
					RedisTopology::Sentinel {
						sentinels: sentinels.clone(),
						service: service.clone(),
					}
				},
				_ => bail!("state: give exactly one of url, nodes, or sentinels with service"),
			};
			if !key_prefix.contains('{') || !key_prefix.contains('}') {
				bail!("state.keyPrefix must contain a {{hash tag}}, so every key shares a Cluster slot");
			}
			StateStore::redis(RedisOptions {
				topology,
				prefix: key_prefix.clone(),
				min_replica_acks: *min_replica_acks,
				replica_ack_timeout_ms: *replica_ack_timeout_ms,
			})
			.await
			.map_err(|e| anyhow::anyhow!("{e}"))
			.context("connecting to the Redis state store")?
		},
	};

	let identity = IdentityTrust {
		google: match &config.identity.google {
			None => None,
			Some(g) => Some(GoogleTrust {
				client_ids: g.client_ids.clone(),
				keys: google_keys(&base, g).await?,
			}),
		},
		eudi: match &config.identity.eudi {
			None => None,
			Some(e) => Some(EudiTrust {
				issuers: e
					.issuers
					.iter()
					.map(|(iss, c)| {
						let keys = serde_json::from_str(&read(&base, &c.jwks)?)
							.with_context(|| format!("parsing {} as a JWKS", c.jwks.display()))?;
						Ok((
							iss.clone(),
							CredentialIssuer {
								keys,
								vcts: c.vcts.clone(),
							},
						))
					})
					.collect::<anyhow::Result<_>>()?,
				verifier_client_ids: e.verifier_client_ids.clone(),
			}),
		},
	};

	let guard = Guard::new(
		GuardConfig {
			tools,
			issuers: jwks_map(&base, &config.issuers)?,
			audience: Party {
				id: config.audience.id,
				name: config.audience.name,
			},
			agent: Party {
				id: config.agent.id,
				name: config.agent.name,
			},
			elicitation_url: config.elicitation_url,
			clock_skew_secs: config.clock_skew_seconds,
			certification: CertificationConfig {
				certifiers: jwks_map(&base, &config.certification.certifiers)?,
				providers: config.certification.providers,
				provisioned,
			},
			agent_resistant_methods: config.agent_resistant_methods,
			challenge_ttl_secs: config.challenge_ttl_seconds,
			rp_signer,
			identity,
		},
		store,
	);
	tracing::info!(listen = %config.listen, "haps-guard: serving");
	tonic::transport::Server::builder()
		.add_service(ExtMcpServer::new(HapsGuardService::new(guard)))
		.serve(config.listen)
		.await?;
	Ok(())
}

//! `haps-guard <config.yaml>`: serve the HAPS guard as an mcpGuardrails processor.
//!
//! Relative paths in the config are resolved against the config file's directory.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use haps_guard::certification::CertificationConfig;
use haps_guard::envelope::{EnvelopeRule, Pointer, RuleKind};
use haps_guard::server::HapsGuardService;
use haps_guard::store::StateStore;
use haps_guard::{
	ArgumentBinding, ChallengeDisplay, Guard, GuardConfig, Party, PohpLevel, RpSigner, ToolPolicy,
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
	tools: HashMap<String, ToolConfig>,
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
	/// Shared by every replica pointed at the same Redis.
	#[serde(rename_all = "camelCase")]
	Redis {
		url: String,
		#[serde(default = "default_prefix")]
		key_prefix: String,
	},
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
		StateConfig::Redis { url, key_prefix } => StateStore::redis(url, key_prefix)
			.await
			.map_err(|e| anyhow::anyhow!("{e}"))
			.context("connecting to the Redis state store")?,
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

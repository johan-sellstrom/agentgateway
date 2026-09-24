//! `haps-guard <config.yaml>`: serve the HAPS guard as an mcpGuardrails processor.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use haps_guard::server::HapsGuardService;
use haps_guard::{Guard, GuardConfig, PohpLevel, ToolPolicy};
use protos::ext_mcp::ext_mcp_server::ExtMcpServer;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
	listen: SocketAddr,
	/// The `aud` an approval must carry: this gateway.
	audience: String,
	/// Issuers whose credentials are accepted. Must not be empty.
	issuers: Vec<String>,
	/// Presence Provider URL the host is sent to when approval is needed.
	elicitation_url: String,
	/// JWKS file holding the Presence Providers' public keys.
	trusted_keys: PathBuf,
	#[serde(default = "default_skew")]
	clock_skew_seconds: u64,
	tools: HashMap<String, ToolConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolConfig {
	action_type: String,
	min_level: String,
}

fn default_skew() -> u64 {
	60
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt::init();
	let path = std::env::args()
		.nth(1)
		.context("usage: haps-guard <config.yaml>")?;
	let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
	let config: Config = serde_norway::from_str(&text).with_context(|| format!("parsing {path}"))?;

	if config.issuers.is_empty() {
		bail!(
			"issuers must not be empty: an empty allowlist would trust no one or, worse, be misread as trusting everyone"
		);
	}
	let jwks = std::fs::read_to_string(&config.trusted_keys)
		.with_context(|| format!("reading {}", config.trusted_keys.display()))?;
	let keys = serde_json::from_str(&jwks).context("parsing trustedKeys as a JWKS")?;
	let mut tools = HashMap::new();
	for (name, t) in config.tools {
		let min_level = PohpLevel::parse(&t.min_level).with_context(|| {
			format!(
				"tool {name}: minLevel {:?} is not HAPS-PoHP-1..4",
				t.min_level
			)
		})?;
		tools.insert(
			name,
			ToolPolicy {
				action_type: t.action_type,
				min_level,
			},
		);
	}

	let guard = Guard::new(GuardConfig {
		tools,
		keys,
		issuers: config.issuers,
		audience: config.audience,
		elicitation_url: config.elicitation_url,
		clock_skew_secs: config.clock_skew_seconds,
	});
	tracing::info!(listen = %config.listen, "haps-guard: serving");
	tonic::transport::Server::builder()
		.add_service(ExtMcpServer::new(HapsGuardService::new(guard)))
		.serve(config.listen)
		.await?;
	Ok(())
}

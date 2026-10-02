//! The `ExtMcp` gRPC service: maps a [`Decision`] onto the mcpGuardrails wire contract.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use protos::ext_mcp::authorization_error::Code;
use protos::ext_mcp::ext_mcp_server::ExtMcp;
use protos::ext_mcp::{
	AuthorizationError, McpRequest, McpRequestResult, McpResponse, McpResponseResult, Pass,
	mcp_request_result, mcp_response_result,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::{Decision, Guard};

/// MCP 2025-11-25 "URL elicitation required".
pub const URL_ELICITATION_REQUIRED: i64 = -32042;

/// The response-metadata key under which the gateway must send a reserved use back, for tools
/// that spend on success: configure the guardrail with
/// `metadata: { hapsReservation: "mcpGuardrails.haps.reservation" }`. The same expression is
/// evaluated for the request, where it finds nothing; that is expected.
pub const RESERVATION_METADATA_KEY: &str = "hapsReservation";

#[derive(Clone)]
pub struct HapsGuardService {
	guard: Arc<Guard>,
}

impl HapsGuardService {
	pub fn new(guard: Guard) -> Self {
		Self {
			guard: Arc::new(guard),
		}
	}

	/// Decide one request against an explicit clock; the RPC handler passes the real one.
	pub async fn decide(&self, req: &McpRequest, now: u64) -> McpRequestResult {
		let tool = tool_name(req);
		// The gateway's metadata for this call, as JSON: where the caller's account comes from.
		let metadata = req
			.metadata_context
			.as_ref()
			.and_then(|m| serde_json::to_value(m).ok())
			.and_then(|v| match v {
				serde_json::Value::Object(m) => Some(m),
				_ => None,
			});
		match self
			.guard
			.check_with(
				&req.method,
				req.mcp_request.as_deref(),
				metadata.as_ref(),
				now,
			)
			.await
		{
			Decision::NotGated => pass(),
			Decision::Approved { params, audit } => {
				info!(
					tool,
					jti = %audit.jti,
					issuer = %audit.issuer,
					level = %audit.level,
					method = %audit.method,
					certifier = %audit.certifier,
					challenge = audit.challenge_id.as_deref().unwrap_or("-"),
					"haps-guard: approved"
				);
				McpRequestResult {
					result: Some(mcp_request_result::Result::Mutated(params.into())),
					header_mutation: None,
					metadata: audit_metadata(&audit),
				}
			},
			Decision::ElicitationRequired {
				reason,
				elicitation,
			} => {
				info!(tool, %reason, "haps-guard: elicitation required");
				// Relies on the gateway honouring `mcp_error` as a JSON-RPC error and bubbling
				// -32042 up from tools/call; without both, the host never sees it.
				let payload = serde_json::json!({
					"code": URL_ELICITATION_REQUIRED,
					"message": "URL elicitation required",
					"data": elicitation,
				});
				reject(reason, Some(payload))
			},
			Decision::Denied(denial) => {
				// A tamper signal as often as a mistake, so it is logged at warn.
				warn!(tool, reason = %denial, "haps-guard: denied");
				// No `mcp_error`: the gateway turns this into a tool result the model reads.
				reject(denial.to_string(), None)
			},
		}
	}
}

impl HapsGuardService {
	/// Settle a use reserved for this response, if there is one. The response always passes
	/// unchanged: settling is bookkeeping, and the tool has already run.
	pub async fn settle(&self, resp: &McpResponse, now: u64) -> McpResponseResult {
		let reservation = resp
			.metadata_context
			.as_ref()
			.and_then(|m| serde_json::to_value(m).ok())
			.and_then(|m| {
				m.get(RESERVATION_METADATA_KEY)
					.and_then(|v| v.as_str())
					.map(str::to_owned)
			});
		if resp.method == "tools/call"
			&& let Some(id) = reservation
		{
			match self.guard.settle(&id, &resp.mcp_response, now).await {
				crate::Settlement::Spent => info!(reservation = %id, "haps-guard: use spent"),
				crate::Settlement::Released => {
					info!(reservation = %id, "haps-guard: tool failed, use given back")
				},
				crate::Settlement::Unknown => {
					warn!(reservation = %id, "haps-guard: no such reservation; it lapsed or was settled")
				},
				crate::Settlement::Failed(e) => {
					warn!(reservation = %id, error = %e, "haps-guard: could not settle; the reservation will lapse")
				},
			}
		}
		McpResponseResult {
			result: Some(mcp_response_result::Result::Pass(Pass {})),
		}
	}
}

#[tonic::async_trait]
impl ExtMcp for HapsGuardService {
	async fn check_request(
		&self,
		request: Request<McpRequest>,
	) -> Result<Response<McpRequestResult>, Status> {
		Ok(Response::new(
			self.decide(request.get_ref(), unix_now()).await,
		))
	}

	async fn check_response(
		&self,
		request: Request<McpResponse>,
	) -> Result<Response<McpResponseResult>, Status> {
		Ok(Response::new(
			self.settle(request.get_ref(), unix_now()).await,
		))
	}
}

fn pass() -> McpRequestResult {
	McpRequestResult {
		result: Some(mcp_request_result::Result::Pass(Pass {})),
		header_mutation: None,
		metadata: None,
	}
}

fn reject(reason: String, mcp_error: Option<serde_json::Value>) -> McpRequestResult {
	McpRequestResult {
		result: Some(mcp_request_result::Result::Error(AuthorizationError {
			code: Code::PermissionDenied as i32,
			reason,
			mcp_error: mcp_error.map(|v| serde_json::to_vec(&v).expect("json value").into()),
		})),
		header_mutation: None,
		metadata: None,
	}
}

/// Exposed to gateway CEL as `mcpGuardrails.haps.*`, for audit and downstream policy. The factor sits
/// beside the level (FACTOR-RP-05), so a later review can tell what kind of proof was accepted.
fn audit_metadata(audit: &crate::Audit) -> Option<prost_wkt_types::Struct> {
	serde_json::from_value(serde_json::json!({
		"haps": {
			"jti": audit.jti,
			"issuer": audit.issuer,
			"level": audit.level,
			"method": audit.method,
			"actionType": audit.action_type,
			"certifier": audit.certifier,
			"providerId": audit.provider_id,
			"evaluation": audit.evaluation,
			"challengeId": audit.challenge_id,
			"variedWithinEnvelope": audit.varied_within_envelope,
			"reservation": audit.reservation_id,
			"format": audit.format,
			"identity": audit.identity.as_ref().map(|b| serde_json::json!({
				"scheme": b.scheme,
				"subject": b.subject,
				"reverified": b.reverified,
			})),
		}
	}))
	.ok()
}

/// The tool name, for logs only; the guard parses the request itself.
fn tool_name(req: &McpRequest) -> String {
	req
		.mcp_request
		.as_deref()
		.and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
		.and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_owned))
		.unwrap_or_default()
}

fn unix_now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

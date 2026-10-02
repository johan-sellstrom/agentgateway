# haps-guard

An agentgateway `mcpGuardrails` processor that acts as the HAPS v0.4 relying party for MCP
`tools/call`. For each gated tool it requires a HAPS Consent Credential, an approval of exactly
this call by a present human, and checks it before the gateway forwards the call.

**Experimental; not production-ready.** Passing its tests does not establish HAPS conformance,
any PoHP level, or that a person saw and approved the right action (`haps-v0.4.0.md` §16).

## What it checks

| | |
| --- | --- |
| RP-CORE-01..10 | signature and issuer trust (keys scoped per issuer), audience, time, `intent_hash`, `presentation_hash` over the view *derived* from the intent, PoHP level and provider certification, one-time use, envelopes, challenge mode, replay retention |
| FACTOR-RP-01..05 | accepted factors; agent-accessible factors refused from PoHP-2 |
| HAPS-RP-ID-0.4 | identity binding: an EUDI wallet presentation or a Google identity, matched to the caller's account |
| Formats | `jwt` and `vc+json` (Data Integrity `eddsa-jcs-2022`, `ecdsa-jcs-2019`) |
| Binding | the approved `action.parameters` equal the call's arguments after canonicalisation, or differ only within an envelope the tool allows |

The module docs in `src/lib.rs` carry the full table; each module documents its part.

## Running it

```sh
haps-guard config.yaml
```

```yaml
listen: 0.0.0.0:9100
audience: {id: did:web:bank.example, name: Example Bank}   # `aud` an approval must carry
agent: {id: did:web:agent.example, name: Treasury Agent}    # named in challenge-mode intents
issuers:                                                    # trusted Presence Providers
  did:web:pp.example: pp-jwks.json
elicitationUrl: https://pp.example/approve
certification:
  certifiers: {did:web:certifier.example: certifier-jwks.json}
  providers: {did:web:pp.example: provider-a}               # issuer -> providerId in its PCC
state:                                                      # memory (default) or redis
  backend: redis
  url: redis://10.0.0.3:6379/          # or nodes: [...] (Cluster), or sentinels: [...] + service
  keyPrefix: "haps-guard:{haps}:"      # the {hash tag} is required
  minReplicaAcks: 1                    # WAIT for a replica before honouring a spend
identity:
  google:
    clientIds: [pp-client.apps.googleusercontent.com]
    jwksUrl: https://www.googleapis.com/oauth2/v3/certs
  eudi:
    issuers:
      https://pid.example: {jwks: pid-issuer-jwks.json, vcts: ["urn:eudi:pid:1"]}
    verifierClientIds: {did:web:pp.example: pp.example}
tools:
  transfer_funds:
    actionType: payment.transfer
    minLevel: HAPS-PoHP-2
    challengeMode: true
    spendOn: success
    binding: envelope
    envelopeRules:
      amountRange: {kind: decimalRange, path: /amount}
      allowedPayees: {kind: allowList, path: /to}
    identity:
      mode: required
      schemes: [eudiWallet, google]
      accountAttribute: account
      eudiSubjectClaim: email_address
      requireEmbeddedEvidence: true
```

Relative paths resolve against the config file's directory. `src/main.rs` documents every key.
The guard refuses to start without a trusted certifier, with an issuer that has no provider
mapping, or with a tool that must re-verify identity evidence for a scheme that is not configured.

On the gateway, attach the guard to the route and pass it what it needs as metadata:

```yaml
policies:
  mcpGuardrails:
    processors:
    - host: haps-guard:9100
      failureMode: failClosed
      methods: {"tools/call": full}
      metadata:
        account: jwt.email                                  # the caller, for identity binding
        hapsReservation: mcpGuardrails.haps.reservation     # for tools with spendOn: success
```

The gateway must carry this fork's two guardrail fixes (processors receive `_meta` and their
edits to it are honoured; `-32042` reaches the host). Without them the credential reaches the
tool and the host never sees the approval URL.

## Interpretations

HAPS v0.4 leaves these open. The guard's choices are interpretations, not specification text,
and a Presence Provider must follow the same ones for its credentials to be accepted. They are
offered as input to the next HAPS draft.

| Open in HAPS v0.4 | The guard's choice | Where |
| --- | --- | --- |
| Executable Signing View derivation (§7.1) | The intent without `version`, `intentId`, `issuedAt`: the one rule the published VEC-01 pair supports | `derive_signing_view` |
| Envelope member semantics (§6.3) | A guard-defined vocabulary, `decimalRange` and `allowList`, configured per tool; an unknown member is refused | `envelope` |
| HAPS-PCC wire form (§16) | `embedded` is a certifier-signed compact JWS; `hash` is over the JCS-canonical PCC claims; a `ref` alone is never fetched, only provisioned | `certification` |
| Issuer to `providerId` mapping | Operator-configured | `certification` |
| Challenge transport (§10, MCP profile) | The HAPS-CHAL travels in the `-32042` data and, canonical and base64url-encoded, in the elicitation URL; `rpProof` is a JWS over the challenge | `issue_challenge` |
| Binding identity evidence to the approval (§9.3) | The evidence's nonce is the approval's `challengeId`, else its `intent_hash` | `identity` |
| Whose account identity binding is matched against (RP-IDB-03) | A gateway metadata key | `identity` |
| Google identity binding | `google_oidc`, a guard-defined adapter modelled on `entra_oidc` | `identity` |
| `vc+json` proof suite and claim mapping (§11) | Data Integrity JCS suites; claims in `credentialSubject`; `verificationMethod` is `<issuer>#<kid>` | `vc` |
| When a one-time approval is spent | On forwarding by default; per tool, on success, reserved and settled from the response | `store` |

## Tests

```sh
cargo test -p haps-guard                                  # unit and policy tests
cargo test -p haps-guard -- --ignored                     # Redis: single node, Cluster, Sentinel failover
cargo test -p agentgateway --lib haps_guard               # through a real gateway and MCP client
(cd ../../interop/haps-guard-eudi-wallet && cargo test)   # EUWallet presents, the guard verifies
```

The Redis tests start their own `redis-server`, `redis-cli` and `redis-sentinel` processes. The
interop crate is its own workspace and needs SSH access to the private EUWallet repository; the
gateway's own build never does.

Test data: the HAPS v0.4 vectors (`testdata/haps-v0.4`) and the W3C Data Integrity vectors
(`testdata/vc-di`) are copied unmodified, with their sources; `testdata/identity` holds a
throwaway RSA key standing in for Google's.

## Not covered

- Revocation: EUDI Token Status Lists are not consulted.
- Identity binding schemes other than the two above (`entra_oidc` is specified by HAPS but not
  implemented here), and the liveness modes of the Digital Credentials profile.
- A real Presence Provider and real trust anchors: every key in the tests is a test key.

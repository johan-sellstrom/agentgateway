//! Replay and challenge state: RP-CORE-07, 09 and 10.
//!
//! Two backends behind one interface. The in-memory store is atomic within one process. The
//! Redis store is atomic across every replica that shares the Redis, which is what a deployment
//! with more than one guard needs: otherwise each replica keeps its own record and the same
//! approval can be spent once per replica.
//!
//! The one write that matters is [`StateStore::consume`]: it spends a use of a `jti` and, in
//! challenge mode, the challenge, together or not at all. Spending one without the other would
//! either burn an approval for a call that was then refused, or leave a challenge open for a
//! second credential.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

/// Outstanding challenges one in-memory store will hold. Every unapproved call to a challenge
/// mode tool creates one, so without a cap a caller could grow the guard's memory without bound.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 10_000;

/// What the guard remembers about a challenge it issued.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
	/// The tool whose call the challenge was issued for.
	pub tool: String,
	/// The `intent_hash` of the AI-INTENT inside the challenge: the transaction context a
	/// credential must carry to answer it.
	pub intent_hash: String,
	/// Unix seconds.
	pub expires_at: u64,
}

/// One use to spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consume {
	pub jti: String,
	/// How many uses the approval allows, or `None` for no limit (nothing is recorded).
	pub max_uses: Option<u32>,
	/// Unix seconds until which the record is kept: `exp + skew` (RP-CORE-10).
	pub retain_until: u64,
	/// In challenge mode, the challenge to spend with it.
	pub challenge_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
	Consumed,
	/// The approval has no uses left.
	Replayed,
	/// The challenge has already been spent, or has expired, since it was read.
	ChallengeGone,
}

#[derive(Debug)]
pub enum StoreError {
	/// The in-memory store is at [`MAX_OUTSTANDING_CHALLENGES`].
	Full,
	Backend(String),
}

impl fmt::Display for StoreError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			StoreError::Full => write!(f, "too many outstanding approval challenges"),
			StoreError::Backend(e) => write!(f, "approval state store unavailable: {e}"),
		}
	}
}

pub enum StateStore {
	Memory(MemoryStore),
	Redis(RedisStore),
}

impl StateStore {
	pub fn memory() -> Self {
		StateStore::Memory(MemoryStore::default())
	}

	/// Connect to Redis. `prefix` namespaces every key; keep the `{…}` hash tag in it on a
	/// Redis Cluster, so that a `jti` and a challenge land in one slot and can be spent in one
	/// script.
	pub async fn redis(url: &str, prefix: &str) -> Result<Self, StoreError> {
		Ok(StateStore::Redis(RedisStore::connect(url, prefix).await?))
	}

	pub async fn put_challenge(
		&self,
		id: &str,
		record: &ChallengeRecord,
		now: u64,
	) -> Result<(), StoreError> {
		match self {
			StateStore::Memory(m) => m.put_challenge(id, record, now),
			StateStore::Redis(r) => r.put_challenge(id, record).await,
		}
	}

	/// The challenge `id`, if it is outstanding: issued, not yet spent and not expired.
	pub async fn get_challenge(
		&self,
		id: &str,
		now: u64,
	) -> Result<Option<ChallengeRecord>, StoreError> {
		match self {
			StateStore::Memory(m) => Ok(m.get_challenge(id, now)),
			StateStore::Redis(r) => r.get_challenge(id, now).await,
		}
	}

	pub async fn consume(&self, c: &Consume, now: u64) -> Result<ConsumeOutcome, StoreError> {
		match self {
			StateStore::Memory(m) => Ok(m.consume(c, now)),
			StateStore::Redis(r) => r.consume(c).await,
		}
	}
}

#[derive(Default)]
pub struct MemoryStore {
	inner: Mutex<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
	/// `jti` → (uses spent, retain until).
	uses: HashMap<String, (u32, u64)>,
	challenges: HashMap<String, ChallengeRecord>,
}

impl MemoryInner {
	fn prune(&mut self, now: u64) {
		self.uses.retain(|_, (_, until)| *until >= now);
		self.challenges.retain(|_, c| c.expires_at >= now);
	}
}

impl MemoryStore {
	fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
		self.inner.lock().unwrap_or_else(PoisonError::into_inner)
	}

	fn put_challenge(&self, id: &str, record: &ChallengeRecord, now: u64) -> Result<(), StoreError> {
		let mut inner = self.lock();
		inner.prune(now);
		if inner.challenges.len() >= MAX_OUTSTANDING_CHALLENGES {
			return Err(StoreError::Full);
		}
		inner.challenges.insert(id.to_owned(), record.clone());
		Ok(())
	}

	fn get_challenge(&self, id: &str, now: u64) -> Option<ChallengeRecord> {
		let mut inner = self.lock();
		inner.prune(now);
		inner.challenges.get(id).cloned()
	}

	fn consume(&self, c: &Consume, now: u64) -> ConsumeOutcome {
		let mut inner = self.lock();
		inner.prune(now);
		let spent = inner.uses.get(&c.jti).map_or(0, |(n, _)| *n);
		if c.max_uses.is_some_and(|max| spent >= max) {
			return ConsumeOutcome::Replayed;
		}
		if let Some(id) = &c.challenge_id
			&& !inner.challenges.contains_key(id)
		{
			return ConsumeOutcome::ChallengeGone;
		}
		if c.max_uses.is_some() {
			inner
				.uses
				.insert(c.jti.clone(), (spent + 1, c.retain_until));
		}
		if let Some(id) = &c.challenge_id {
			inner.challenges.remove(id);
		}
		ConsumeOutcome::Consumed
	}
}

/// Spends a use of a `jti` and, if given, a challenge, atomically: Redis runs a script without
/// interleaving any other command. Returns 0 consumed, 1 replayed, 2 challenge gone.
const CONSUME_SCRIPT: &str = r"
local limit = tonumber(ARGV[1])
if limit > 0 then
  local spent = tonumber(redis.call('GET', KEYS[1]) or '0')
  if spent >= limit then return 1 end
end
if #KEYS == 2 and redis.call('EXISTS', KEYS[2]) == 0 then return 2 end
if limit > 0 then
  redis.call('INCR', KEYS[1])
  redis.call('EXPIREAT', KEYS[1], ARGV[2])
end
if #KEYS == 2 then redis.call('DEL', KEYS[2]) end
return 0
";

pub struct RedisStore {
	conn: redis::aio::ConnectionManager,
	prefix: String,
	consume: redis::Script,
}

impl RedisStore {
	async fn connect(url: &str, prefix: &str) -> Result<Self, StoreError> {
		let backend = |e: redis::RedisError| StoreError::Backend(e.to_string());
		let client = redis::Client::open(url).map_err(backend)?;
		let conn = client.get_connection_manager().await.map_err(backend)?;
		Ok(Self {
			conn,
			prefix: prefix.to_owned(),
			consume: redis::Script::new(CONSUME_SCRIPT),
		})
	}

	fn jti_key(&self, jti: &str) -> String {
		format!("{}jti:{jti}", self.prefix)
	}

	fn challenge_key(&self, id: &str) -> String {
		format!("{}chal:{id}", self.prefix)
	}

	async fn put_challenge(&self, id: &str, record: &ChallengeRecord) -> Result<(), StoreError> {
		let value = serde_json::to_string(record).map_err(|e| StoreError::Backend(e.to_string()))?;
		let mut conn = self.conn.clone();
		// NX: a challenge id is a fresh UUID, so a collision is a bug, never an overwrite.
		let set: Option<String> = redis::cmd("SET")
			.arg(self.challenge_key(id))
			.arg(value)
			.arg("EXAT")
			.arg(record.expires_at)
			.arg("NX")
			.query_async(&mut conn)
			.await
			.map_err(|e| StoreError::Backend(e.to_string()))?;
		match set {
			Some(_) => Ok(()),
			None => Err(StoreError::Backend(format!(
				"challenge {id} already exists"
			))),
		}
	}

	async fn get_challenge(&self, id: &str, now: u64) -> Result<Option<ChallengeRecord>, StoreError> {
		let mut conn = self.conn.clone();
		let value: Option<String> = redis::cmd("GET")
			.arg(self.challenge_key(id))
			.query_async(&mut conn)
			.await
			.map_err(|e| StoreError::Backend(e.to_string()))?;
		let Some(value) = value else { return Ok(None) };
		let record: ChallengeRecord =
			serde_json::from_str(&value).map_err(|e| StoreError::Backend(e.to_string()))?;
		// Redis expiry is to the second and lazy; the record's own expiry is authoritative.
		Ok((record.expires_at >= now).then_some(record))
	}

	async fn consume(&self, c: &Consume) -> Result<ConsumeOutcome, StoreError> {
		let mut conn = self.conn.clone();
		let mut invocation = self.consume.prepare_invoke();
		invocation.key(self.jti_key(&c.jti));
		if let Some(id) = &c.challenge_id {
			invocation.key(self.challenge_key(id));
		}
		invocation.arg(c.max_uses.unwrap_or(0)).arg(c.retain_until);
		let outcome: i64 = invocation
			.invoke_async(&mut conn)
			.await
			.map_err(|e| StoreError::Backend(e.to_string()))?;
		match outcome {
			0 => Ok(ConsumeOutcome::Consumed),
			1 => Ok(ConsumeOutcome::Replayed),
			2 => Ok(ConsumeOutcome::ChallengeGone),
			n => Err(StoreError::Backend(format!("consume script returned {n}"))),
		}
	}
}

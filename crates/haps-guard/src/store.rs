//! Replay and challenge state: RP-CORE-07, 09 and 10.
//!
//! Two backends behind one interface. The in-memory store is atomic within one process. The
//! Redis store is atomic across every replica of the guard that shares the Redis, which is what
//! a deployment with more than one guard needs: otherwise each keeps its own record and the
//! same approval can be spent once per replica. Redis may be a single node, a Cluster, or a
//! Sentinel-managed primary with replicas.
//!
//! The write that matters is [`StateStore::consume`]: it spends a use of a `jti` and, in
//! challenge mode, the challenge, together or not at all. Spending one without the other would
//! either burn an approval for a call that was then refused, or leave a challenge open for a
//! second credential.
//!
//! A use is spent either at once, or reserved and settled later: [`StateStore::commit`] when the
//! tool succeeded, [`StateStore::release`] when it failed. A reservation counts as a use while it
//! lives, so a second call cannot run concurrently on the same approval, and lapses on its own if
//! never settled — a timeout, an upstream error, a crashed gateway. That last case is the price
//! of spending on success: if the tool ran but the commit never arrived, the approval becomes
//! usable again when the reservation lapses. Tools where running twice is worse than a failed
//! call burning an approval should spend at once.
//!
//! **Durability under failover.** Redis replicates asynchronously. A spend acknowledged by a
//! primary that then fails before replicating is lost, and the approval can be spent again on
//! the promoted replica. `min_replica_acks` makes the guard wait for that many replicas to
//! confirm each spend (`WAIT`) and fail closed when they do not.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use redis::cluster_routing::{Route, RoutingInfo, SingleNodeRoutingInfo, SlotAddr};
use redis::{Cmd, FromRedisValue, RedisError, RedisResult};
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

/// One use to spend or reserve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consume {
	pub jti: String,
	/// How many uses the approval allows, or `None` for no limit (nothing is counted).
	pub max_uses: Option<u32>,
	/// Unix seconds until which the record is kept: `exp + skew` (RP-CORE-10).
	pub retain_until: u64,
	/// In challenge mode, the challenge to spend with it.
	pub challenge_id: Option<String>,
	/// Reserve the use instead of spending it now.
	pub reservation: Option<Reservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
	/// Unguessable: whoever holds it can settle the reservation.
	pub id: String,
	/// Unix seconds after which an unsettled reservation lapses.
	pub expires_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
	/// Spent, or reserved if a reservation was asked for.
	Consumed,
	/// The approval has no uses left.
	Replayed,
	/// The challenge has been spent, has expired, or is reserved by a call in flight.
	ChallengeGone,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SettleOutcome {
	Settled,
	/// No such reservation: already settled, lapsed, or never made.
	Unknown,
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

impl From<RedisError> for StoreError {
	fn from(e: RedisError) -> Self {
		StoreError::Backend(e.to_string())
	}
}

/// The reservation as stored: what a commit or release needs to find again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reserved {
	jti: String,
	challenge_id: Option<String>,
	retain_until: u64,
	max_uses: Option<u32>,
	expires_at: u64,
}

pub enum StateStore {
	Memory(MemoryStore),
	Redis(Box<RedisStore>),
}

impl StateStore {
	pub fn memory() -> Self {
		StateStore::Memory(MemoryStore::default())
	}

	pub async fn redis(options: RedisOptions) -> Result<Self, StoreError> {
		Ok(StateStore::Redis(Box::new(
			RedisStore::connect(options).await?,
		)))
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
			StateStore::Redis(r) => r.consume(c, now).await,
		}
	}

	/// The reserved call succeeded: spend the use, and the challenge.
	pub async fn commit(&self, reservation_id: &str, now: u64) -> Result<SettleOutcome, StoreError> {
		match self {
			StateStore::Memory(m) => Ok(m.settle(reservation_id, true, now)),
			StateStore::Redis(r) => r.settle(reservation_id, true).await,
		}
	}

	/// The reserved call failed: give the use back. The challenge stays outstanding.
	pub async fn release(&self, reservation_id: &str, now: u64) -> Result<SettleOutcome, StoreError> {
		match self {
			StateStore::Memory(m) => Ok(m.settle(reservation_id, false, now)),
			StateStore::Redis(r) => r.settle(reservation_id, false).await,
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
	reservations: HashMap<String, Reserved>,
}

impl MemoryInner {
	fn prune(&mut self, now: u64) {
		self.uses.retain(|_, (_, until)| *until >= now);
		self.challenges.retain(|_, c| c.expires_at >= now);
		self.reservations.retain(|_, r| r.expires_at >= now);
	}

	fn in_flight(&self, jti: &str) -> u32 {
		self.reservations.values().filter(|r| r.jti == jti).count() as u32
	}

	fn challenge_reserved(&self, id: &str) -> bool {
		self
			.reservations
			.values()
			.any(|r| r.challenge_id.as_deref() == Some(id))
	}

	fn spend(
		&mut self,
		jti: &str,
		max_uses: Option<u32>,
		retain_until: u64,
		challenge: Option<&str>,
	) {
		if max_uses.is_some() {
			let entry = self.uses.entry(jti.to_owned()).or_insert((0, retain_until));
			entry.0 += 1;
			entry.1 = entry.1.max(retain_until);
		}
		if let Some(id) = challenge {
			self.challenges.remove(id);
		}
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
		if c
			.max_uses
			.is_some_and(|max| spent + inner.in_flight(&c.jti) >= max)
		{
			return ConsumeOutcome::Replayed;
		}
		if let Some(id) = &c.challenge_id
			&& (!inner.challenges.contains_key(id) || inner.challenge_reserved(id))
		{
			return ConsumeOutcome::ChallengeGone;
		}
		match &c.reservation {
			None => inner.spend(
				&c.jti,
				c.max_uses,
				c.retain_until,
				c.challenge_id.as_deref(),
			),
			Some(r) => {
				inner.reservations.insert(
					r.id.clone(),
					Reserved {
						jti: c.jti.clone(),
						challenge_id: c.challenge_id.clone(),
						retain_until: c.retain_until,
						max_uses: c.max_uses,
						expires_at: r.expires_at,
					},
				);
			},
		}
		ConsumeOutcome::Consumed
	}

	fn settle(&self, id: &str, commit: bool, now: u64) -> SettleOutcome {
		let mut inner = self.lock();
		inner.prune(now);
		let Some(r) = inner.reservations.remove(id) else {
			return SettleOutcome::Unknown;
		};
		if commit {
			inner.spend(
				&r.jti,
				r.max_uses,
				r.retain_until,
				r.challenge_id.as_deref(),
			);
		}
		SettleOutcome::Settled
	}
}

/// Where the Redis is, and how much durability to demand of it.
#[derive(Clone, Debug)]
pub struct RedisOptions {
	pub topology: RedisTopology,
	/// Namespaces every key. Keep a `{…}` hash tag in it: on a Cluster, every key the guard
	/// touches must hash to one slot, so one script can spend a `jti` and a challenge together.
	pub prefix: String,
	/// Replicas that must confirm each spend before the guard approves (`WAIT`). 0 disables it.
	pub min_replica_acks: u32,
	pub replica_ack_timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub enum RedisTopology {
	Single {
		url: String,
	},
	Cluster {
		nodes: Vec<String>,
	},
	/// Sentinels monitoring the primary named `service`. The guard asks them for the current
	/// primary, and asks again whenever the connection fails or turns read-only.
	Sentinel {
		sentinels: Vec<String>,
		service: String,
	},
}

pub struct RedisStore {
	conn: Conn,
	prefix: String,
	min_replica_acks: u32,
	replica_ack_timeout_ms: u64,
}

enum Conn {
	Single(redis::aio::ConnectionManager),
	Cluster(redis::cluster_async::ClusterConnection),
	Sentinel(Box<SentinelConn>),
}

struct SentinelConn {
	client: tokio::sync::Mutex<redis::sentinel::SentinelClient>,
	conn: tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>,
}

impl SentinelConn {
	async fn connection(&self) -> RedisResult<redis::aio::MultiplexedConnection> {
		let mut cached = self.conn.lock().await;
		if let Some(c) = cached.as_ref() {
			return Ok(c.clone());
		}
		let client = self.client.lock().await.async_get_client().await?;
		let c = client.get_multiplexed_async_connection().await?;
		*cached = Some(c.clone());
		Ok(c)
	}

	async fn forget(&self) {
		*self.conn.lock().await = None;
	}
}

/// After a failover the old connection fails or lands on a demoted, read-only node.
fn primary_moved(e: &RedisError) -> bool {
	e.is_io_error()
		|| e.is_connection_dropped()
		|| e.is_unrecoverable_error()
		|| matches!(
			e.kind(),
			redis::ErrorKind::Server(redis::ServerErrorKind::ReadOnly)
		)
}

impl Conn {
	/// Run one command. `key` names the slot the command concerns, so commands without keys of
	/// their own (`WAIT`) reach the right Cluster shard.
	async fn query<T: FromRedisValue>(&self, cmd: &Cmd, key: &str) -> RedisResult<T> {
		match self {
			Conn::Single(c) => cmd.query_async(&mut c.clone()).await,
			Conn::Cluster(c) => {
				let routing = RoutingInfo::SingleNode(SingleNodeRoutingInfo::SpecificNode(
					Route::with_key(key, SlotAddr::Master),
				));
				let value = c.clone().route_command(cmd.clone(), routing).await?;
				T::from_redis_value(value).map_err(RedisError::from)
			},
			Conn::Sentinel(s) => {
				match cmd.query_async(&mut s.connection().await?).await {
					Err(e) if primary_moved(&e) => {
						// One retry against whichever node is primary now. A retried spend that
						// had in fact applied counts the use twice, which errs toward refusing.
						s.forget().await;
						cmd.query_async(&mut s.connection().await?).await
					},
					other => other,
				}
			},
		}
	}
}

/// Spends or reserves a use of a `jti` and, if asked, a challenge, atomically: Redis runs a
/// script without interleaving any other command.
///
/// KEYS: 1 uses-spent counter, 2 in-flight reservations (sorted by expiry), 3 challenge,
/// 4 challenge-reserved marker, 5 reservation record.
/// ARGV: 1 max uses (0 = unlimited), 2 retain-until, 3 now, 4 reserve (1/0), 5 has challenge
/// (1/0), 6 reservation id, 7 reservation expiry, 8 reservation record.
/// Returns 0 consumed, 1 replayed, 2 challenge gone.
const CONSUME_SCRIPT: &str = r"
local max = tonumber(ARGV[1])
local now = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '(' .. now)
if max > 0 then
  local spent = tonumber(redis.call('GET', KEYS[1]) or '0')
  if spent + redis.call('ZCARD', KEYS[2]) >= max then return 1 end
end
if ARGV[5] == '1' then
  if redis.call('EXISTS', KEYS[3]) == 0 then return 2 end
  if redis.call('EXISTS', KEYS[4]) == 1 then return 2 end
end
if ARGV[4] == '1' then
  local exp = tonumber(ARGV[7])
  redis.call('ZADD', KEYS[2], exp, ARGV[6])
  redis.call('EXPIREAT', KEYS[2], math.max(exp, tonumber(ARGV[2])))
  redis.call('SET', KEYS[5], ARGV[8], 'EXAT', exp)
  if ARGV[5] == '1' then redis.call('SET', KEYS[4], ARGV[6], 'EXAT', exp) end
else
  if max > 0 then
    redis.call('INCR', KEYS[1])
    redis.call('EXPIREAT', KEYS[1], ARGV[2])
  end
  if ARGV[5] == '1' then redis.call('DEL', KEYS[3]) end
end
return 0
";

/// Commits (ARGV[3] = 1) or releases a reservation, if it is still the one read.
///
/// KEYS: as [`CONSUME_SCRIPT`]. ARGV: 1 the record as read, 2 reservation id, 3 commit (1/0),
/// 4 max uses (0 = unlimited), 5 retain-until, 6 has challenge (1/0).
/// Returns 0 settled, 1 unknown.
const SETTLE_SCRIPT: &str = r"
local current = redis.call('GET', KEYS[5])
if not current or current ~= ARGV[1] then return 1 end
redis.call('DEL', KEYS[5])
redis.call('ZREM', KEYS[2], ARGV[2])
if ARGV[6] == '1' then redis.call('DEL', KEYS[4]) end
if ARGV[3] == '1' then
  if tonumber(ARGV[4]) > 0 then
    redis.call('INCR', KEYS[1])
    redis.call('EXPIREAT', KEYS[1], ARGV[5])
  end
  if ARGV[6] == '1' then redis.call('DEL', KEYS[3]) end
end
return 0
";

impl RedisStore {
	async fn connect(o: RedisOptions) -> Result<Self, StoreError> {
		let conn = match &o.topology {
			RedisTopology::Single { url } => {
				let client = redis::Client::open(url.as_str())?;
				Conn::Single(client.get_connection_manager().await?)
			},
			RedisTopology::Cluster { nodes } => {
				let client = redis::cluster::ClusterClient::new(nodes.iter().map(String::as_str))?;
				Conn::Cluster(client.get_async_connection().await?)
			},
			RedisTopology::Sentinel { sentinels, service } => {
				let client = redis::sentinel::SentinelClient::build(
					sentinels.iter().map(String::as_str).collect(),
					service.clone(),
					None,
					redis::sentinel::SentinelServerType::Master,
				)?;
				let s = SentinelConn {
					client: tokio::sync::Mutex::new(client),
					conn: tokio::sync::Mutex::new(None),
				};
				// Fail at startup, not on the first approval.
				s.connection().await?;
				Conn::Sentinel(Box::new(s))
			},
		};
		Ok(Self {
			conn,
			prefix: o.prefix,
			min_replica_acks: o.min_replica_acks,
			replica_ack_timeout_ms: o.replica_ack_timeout_ms,
		})
	}

	fn key(&self, kind: &str, id: &str) -> String {
		format!("{}{kind}:{id}", self.prefix)
	}

	/// The five keys the scripts touch for one use. Unused ones are named anyway, so every
	/// invocation declares the same shape; they share the prefix, and so the slot.
	fn keys(&self, jti: &str, challenge: Option<&str>, reservation: Option<&str>) -> [String; 5] {
		let ch = challenge.unwrap_or("");
		[
			self.key("jti", jti),
			self.key("pending", jti),
			self.key("chal", ch),
			self.key("chalres", ch),
			self.key("res", reservation.unwrap_or("")),
		]
	}

	/// `WAIT` for replicas to hold what was just written, when that is required.
	async fn durable(&self, slot_key: &str) -> Result<(), StoreError> {
		if self.min_replica_acks == 0 {
			return Ok(());
		}
		let acked: i64 = self
			.conn
			.query(
				redis::cmd("WAIT")
					.arg(self.min_replica_acks)
					.arg(self.replica_ack_timeout_ms),
				slot_key,
			)
			.await?;
		if acked < i64::from(self.min_replica_acks) {
			return Err(StoreError::Backend(format!(
				"only {acked} of {} required replicas confirmed the spend",
				self.min_replica_acks
			)));
		}
		Ok(())
	}

	async fn put_challenge(&self, id: &str, record: &ChallengeRecord) -> Result<(), StoreError> {
		let value = serde_json::to_string(record).map_err(|e| StoreError::Backend(e.to_string()))?;
		let key = self.key("chal", id);
		// NX: a challenge id is a fresh UUID, so a collision is a bug, never an overwrite.
		let set: Option<String> = self
			.conn
			.query(
				redis::cmd("SET")
					.arg(&key)
					.arg(value)
					.arg("EXAT")
					.arg(record.expires_at)
					.arg("NX"),
				&key,
			)
			.await?;
		match set {
			Some(_) => Ok(()),
			None => Err(StoreError::Backend(format!(
				"challenge {id} already exists"
			))),
		}
	}

	async fn get_challenge(&self, id: &str, now: u64) -> Result<Option<ChallengeRecord>, StoreError> {
		let key = self.key("chal", id);
		let value: Option<String> = self.conn.query(redis::cmd("GET").arg(&key), &key).await?;
		let Some(value) = value else { return Ok(None) };
		let record: ChallengeRecord =
			serde_json::from_str(&value).map_err(|e| StoreError::Backend(e.to_string()))?;
		// Redis expiry is to the second and lazy; the record's own expiry is authoritative.
		Ok((record.expires_at >= now).then_some(record))
	}

	async fn consume(&self, c: &Consume, now: u64) -> Result<ConsumeOutcome, StoreError> {
		let reservation_id = c.reservation.as_ref().map(|r| r.id.as_str());
		let keys = self.keys(&c.jti, c.challenge_id.as_deref(), reservation_id);
		let record = match &c.reservation {
			Some(r) => serde_json::to_string(&Reserved {
				jti: c.jti.clone(),
				challenge_id: c.challenge_id.clone(),
				retain_until: c.retain_until,
				max_uses: c.max_uses,
				expires_at: r.expires_at,
			})
			.map_err(|e| StoreError::Backend(e.to_string()))?,
			None => String::new(),
		};
		let mut cmd = redis::cmd("EVAL");
		cmd.arg(CONSUME_SCRIPT).arg(keys.len()).arg(&keys);
		cmd
			.arg(c.max_uses.unwrap_or(0))
			.arg(c.retain_until)
			.arg(now)
			.arg(u8::from(c.reservation.is_some()))
			.arg(u8::from(c.challenge_id.is_some()))
			.arg(reservation_id.unwrap_or(""))
			.arg(c.reservation.as_ref().map_or(0, |r| r.expires_at))
			.arg(record);
		let outcome: i64 = self.conn.query(&cmd, &keys[0]).await?;
		match outcome {
			0 => {
				self.durable(&keys[0]).await?;
				Ok(ConsumeOutcome::Consumed)
			},
			1 => Ok(ConsumeOutcome::Replayed),
			2 => Ok(ConsumeOutcome::ChallengeGone),
			n => Err(StoreError::Backend(format!("consume script returned {n}"))),
		}
	}

	async fn settle(&self, id: &str, commit: bool) -> Result<SettleOutcome, StoreError> {
		let res_key = self.key("res", id);
		let raw: Option<String> = self
			.conn
			.query(redis::cmd("GET").arg(&res_key), &res_key)
			.await?;
		let Some(raw) = raw else {
			return Ok(SettleOutcome::Unknown);
		};
		let r: Reserved = serde_json::from_str(&raw).map_err(|e| StoreError::Backend(e.to_string()))?;
		let keys = self.keys(&r.jti, r.challenge_id.as_deref(), Some(id));
		let mut cmd = redis::cmd("EVAL");
		cmd.arg(SETTLE_SCRIPT).arg(keys.len()).arg(&keys);
		cmd
			.arg(&raw)
			.arg(id)
			.arg(u8::from(commit))
			.arg(r.max_uses.unwrap_or(0))
			.arg(r.retain_until)
			.arg(u8::from(r.challenge_id.is_some()));
		let outcome: i64 = self.conn.query(&cmd, &keys[0]).await?;
		match outcome {
			0 => {
				if commit {
					self.durable(&keys[0]).await?;
				}
				Ok(SettleOutcome::Settled)
			},
			1 => Ok(SettleOutcome::Unknown),
			n => Err(StoreError::Backend(format!("settle script returned {n}"))),
		}
	}
}

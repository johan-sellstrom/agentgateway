//! The Redis store against a real `redis-server`. Ignored by default, since CI may have no
//! Redis: run them with `cargo test -p haps-guard -- --ignored` and `redis-server` on PATH.

use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

struct RedisServer {
	child: Child,
	url: String,
}

impl Drop for RedisServer {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// A throwaway Redis on a free port, with persistence off.
fn start_redis() -> RedisServer {
	let port = TcpListener::bind("127.0.0.1:0")
		.unwrap()
		.local_addr()
		.unwrap()
		.port();
	let child = Command::new("redis-server")
		.args([
			"--port",
			&port.to_string(),
			"--save",
			"",
			"--appendonly",
			"no",
		])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.expect("redis-server must be on PATH to run the ignored Redis tests");
	let deadline = Instant::now() + Duration::from_secs(10);
	while TcpStream::connect(("127.0.0.1", port)).is_err() {
		assert!(Instant::now() < deadline, "redis-server did not start");
		std::thread::sleep(Duration::from_millis(50));
	}
	RedisServer {
		child,
		url: format!("redis://127.0.0.1:{port}/"),
	}
}

async fn redis(server: &RedisServer, prefix: &str) -> StateStore {
	StateStore::redis(&server.url, prefix).await.unwrap()
}

#[tokio::test]
#[ignore = "needs redis-server on PATH"]
async fn the_redis_store_spends_a_jti_and_a_challenge_together_or_not_at_all() {
	let server = start_redis();
	let s = redis(&server, "t1:{haps}:").await;
	let gone = Consume {
		jti: "j1".into(),
		max_uses: Some(1),
		retain_until: unix_now() + 100,
		challenge_id: Some("never-issued".into()),
	};
	assert_eq!(
		s.consume(&gone, 0).await.unwrap(),
		ConsumeOutcome::ChallengeGone
	);
	let plain = Consume {
		challenge_id: None,
		..gone.clone()
	};
	assert_eq!(
		s.consume(&plain, 0).await.unwrap(),
		ConsumeOutcome::Consumed
	);
	assert_eq!(
		s.consume(&plain, 0).await.unwrap(),
		ConsumeOutcome::Replayed
	);

	let record = ChallengeRecord {
		tool: TOOL.into(),
		intent_hash: "sha256:x".into(),
		expires_at: unix_now() + 300,
	};
	s.put_challenge("c1", &record, 0).await.unwrap();
	assert_eq!(
		s.get_challenge("c1", 0).await.unwrap(),
		Some(record.clone())
	);
	// The challenge is outstanding but the jti is spent: neither is consumed.
	let both = Consume {
		challenge_id: Some("c1".into()),
		..gone.clone()
	};
	assert_eq!(s.consume(&both, 0).await.unwrap(), ConsumeOutcome::Replayed);
	assert!(s.get_challenge("c1", 0).await.unwrap().is_some());
	let fresh = Consume {
		jti: "j2".into(),
		..both
	};
	assert_eq!(
		s.consume(&fresh, 0).await.unwrap(),
		ConsumeOutcome::Consumed
	);
	assert_eq!(s.get_challenge("c1", 0).await.unwrap(), None);
	assert_eq!(
		s.consume(&fresh, 0).await.unwrap(),
		ConsumeOutcome::Replayed
	);
	// A challenge id is never overwritten.
	s.put_challenge("c2", &record, 0).await.unwrap();
	assert!(s.put_challenge("c2", &record, 0).await.is_err());
}

#[tokio::test]
#[ignore = "needs redis-server on PATH"]
async fn concurrent_spends_of_one_approval_succeed_exactly_once() {
	let server = start_redis();
	let s = Arc::new(redis(&server, "t2:{haps}:").await);
	let tasks: Vec<_> = (0..32)
		.map(|_| {
			let s = s.clone();
			tokio::spawn(async move {
				let c = Consume {
					jti: "contended".into(),
					max_uses: Some(1),
					retain_until: unix_now() + 100,
					challenge_id: None,
				};
				s.consume(&c, 0).await.unwrap()
			})
		})
		.collect();
	let mut consumed = 0;
	for t in tasks {
		if t.await.unwrap() == ConsumeOutcome::Consumed {
			consumed += 1;
		}
	}
	assert_eq!(consumed, 1);
}

/// Two replicas of the guard behind a load balancer, sharing one Redis: what one accepts the
/// other treats as spent, and a challenge one issues the other can accept, once.
#[tokio::test]
#[ignore = "needs redis-server on PATH"]
async fn replicas_sharing_redis_share_replay_and_challenge_state() {
	let server = start_redis();
	let w = World::new();
	// Real time: Redis expires keys by the wall clock, so the clock the guard checks against
	// must be the same one. The credential and intent are built for now.
	let now = unix_now();
	let fresh = |mut i: Value| {
		i["constraints"]["expiresAt"] = json!(rfc3339(now + 120));
		i
	};
	let fresh_claims = |intent: &Value| {
		let mut c = w.claims_for(intent);
		c["iat"] = json!(now);
		c["nbf"] = json!(now);
		c["exp"] = json!(now + 120);
		c
	};

	let a = Guard::new(
		w.config(policy("HAPS-PoHP-2")),
		redis(&server, "t3:{haps}:").await,
	);
	let b = Guard::new(
		w.config(policy("HAPS-PoHP-2")),
		redis(&server, "t3:{haps}:").await,
	);
	let i = fresh(intent());
	let params = call(
		TOOL,
		approved_arguments(),
		Some(meta_for(&w.sign(&fresh_claims(&i)), &i, None)),
	);
	assert!(is_approved(&check(&a, &params, now).await));
	assert_eq!(denied(check(&b, &params, now).await), Denial::Replayed);

	let a = Guard::new(
		w.config(challenge_policy()),
		redis(&server, "t4:{haps}:").await,
	);
	let b = Guard::new(
		w.config(challenge_policy()),
		redis(&server, "t4:{haps}:").await,
	);
	let args = approved_arguments();
	let ch = challenge_for(&a, &args, now).await;
	let intent = ch["actionIntent"].clone();
	let answered = |jti: &str| {
		let c = with(
			with(
				fresh_claims(&intent),
				"challengeId",
				ch["challengeId"].clone(),
			),
			"jti",
			json!(jti),
		);
		call(
			TOOL,
			args.clone(),
			Some(meta_for(&w.sign(&c), &intent, None)),
		)
	};
	assert!(is_approved(&check(&b, &answered("jti-r1"), now).await));
	assert_eq!(
		denied(check(&a, &answered("jti-r2"), now).await),
		Denial::ChallengeUnknown
	);
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
}

fn rfc3339(t: u64) -> String {
	DateTime::from_timestamp(t as i64, 0)
		.unwrap()
		.to_rfc3339_opts(SecondsFormat::Secs, true)
}

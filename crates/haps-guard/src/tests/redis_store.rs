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
	_dir: tempfile::TempDir,
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
	let dir = tempfile::tempdir().unwrap();
	let child = Command::new("redis-server")
		.current_dir(dir.path())
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
		_dir: dir,
	}
}

async fn redis(server: &RedisServer, prefix: &str) -> StateStore {
	StateStore::redis(RedisOptions {
		topology: RedisTopology::Single {
			url: server.url.clone(),
		},
		prefix: prefix.to_owned(),
		min_replica_acks: 0,
		replica_ack_timeout_ms: 200,
	})
	.await
	.unwrap()
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
		reservation: None,
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
					reservation: None,
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

// ------------------------------------------------------------------ topologies

#[tokio::test]
#[ignore = "needs redis-server on PATH"]
async fn a_single_redis_keeps_the_reservation_contract() {
	let server = start_redis();
	reservation_contract(&redis(&server, "t5:{haps}:").await, unix_now()).await;
}

/// Local Redis processes in a scratch directory, killed on drop.
struct Procs {
	children: Vec<Child>,
	_dir: tempfile::TempDir,
}

impl Drop for Procs {
	fn drop(&mut self) {
		for c in &mut self.children {
			let _ = c.kill();
			let _ = c.wait();
		}
	}
}

/// A free port below 40000: a Cluster node also listens on its port + 10000.
fn free_port() -> u16 {
	use std::sync::atomic::{AtomicU16, Ordering};
	static NEXT: AtomicU16 = AtomicU16::new(0);
	let start = 20_000 + (std::process::id() % 10_000) as u16;
	loop {
		let p = start + NEXT.fetch_add(1, Ordering::Relaxed) % 10_000;
		if TcpListener::bind(("127.0.0.1", p)).is_ok()
			&& TcpListener::bind(("127.0.0.1", p + 10_000)).is_ok()
		{
			return p;
		}
	}
}

/// Started in `dir`: Redis writes files to its working directory (a replica writes an RDB
/// during full sync even with saving off), and a later run must never load them.
fn spawn(program: &str, args: &[&str], dir: &std::path::Path) -> Child {
	Command::new(program)
		.current_dir(dir)
		.args(args)
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.unwrap_or_else(|e| panic!("{program} must be on PATH: {e}"))
}

fn wait_for_port(port: u16) {
	let deadline = Instant::now() + Duration::from_secs(10);
	while TcpStream::connect(("127.0.0.1", port)).is_err() {
		assert!(Instant::now() < deadline, "nothing listening on {port}");
		std::thread::sleep(Duration::from_millis(50));
	}
}

fn cli(port: u16, args: &[&str]) -> String {
	let out = Command::new("redis-cli")
		.args(["-p", &port.to_string()])
		.args(args)
		.output()
		.expect("redis-cli must be on PATH");
	String::from_utf8_lossy(&out.stdout).into_owned()
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(30);
	while !ok() {
		assert!(Instant::now() < deadline, "timed out waiting for {what}");
		std::thread::sleep(Duration::from_millis(100));
	}
}

/// A three-shard Redis Cluster with no replicas.
fn start_cluster() -> (Procs, Vec<u16>) {
	let dir = tempfile::tempdir().unwrap();
	let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
	let children = ports
		.iter()
		.map(|p| {
			let p = p.to_string();
			let conf = format!("nodes-{p}.conf");
			spawn(
				"redis-server",
				&[
					"--port",
					&p,
					"--cluster-enabled",
					"yes",
					"--cluster-config-file",
					&conf,
					"--save",
					"",
					"--appendonly",
					"no",
					"--dir",
					dir.path().to_str().unwrap(),
				],
				dir.path(),
			)
		})
		.collect();
	for p in &ports {
		wait_for_port(*p);
	}
	let nodes: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
	let status = Command::new("redis-cli")
		.args(["--cluster", "create"])
		.args(&nodes)
		.args(["--cluster-replicas", "0", "--cluster-yes"])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.unwrap();
	assert!(status.success(), "redis-cli --cluster create failed");
	for p in &ports {
		wait_until("the cluster to agree", || {
			cli(*p, &["cluster", "info"]).contains("cluster_state:ok")
		});
	}
	(
		Procs {
			children,
			_dir: dir,
		},
		ports,
	)
}

fn cluster_options(ports: &[u16], prefix: &str) -> RedisOptions {
	RedisOptions {
		topology: RedisTopology::Cluster {
			nodes: ports
				.iter()
				.map(|p| format!("redis://127.0.0.1:{p}/"))
				.collect(),
		},
		prefix: prefix.into(),
		min_replica_acks: 0,
		replica_ack_timeout_ms: 200,
	}
}

#[tokio::test]
#[ignore = "needs redis-server and redis-cli on PATH"]
async fn a_redis_cluster_keeps_the_reservation_contract() {
	let (_procs, ports) = start_cluster();
	let s = StateStore::redis(cluster_options(&ports, "t6:{haps}:"))
		.await
		.unwrap();
	reservation_contract(&s, unix_now()).await;
}

#[tokio::test]
#[ignore = "needs redis-server and redis-cli on PATH"]
async fn on_a_cluster_the_hash_tag_is_what_lets_one_script_spend_together() {
	// Negative control for the `{hash tag}` the config requires: without it a jti and a
	// challenge hash to different shards, and Redis refuses the script outright.
	let (_procs, ports) = start_cluster();
	let s = StateStore::redis(cluster_options(&ports, "untagged:"))
		.await
		.unwrap();
	let record = ChallengeRecord {
		tool: TOOL.into(),
		intent_hash: "sha256:x".into(),
		expires_at: unix_now() + 300,
	};
	s.put_challenge("c-untagged", &record, 0).await.unwrap();
	let c = Consume {
		jti: "j-untagged".into(),
		max_uses: Some(1),
		retain_until: unix_now() + 100,
		challenge_id: Some("c-untagged".into()),
		reservation: None,
	};
	let err = s
		.consume(&c, unix_now())
		.await
		.expect_err("cross-slot script");
	assert!(err.to_string().to_lowercase().contains("slot"), "{err}");
}

/// A primary, one replica, and one Sentinel watching them as `mymaster`.
fn start_sentinel() -> (Procs, u16, u16, u16) {
	let dir = tempfile::tempdir().unwrap();
	let (primary, replica, sentinel) = (free_port(), free_port(), free_port());
	let base = ["--save", "", "--appendonly", "no"];
	let mut children = vec![spawn(
		"redis-server",
		&[&["--port", &primary.to_string()][..], &base].concat(),
		dir.path(),
	)];
	wait_for_port(primary);
	children.push(spawn(
		"redis-server",
		&[
			&[
				"--port",
				&replica.to_string(),
				"--replicaof",
				"127.0.0.1",
				&primary.to_string(),
			][..],
			&base,
		]
		.concat(),
		dir.path(),
	));
	wait_for_port(replica);
	wait_until("the replica to sync", || {
		cli(replica, &["info", "replication"]).contains("master_link_status:up")
	});
	let conf = dir.path().join("sentinel.conf");
	std::fs::write(
		&conf,
		format!(
			"port {sentinel}\nsentinel monitor mymaster 127.0.0.1 {primary} 1\nsentinel down-after-milliseconds mymaster 1000\nsentinel failover-timeout mymaster 5000\n"
		),
	)
	.unwrap();
	children.push(spawn(
		"redis-sentinel",
		&[conf.to_str().unwrap()],
		dir.path(),
	));
	wait_for_port(sentinel);
	wait_until("the sentinel to see the replica", || {
		cli(sentinel, &["sentinel", "replicas", "mymaster"]).contains(&replica.to_string())
	});
	(
		Procs {
			children,
			_dir: dir,
		},
		primary,
		replica,
		sentinel,
	)
}

fn current_primary(sentinel: u16) -> String {
	cli(
		sentinel,
		&["sentinel", "get-master-addr-by-name", "mymaster"],
	)
}

fn sentinel_options(sentinel: u16, acks: u32) -> RedisOptions {
	RedisOptions {
		topology: RedisTopology::Sentinel {
			sentinels: vec![format!("redis://127.0.0.1:{sentinel}/")],
			service: "mymaster".into(),
		},
		prefix: "t7:{haps}:".into(),
		min_replica_acks: acks,
		replica_ack_timeout_ms: 2000,
	}
}

#[tokio::test]
#[ignore = "needs redis-server and redis-sentinel on PATH"]
async fn a_spend_confirmed_by_a_replica_survives_failover() {
	let (_procs, primary, replica, sentinel) = start_sentinel();
	let s = StateStore::redis(sentinel_options(sentinel, 1))
		.await
		.unwrap();
	let spend = |jti: &str| Consume {
		jti: jti.into(),
		max_uses: Some(1),
		retain_until: unix_now() + 600,
		challenge_id: None,
		reservation: None,
	};
	assert_eq!(
		s.consume(&spend("before"), unix_now()).await.unwrap(),
		ConsumeOutcome::Consumed
	);

	// Promote the replica. The store's connection now points at a demoted, read-only node.
	assert!(current_primary(sentinel).contains(&primary.to_string()));
	// Sentinel refuses a failover until it has judged the replica eligible; keep asking.
	wait_until("the sentinel to accept a failover", || {
		cli(sentinel, &["sentinel", "failover", "mymaster"]).starts_with("OK")
	});
	wait_until("the failover", || {
		current_primary(sentinel).contains(&replica.to_string())
			&& cli(replica, &["role"]).starts_with("master")
	});
	// The demoted node must also be following the new primary before WAIT can be satisfied.
	wait_until("the old primary to follow", || {
		cli(primary, &["info", "replication"]).contains("master_link_status:up")
	});

	// The spend made before failover is still spent on the new primary.
	assert_eq!(
		s.consume(&spend("before"), unix_now()).await.unwrap(),
		ConsumeOutcome::Replayed
	);
	// And new spends land on the new primary.
	assert_eq!(
		s.consume(&spend("after"), unix_now()).await.unwrap(),
		ConsumeOutcome::Consumed
	);
	reservation_contract(&s, unix_now()).await;
}

#[tokio::test]
#[ignore = "needs redis-server on PATH"]
async fn a_spend_no_replica_confirms_fails_closed() {
	// A lone node has no replica to confirm the spend, so a guard requiring one refuses rather
	// than approve on a record a failover could lose.
	let server = start_redis();
	let s = StateStore::redis(RedisOptions {
		topology: RedisTopology::Single {
			url: server.url.clone(),
		},
		prefix: "t8:{haps}:".into(),
		min_replica_acks: 1,
		replica_ack_timeout_ms: 100,
	})
	.await
	.unwrap();
	let c = Consume {
		jti: "lonely".into(),
		max_uses: Some(1),
		retain_until: unix_now() + 100,
		challenge_id: None,
		reservation: None,
	};
	let err = s
		.consume(&c, unix_now())
		.await
		.expect_err("no replica confirmed");
	assert!(err.to_string().contains("0 of 1"), "{err}");
}

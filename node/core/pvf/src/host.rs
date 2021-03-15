// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

use crate::{
	Priority, Pvf,
	artifacts::{Artifacts, ArtifactState, ArtifactId},
	execute, prepare,
};
use std::{
	collections::{HashMap, hash_map::Entry},
	time::{Duration, SystemTime},
};
use async_std::{
	path::{Path, PathBuf},
	sync::Mutex,
};
use polkadot_parachain::{primitives::ValidationResult, wasm_executor::ValidationError};
use futures::{
	Future, FutureExt, SinkExt, StreamExt,
	channel::{mpsc, oneshot},
};

pub struct ValidationHost {
	from_handle_tx: Mutex<mpsc::Sender<FromHandle>>,
}

impl ValidationHost {
	pub async fn execute_pvf(
		&self,
		pvf: Pvf,
		params: Vec<u8>,
		priority: Priority,
		result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
	) -> Result<(), String> {
		self.from_handle_tx
			.lock()
			.await
			.send(FromHandle::ExecutePvf {
				pvf,
				params,
				priority,
				result_tx,
			})
			.await
			.map_err(|_| format!("the inner loop hung up"))
	}

	pub async fn heads_up(&self, active_pvfs: Vec<Pvf>) -> Result<(), String> {
		self.from_handle_tx
			.lock()
			.await
			.send(FromHandle::HeadsUp { active_pvfs })
			.await
			.map_err(|_| format!("the inner loop hung up"))
	}
}

enum FromHandle {
	ExecutePvf {
		pvf: Pvf,
		params: Vec<u8>,
		priority: Priority,
		result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
	},
	HeadsUp {
		active_pvfs: Vec<Pvf>,
	},
}

pub struct Config {
	pub cache_path: PathBuf,
	pub prepare_worker_program_path: PathBuf,
	pub prepare_workers_soft_max_num: usize,
	pub prepare_workers_hard_max_num: usize,
	pub execute_worker_program_path: PathBuf,
	pub execute_workers_max_num: usize,
}

impl Config {
	pub fn new(cache_path: PathBuf, program_path: PathBuf) -> Self {
		Self {
			cache_path,
			prepare_worker_program_path: program_path.clone(),
			prepare_workers_soft_max_num: 8,
			prepare_workers_hard_max_num: 5,
			execute_worker_program_path: program_path,
			execute_workers_max_num: 5,
		}
	}
}

pub fn start(config: Config) -> (ValidationHost, impl Future<Output = ()>) {
	let (from_handle_tx, from_handle_rx) = mpsc::channel(10);

	let validation_host = ValidationHost {
		from_handle_tx: Mutex::new(from_handle_tx),
	};

	let (to_prepare_pool, from_prepare_pool, run_prepare_pool) =
		prepare::start_pool(config.prepare_worker_program_path.to_owned());

	let (to_prepare_queue_tx, from_prepare_queue_rx, run_prepare_queue) = prepare::start_queue(
		config.prepare_workers_soft_max_num,
		config.prepare_workers_hard_max_num,
		config.cache_path.clone(),
		to_prepare_pool,
		from_prepare_pool,
	);

	let (to_execute_queue_tx, run_execute_queue) = execute::start(
		config.execute_worker_program_path.to_owned(),
		config.execute_workers_max_num,
	);

	let (to_sweeper_tx, to_sweeper_rx) = mpsc::channel(100);
	let run_sweeper = sweeper_task(to_sweeper_rx);

	let run = async move {
		let artifacts = Artifacts::new(&config.cache_path).await;

		futures::pin_mut!(
			run_prepare_queue,
			run_prepare_pool,
			run_execute_queue,
			run_sweeper
		);

		run(
			Inner {
				cache_path: config.cache_path,
				cleanup_pulse_interval: Duration::from_secs(3600),
				artifact_ttl: Duration::from_secs(3600 * 24),
				artifacts,
				from_handle_rx,
				to_prepare_queue_tx,
				from_prepare_queue_rx,
				to_execute_queue_tx,
				to_sweeper_tx,
				awaiting_prepare: HashMap::new(),
			},
			run_prepare_pool,
			run_prepare_queue,
			run_execute_queue,
			run_sweeper,
		)
		.await
	};

	(validation_host, run)
}

#[derive(Debug)]
struct PendingExecutionRequest {
	params: Vec<u8>,
	result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
}

struct Inner {
	cache_path: PathBuf,
	cleanup_pulse_interval: Duration,
	artifact_ttl: Duration,
	artifacts: Artifacts,

	from_handle_rx: mpsc::Receiver<FromHandle>,

	to_prepare_queue_tx: mpsc::Sender<prepare::ToQueue>,
	from_prepare_queue_rx: mpsc::UnboundedReceiver<prepare::FromQueue>,

	to_execute_queue_tx: mpsc::Sender<execute::ToQueue>,
	to_sweeper_tx: mpsc::Sender<PathBuf>,

	awaiting_prepare: HashMap<ArtifactId, Vec<PendingExecutionRequest>>,
}

#[derive(Debug)]
struct Fatal;

async fn run(
	Inner {
		cache_path,
		cleanup_pulse_interval,
		artifact_ttl,
		mut artifacts,
		from_handle_rx,
		from_prepare_queue_rx,
		mut to_prepare_queue_tx,
		mut to_execute_queue_tx,
		mut to_sweeper_tx,
		mut awaiting_prepare,
	}: Inner,
	prepare_pool: impl Future<Output = ()> + Unpin,
	prepare_queue: impl Future<Output = ()> + Unpin,
	execute_queue: impl Future<Output = ()> + Unpin,
	sweeper: impl Future<Output = ()> + Unpin,
) {
	macro_rules! break_if_fatal {
		($expr:expr) => {
			match $expr {
				Err(Fatal) => break,
				Ok(v) => v,
			}
		};
	}

	let cleanup_pulse = pulse_every(cleanup_pulse_interval).fuse();
	futures::pin_mut!(cleanup_pulse);

	let mut from_handle_rx = from_handle_rx.fuse();
	let mut from_prepare_queue_rx = from_prepare_queue_rx.fuse();

	// Make sure that the task-futures are fused.
	let mut prepare_queue = prepare_queue.fuse();
	let mut prepare_pool = prepare_pool.fuse();
	let mut execute_queue = execute_queue.fuse();
	let mut sweeper = sweeper.fuse();

	loop {
		futures::select_biased! {
			_ = prepare_queue => {
				panic!()
			},
			_ = prepare_pool => {
				panic!()
			},
			_ = execute_queue => {
				panic!()
			},
			_ = sweeper => {
				panic!()
			},
			() = cleanup_pulse.select_next_some() => {
				break_if_fatal!(handle_cleanup_pulse(
					&mut to_sweeper_tx,
					&mut artifacts,
					&artifact_ttl,
				).await);
			},
			from_handle = from_handle_rx.next() => {
				let from_handle = break_if_fatal!(from_handle.ok_or(Fatal));

				break_if_fatal!(handle_from_handle(
					&mut artifacts,
					&mut to_prepare_queue_tx,
					&mut to_execute_queue_tx,
					&mut awaiting_prepare,
					from_handle,
				)
				.await);
			},
			from_prepare_queue = from_prepare_queue_rx.next() => {
				let prepare::FromQueue::Prepared(artifact_id)
					= break_if_fatal!(from_prepare_queue.ok_or(Fatal));

				// Note that preparation always succeeds.
				//
				// That's because the error conditions are written into the artifact and will be
				// reported at the time of the  execution. It potentially, but not necessarily,
				// can be scheduled as a result of this function call, in case there are pending
				// executions.
				//
				// We could be eager in terms of reporting and plumb the result from the prepartion
				// worker but we don't for the sake of simplicity.
				break_if_fatal!(handle_prepare_done(
					&cache_path,
					&mut artifacts,
					&mut to_execute_queue_tx,
					&mut awaiting_prepare,
					artifact_id,
				).await);
			},
		}
	}
}

async fn handle_from_handle(
	artifacts: &mut Artifacts,
	prepare_queue: &mut mpsc::Sender<prepare::ToQueue>,
	execute_queue: &mut mpsc::Sender<execute::ToQueue>,
	awaiting_prepare: &mut HashMap<ArtifactId, Vec<PendingExecutionRequest>>,
	from_handle: FromHandle,
) -> Result<(), Fatal> {
	match from_handle {
		FromHandle::ExecutePvf {
			pvf,
			params,
			priority,
			result_tx,
		} => {
			handle_execute_pvf(
				artifacts,
				prepare_queue,
				execute_queue,
				awaiting_prepare,
				pvf,
				params,
				priority,
				result_tx,
			)
			.await?;
		}
		FromHandle::HeadsUp { active_pvfs } => {
			handle_heads_up(artifacts, prepare_queue, active_pvfs).await?;
		}
	}

	Ok(())
}

async fn handle_execute_pvf(
	artifacts: &mut Artifacts,
	prepare_queue: &mut mpsc::Sender<prepare::ToQueue>,
	execute_queue: &mut mpsc::Sender<execute::ToQueue>,
	awaiting_prepare: &mut HashMap<ArtifactId, Vec<PendingExecutionRequest>>,
	pvf: Pvf,
	params: Vec<u8>,
	priority: Priority,
	result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
) -> Result<(), Fatal> {
	let artifact_id = pvf.to_artifact_id();

	match artifacts.artifacts.entry(artifact_id.clone()) {
		Entry::Occupied(mut o) => match *o.get_mut() {
			ArtifactState::Prepared {
				ref artifact_path, ..
			} => {
				// TODO: Update the last needed
				execute_queue
					.send(execute::ToQueue::Enqueue {
						artifact_path: artifact_path.clone(),
						params,
						result_tx,
					})
					.await
					.map_err(|_| Fatal)?;
			}
			ArtifactState::Preparing => {
				prepare_queue
					.send(prepare::ToQueue::Amend {
						priority,
						artifact_id: pvf.to_artifact_id(),
					})
					.await
					.map_err(|_| Fatal)?;

				awaiting_prepare
					.entry(artifact_id)
					.or_default()
					.push(PendingExecutionRequest { params, result_tx });
			}
		},
		Entry::Vacant(v) => {
			prepare_queue
				.send(prepare::ToQueue::Enqueue { priority, pvf })
				.await
				.map_err(|_| Fatal)?;

			v.insert(ArtifactState::Preparing);
			awaiting_prepare
				.entry(artifact_id)
				.or_default()
				.push(PendingExecutionRequest { params, result_tx });
		}
	}

	Ok(())
}

async fn handle_heads_up(
	artifacts: &mut Artifacts,
	prepare_queue: &mut mpsc::Sender<prepare::ToQueue>,
	active_pvfs: Vec<Pvf>,
) -> Result<(), Fatal> {
	let now = SystemTime::now();

	for active_pvf in active_pvfs {
		let artifact_id = active_pvf.to_artifact_id();
		match artifacts.artifacts.entry(artifact_id.clone()) {
			Entry::Occupied(mut o) => {
				match o.get_mut() {
					ArtifactState::Prepared {
						last_time_needed, ..
					} => {
						*last_time_needed = now.clone();
					}
					ArtifactState::Preparing => {
						// Already preparing. We don't need to send a priority amend either because
						// it can't get any lower than the background.
					}
				}
			}
			Entry::Vacant(v) => {
				v.insert(ArtifactState::Preparing);

				prepare_queue
					.send(prepare::ToQueue::Enqueue {
						priority: Priority::Background,
						pvf: active_pvf,
					})
					.await
					.map_err(|_| Fatal)?;
			}
		}
	}

	Ok(())
}

async fn handle_prepare_done(
	cache_path: &Path,
	artifacts: &mut Artifacts,
	execute_queue: &mut mpsc::Sender<execute::ToQueue>,
	awaiting_prepare: &mut HashMap<ArtifactId, Vec<PendingExecutionRequest>>,
	artifact_id: ArtifactId,
) -> Result<(), Fatal> {
	let artifact_path = artifact_id.path(&cache_path);
	let artifact_state = artifacts.artifacts.remove(&artifact_id).unwrap(); // TODO:
	match artifact_state {
		ArtifactState::Preparing => {
			let pending_requests = awaiting_prepare.remove(&artifact_id).unwrap_or_default();
			for PendingExecutionRequest { params, result_tx } in pending_requests {
				execute_queue
					.send(execute::ToQueue::Enqueue {
						artifact_path: artifact_path.clone(),
						params,
						result_tx,
					})
					.await
					.map_err(|_| Fatal)?;
			}
		}
		_ => panic!(), // TODO:
	}

	artifacts.artifacts.insert(
		artifact_id,
		ArtifactState::Prepared {
			last_time_needed: SystemTime::now(),
			artifact_path,
		},
	);

	Ok(())
}

async fn handle_cleanup_pulse(
	sweeper_tx: &mut mpsc::Sender<PathBuf>,
	artifacts: &mut Artifacts,
	artifact_ttl: &Duration,
) -> Result<(), Fatal> {
	let now = std::time::SystemTime::now();

	let mut to_remove = vec![];
	for (k, v) in artifacts.artifacts.iter() {
		if let ArtifactState::Prepared {
			last_time_needed, ..
		} = *v
		{
			if now
				.duration_since(last_time_needed)
				.map(|age| age > *artifact_ttl)
				.unwrap_or(false)
			{
				to_remove.push(dbg!(k.clone()));
			}
		}
	}

	for k in to_remove {
		let (_, artifact_path) = artifacts
			.artifacts
			.remove(&k)
			.expect("k is from to_remove; to_remove is based on the actual kv pairs; qed")
			.into_prepared()
			.expect("k is from to_remove; to_remove consists of prepared artifacts; qed");

		sweeper_tx.send(artifact_path).await.map_err(|_| Fatal)?;
	}

	Ok(())
}

/// A simple task which sole purpose is to delete files thrown at it.
async fn sweeper_task(mut sweeper_rx: mpsc::Receiver<PathBuf>) {
	loop {
		match sweeper_rx.next().await {
			None => break,
			Some(condemned) => {
				let _ = async_std::fs::remove_file(condemned).await;
			}
		}
	}
}

/// A stream that yields a pulse continuously at a given interval.
fn pulse_every(interval: std::time::Duration) -> impl futures::Stream<Item = ()> {
	futures::stream::unfold(interval, {
		|interval| async move {
			futures_timer::Delay::new(interval).await;
			Some(((), interval))
		}
	})
	.map(|_| ())
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures::future::BoxFuture;
	use assert_matches::assert_matches;

	#[async_std::test]
	async fn pulse_test() {
		let pulse = pulse_every(Duration::from_millis(100));
		futures::pin_mut!(pulse);

		for _ in 0usize..5usize {
			let start = std::time::Instant::now();
			let _ = pulse.next().await.unwrap();

			let el = start.elapsed().as_millis();
			assert!(el > 50 && el < 150, "{}", el);
		}
	}

	/// Creates a new pvf which artifact id can be uniquely identified by the given number.
	fn artifact_id(descriminator: u32) -> ArtifactId {
		Pvf::from_discriminator(descriminator).to_artifact_id()
	}

	fn artifact_path(descriminator: u32) -> PathBuf {
		artifact_id(descriminator)
			.path(&PathBuf::from(std::env::temp_dir()))
			.to_owned()
	}

	struct Builder {
		cleanup_pulse_interval: Duration,
		artifact_ttl: Duration,
		artifacts: Artifacts,
	}

	impl Builder {
		fn default() -> Self {
			Self {
				// these are selected high to not interfere in tests in which pruning is irrelevant.
				cleanup_pulse_interval: Duration::from_secs(3600),
				artifact_ttl: Duration::from_secs(3600),

				artifacts: Artifacts::empty(),
			}
		}

		fn build(self) -> Test {
			Test::new(self)
		}
	}

	struct Test {
		from_handle_tx: Option<mpsc::Sender<FromHandle>>,

		to_prepare_queue_rx: mpsc::Receiver<prepare::ToQueue>,
		from_prepare_queue_tx: mpsc::UnboundedSender<prepare::FromQueue>,
		to_execute_queue_rx: mpsc::Receiver<execute::ToQueue>,
		to_sweeper_rx: mpsc::Receiver<PathBuf>,

		run: BoxFuture<'static, ()>,
	}

	impl Test {
		fn new(
			Builder {
				cleanup_pulse_interval,
				artifact_ttl,
				artifacts,
			}: Builder,
		) -> Self {
			let cache_path = PathBuf::from(std::env::temp_dir());

			let (from_handle_tx, from_handle_rx) = mpsc::channel(10);
			let (to_prepare_queue_tx, to_prepare_queue_rx) = mpsc::channel(10);
			let (from_prepare_queue_tx, from_prepare_queue_rx) = mpsc::unbounded();
			let (to_execute_queue_tx, to_execute_queue_rx) = mpsc::channel(10);
			let (to_sweeper_tx, to_sweeper_rx) = mpsc::channel(10);

			let mk_dummy_loop = || std::future::pending().boxed();

			let run = run(
				Inner {
					cache_path,
					cleanup_pulse_interval,
					artifact_ttl,
					artifacts,
					from_handle_rx,
					to_prepare_queue_tx,
					from_prepare_queue_rx,
					to_execute_queue_tx,
					to_sweeper_tx,
					awaiting_prepare: HashMap::new(),
				},
				mk_dummy_loop(),
				mk_dummy_loop(),
				mk_dummy_loop(),
				mk_dummy_loop(),
			)
			.boxed();

			Self {
				from_handle_tx: Some(from_handle_tx),
				to_prepare_queue_rx,
				from_prepare_queue_tx,
				to_execute_queue_rx,
				to_sweeper_rx,
				run,
			}
		}

		fn host_handle(&mut self) -> ValidationHost {
			let tx = self.from_handle_tx.take().unwrap();
			ValidationHost {
				from_handle_tx: Mutex::new(tx),
			}
		}
	}

	async fn run_until<R>(
		task: &mut (impl Future<Output = ()> + Unpin),
		mut fut: (impl Future<Output = R> + Unpin),
	) -> R {
		use std::task::Poll;

		let start = std::time::Instant::now();
		let fut = &mut fut;
		loop {
			if start.elapsed() > std::time::Duration::from_secs(2) {
				// We expect that this will take only a couple of iterations and thus to take way
				// less than a second.
				panic!("timeout");
			}

			if let Poll::Ready(r) = futures::poll!(&mut *fut) {
				break r;
			}

			if futures::poll!(&mut *task).is_ready() {
				panic!()
			}
		}
	}

	#[async_std::test]
	async fn shutdown_on_handle_drop() {
		let test = Builder::default().build();

		let join_handle = async_std::task::spawn(test.run);

		// Dropping the handle will lead to conclusion of the read part and thus will make the event
		// loop to stop, which in turn will resolve the join handle.
		drop(test.from_handle_tx);
		join_handle.await;
	}

	#[async_std::test]
	async fn pruning() {
		let mock_now = SystemTime::now() - Duration::from_millis(1000);

		let mut builder = Builder::default();
		builder.cleanup_pulse_interval = Duration::from_millis(100);
		builder.artifact_ttl = Duration::from_millis(500);
		builder.artifacts.artifacts.insert(
			artifact_id(1),
			ArtifactState::Prepared {
				last_time_needed: mock_now,
				artifact_path: artifact_path(1),
			},
		);
		builder.artifacts.artifacts.insert(
			artifact_id(2),
			ArtifactState::Prepared {
				last_time_needed: mock_now,
				artifact_path: artifact_path(2),
			},
		);
		let mut test = builder.build();
		let host = test.host_handle();

		host.heads_up(vec![Pvf::from_discriminator(1)])
			.now_or_never()
			.unwrap()
			.unwrap();

		let to_sweeper_rx = &mut test.to_sweeper_rx;
		run_until(
			&mut test.run,
			async {
				assert_eq!(to_sweeper_rx.next().await.unwrap(), artifact_path(2));
			}
			.boxed(),
		)
		.await;
	}

	#[async_std::test]
	async fn amending_priority() {
		let mut test = Builder::default().build();
		let host = test.host_handle();

		host.heads_up(vec![Pvf::from_discriminator(1)])
			.now_or_never()
			.unwrap()
			.unwrap();

		// Run until we receive a prepare request.
		let prepare_q_rx = &mut test.to_prepare_queue_rx;
		run_until(
			&mut test.run,
			async {
				assert_matches!(
					prepare_q_rx.next().await.unwrap(),
					prepare::ToQueue::Enqueue { .. }
				);
			}
			.boxed(),
		)
		.await;

		let (result_tx, _result_rx) = oneshot::channel();
		host.execute_pvf(
			Pvf::from_discriminator(1),
			vec![],
			Priority::Critical,
			result_tx,
		)
		.now_or_never()
		.unwrap()
		.unwrap();

		run_until(
			&mut test.run,
			async {
				assert_matches!(
					prepare_q_rx.next().await.unwrap(),
					prepare::ToQueue::Amend { .. }
				);
			}
			.boxed(),
		)
		.await;
	}

	#[async_std::test]
	async fn execute_pvf_requests() {
		use polkadot_parachain::wasm_executor::InvalidCandidate;

		let mut test = Builder::default().build();
		let host = test.host_handle();

		let (result_tx, result_rx_pvf_1_1) = oneshot::channel();
		host.execute_pvf(
			Pvf::from_discriminator(1),
			b"pvf1".to_vec(),
			Priority::Normal,
			result_tx,
		)
		.await
		.unwrap();

		let (result_tx, result_rx_pvf_1_2) = oneshot::channel();
		host.execute_pvf(
			Pvf::from_discriminator(1),
			b"pvf1".to_vec(),
			Priority::Critical,
			result_tx,
		)
		.await
		.unwrap();

		let (result_tx, result_rx_pvf_2) = oneshot::channel();
		host.execute_pvf(
			Pvf::from_discriminator(2),
			b"pvf1".to_vec(),
			Priority::Normal,
			result_tx,
		)
		.await
		.unwrap();

		let prepare_q_rx = &mut test.to_prepare_queue_rx;
		run_until(
			&mut test.run,
			async {
				assert_matches!(
					prepare_q_rx.next().await.unwrap(),
					prepare::ToQueue::Enqueue { .. }
				);
				assert_matches!(
					prepare_q_rx.next().await.unwrap(),
					prepare::ToQueue::Amend { .. }
				);
				assert_matches!(
					prepare_q_rx.next().await.unwrap(),
					prepare::ToQueue::Enqueue { .. }
				);
			}
			.boxed(),
		)
		.await;

		test.from_prepare_queue_tx
			.send(prepare::FromQueue::Prepared(artifact_id(1)))
			.await
			.unwrap();
		let execute_q_rx = &mut test.to_execute_queue_rx;
		let result_tx_pvf_1_1 = run_until(
			&mut test.run,
			async {
				assert_matches!(
					execute_q_rx.next().await.unwrap(),
					execute::ToQueue::Enqueue { result_tx, .. } => result_tx
				)
			}
			.boxed(),
		)
		.await;
		let result_tx_pvf_1_2 = run_until(
			&mut test.run,
			async {
				assert_matches!(
					execute_q_rx.next().await.unwrap(),
					execute::ToQueue::Enqueue { result_tx, .. } => result_tx
				)
			}
			.boxed(),
		)
		.await;

		test.from_prepare_queue_tx
			.send(prepare::FromQueue::Prepared(artifact_id(2)))
			.await
			.unwrap();
		let execute_q_rx = &mut test.to_execute_queue_rx;
		let result_tx_pvf_2 = run_until(
			&mut test.run,
			async {
				assert_matches!(
					execute_q_rx.next().await.unwrap(),
					execute::ToQueue::Enqueue { result_tx, .. } => result_tx
				)
			}
			.boxed(),
		)
		.await;

		result_tx_pvf_1_1
			.send(Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn,
			)))
			.unwrap();
		assert_matches!(
			result_rx_pvf_1_1.now_or_never().unwrap().unwrap(),
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn
			))
		);

		result_tx_pvf_1_2
			.send(Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn,
			)))
			.unwrap();
		assert_matches!(
			result_rx_pvf_1_2.now_or_never().unwrap().unwrap(),
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn
			))
		);

		result_tx_pvf_2
			.send(Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn,
			)))
			.unwrap();
		assert_matches!(
			result_rx_pvf_2.now_or_never().unwrap().unwrap(),
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::BadReturn
			))
		);
	}
}

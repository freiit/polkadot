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

use super::{
	pool::{self, Worker},
};
use crate::{LOG_TARGET, Priority, Pvf, artifacts::ArtifactId};
use futures::{Future, SinkExt, channel::mpsc, stream::StreamExt as _};
use std::collections::{HashMap, VecDeque};
use async_std::path::PathBuf;
use always_assert::never;

#[derive(Debug)]
pub enum ToQueue {
	Enqueue {
		priority: Priority,
		pvf: Pvf,
	},
	Amend {
		priority: Priority,
		artifact_id: ArtifactId,
	},
}

#[derive(Debug, PartialEq, Eq)]
pub enum FromQueue {
	Prepared(ArtifactId),
}

#[derive(Default)]
struct Limits {
	/// The maximum number of workers this pool can ever host. This is expected to be a small
	/// number, e.g. within a dozen.
	hard_capacity: usize,

	/// The number of workers we want aim to have. If there is a critical job and we are already
	/// at `soft_capacity`, we are allowed to grow up to `hard_capacity`. Thus this should be equal
	/// or smaller than `hard_capacity`.
	soft_capacity: usize,
}

impl Limits {
	/// Returns `true` if the queue is allowed to request one more worker.
	fn can_afford_one_more(&self, spawned_num: usize, critical: bool) -> bool {
		let cap = if critical {
			self.hard_capacity
		} else {
			self.soft_capacity
		};
		spawned_num < cap
	}

	/// Offer the worker back to the pool. The passed worker ID must be considered unusable unless
	/// it wasn't taken by the pool, in which case it will be returned as `Some`.
	fn should_cull(&mut self, spawned_num: usize) -> bool {
		spawned_num > self.soft_capacity
	}
}

slotmap::new_key_type! { pub struct Job; }

struct JobData {
	/// The priority of this job. Can be bumped.
	priority: Priority,
	pvf: Pvf,
	worker: Option<Worker>,
}

#[derive(Default)]
struct WorkerData {
	job: Option<Job>,
}

impl WorkerData {
	fn is_idle(&self) -> bool {
		self.job.is_none()
	}
}

/// TODO:
/// This structure is prone to starving, however, we don't care that much since we expect there is
/// going to be a limited number of critical jobs and we don't really care if background starve.
#[derive(Default)]
struct Unscheduled {
	background: VecDeque<Job>,
	normal: VecDeque<Job>,
	critical: VecDeque<Job>,
}

impl Unscheduled {
	fn queue_mut(&mut self, prio: Priority) -> &mut VecDeque<Job> {
		match prio {
			Priority::Background => &mut self.background,
			Priority::Normal => &mut self.normal,
			Priority::Critical => &mut self.critical,
		}
	}

	fn add(&mut self, prio: Priority, job: Job) {
		self.queue_mut(prio).push_back(job);
	}

	fn readd(&mut self, prio: Priority, job: Job) {
		self.queue_mut(prio).push_front(job);
	}

	fn next(&mut self) -> Option<Job> {
		let mut check = |prio: Priority| self.queue_mut(prio).pop_front();
		None.or_else(|| check(Priority::Critical))
			.or_else(|| check(Priority::Normal))
			.or_else(|| check(Priority::Background))
	}
}

struct Queue {
	to_queue_rx: mpsc::Receiver<ToQueue>,
	from_queue_tx: mpsc::UnboundedSender<FromQueue>,

	to_pool_tx: mpsc::Sender<pool::ToPool>,
	from_pool_rx: mpsc::UnboundedReceiver<pool::FromPool>,

	cache_path: PathBuf,
	limits: Limits,

	jobs: slotmap::SlotMap<Job, JobData>,

	/// A mapping from artifact id to a job.
	artifact_id_to_job: HashMap<ArtifactId, Job>,
	workers: slotmap::SparseSecondaryMap<Worker, WorkerData>,
	spawn_inflight: usize,

	/// The jobs that are not yet scheduled. These are waiting until the next `poll` where they are
	/// processed all at once.
	unscheduled: Unscheduled,
}

/// A fatal error that warrants stopping the queue.
struct Fatal;

impl Queue {
	fn new(
		soft_capacity: usize,
		hard_capacity: usize,
		cache_path: PathBuf,
		to_queue_rx: mpsc::Receiver<ToQueue>,
		from_queue_tx: mpsc::UnboundedSender<FromQueue>,
		to_pool_tx: mpsc::Sender<pool::ToPool>,
		from_pool_rx: mpsc::UnboundedReceiver<pool::FromPool>,
	) -> Self {
		Self {
			to_queue_rx,
			from_queue_tx,
			to_pool_tx,
			from_pool_rx,
			cache_path,
			spawn_inflight: 0,
			limits: Limits {
				soft_capacity,
				hard_capacity,
			},
			jobs: slotmap::SlotMap::with_key(),
			unscheduled: Unscheduled::default(),
			artifact_id_to_job: HashMap::new(),
			workers: slotmap::SparseSecondaryMap::new(),
		}
	}

	async fn run(mut self) {
		macro_rules! break_if_fatal {
			($expr:expr) => {
				if let Err(Fatal) = $expr {
					break;
				}
			};
		}

		loop {
			// biased to make it behave deterministically for tests.
			futures::select_biased! {
				to_queue = self.to_queue_rx.select_next_some() =>
					break_if_fatal!(handle_to_queue(&mut self, to_queue).await),
				from_pool = self.from_pool_rx.select_next_some() =>
					break_if_fatal!(handle_from_pool(&mut self, from_pool).await),
			}
		}
	}
}

async fn handle_to_queue(queue: &mut Queue, to_queue: ToQueue) -> Result<(), Fatal> {
	match to_queue {
		ToQueue::Enqueue { priority, pvf } => {
			handle_enqueue(queue, priority, pvf).await?;
		}
		ToQueue::Amend {
			priority,
			artifact_id,
		} => {
			handle_amend(queue, priority, artifact_id).await?;
		}
	}
	Ok(())
}

async fn handle_enqueue(queue: &mut Queue, priority: Priority, pvf: Pvf) -> Result<(), Fatal> {
	println!("enque");

	let artifact_id = pvf.as_artifact_id();
	if never!(queue.artifact_id_to_job.contains_key(&artifact_id)) {
		// We already know about this artifact yet it was still enqueued.
		tracing::warn!(
			target: LOG_TARGET,
			"duplicate `enqueue` command received for {:?}",
			artifact_id,
		);
		return Ok(());
	}

	let job = queue.jobs.insert(JobData {
		priority,
		pvf,
		worker: None,
	});
	queue.artifact_id_to_job.insert(artifact_id, job);

	if let Some(available) = find_idle_worker(queue) {
		// TODO: Explain, why this should be fair, i.e. that the work won't be handled out of order.
		assign(queue, available, job).await?;
	} else {
		spawn_extra_worker(queue, priority.is_critical()).await?;
		queue.unscheduled.add(priority, job);
	}

	Ok(())
}

fn find_idle_worker(queue: &mut Queue) -> Option<Worker> {
	queue
		.workers
		.iter()
		.filter(|(_, data)| data.is_idle())
		.map(|(k, _)| k)
		.next()
}

async fn handle_amend(
	queue: &mut Queue,
	priority: Priority,
	artifact_id: ArtifactId,
) -> Result<(), Fatal> {
	if let Some(&job) = queue.artifact_id_to_job.get(&artifact_id) {
		let mut job_data: &mut JobData = &mut queue.jobs[job];

		if job_data.priority < priority {
			// The new priority is higher. We should do two things:
			// - if the worker was already spawned with the background prio and the new one is not
			//   (it's already the case, if we are in this branch but we still do the check for
			//   clarity), then we should tell the pool to bump the priority for the worker.
			//
			// - save the new priority in the job.

			if let Some(worker) = job_data.worker {
				if job_data.priority.is_background() && !priority.is_background() {
					send_pool(&mut queue.to_pool_tx, pool::ToPool::BumpPriority(worker)).await?;
				}
			}

			job_data.priority = dbg!(priority);
		}
	}

	Ok(())
}

async fn handle_from_pool(queue: &mut Queue, from_pool: pool::FromPool) -> Result<(), Fatal> {
	use pool::FromPool::*;
	match from_pool {
		Spawned(worker) => handle_worker_spawned(queue, worker).await?,
		Concluded(worker) => handle_worker_concluded(queue, worker).await?,
		Rip(worker) => handle_worker_rip(queue, worker).await?,
	}
	Ok(())
}

async fn handle_worker_spawned(queue: &mut Queue, worker: Worker) -> Result<(), Fatal> {
	queue.workers.insert(worker, WorkerData::default());
	queue.spawn_inflight -= 1;

	if let Some(job) = queue.unscheduled.next() {
		dbg!(&job);
		assign(queue, worker, job).await?;
	}

	Ok(())
}

async fn handle_worker_concluded(queue: &mut Queue, worker: Worker) -> Result<(), Fatal> {
	macro_rules! never_none {
		($expr:expr) => {
			match $expr {
				Some(v) => v,
				None => {
					never!("never_none, {}", stringify!($expr));
					return Ok(());
				}
			}
		};
	}

	// Find out on which artifact was the worker working.
	let worker_data = never_none!(queue.workers.get_mut(worker));
	let job = never_none!(worker_data.job.take());
	let job_data = never_none!(queue.jobs.remove(job));
	let artifact_id = job_data.pvf.as_artifact_id();

	queue.artifact_id_to_job.remove(&artifact_id);

	reply(&mut queue.from_queue_tx, FromQueue::Prepared(artifact_id))?;

	if queue
		.limits
		.should_cull(queue.workers.len() + queue.spawn_inflight)
	{
		// We no longer need services of this worker. Kill it.
		queue.workers.remove(worker);
		send_pool(&mut queue.to_pool_tx, pool::ToPool::Kill(worker)).await?;
	} else {
		// see if there are more work available and schedule it.
		if let Some(job) = queue.unscheduled.next() {
			assign(queue, worker, job).await?;
		}
	}

	Ok(())
}

async fn handle_worker_rip(queue: &mut Queue, worker: Worker) -> Result<(), Fatal> {
	let worker = match queue.workers.remove(worker) {
		None => {
			// That's fine. This can happen when we wanted to kill the worker but it died naturally
			// before us receiving the message.
			return Ok(());
		}
		Some(w) => w,
	};

	if let Some(job) = worker.job {
		let job_data = &mut queue.jobs[job];

		queue.unscheduled.readd(job_data.priority, job);

		// Spawn another worker to replace the ripped one. That unconditionally is not critical
		// even though the job might have been, just to not accidentally fill up the whole pool.
		spawn_extra_worker(queue, false).await?;
	}

	Ok(())
}

async fn spawn_extra_worker(queue: &mut Queue, critical: bool) -> Result<(), Fatal> {
	if queue
		.limits
		.can_afford_one_more(queue.workers.len() + queue.spawn_inflight, critical)
	{
		queue.spawn_inflight += 1;
		send_pool(&mut queue.to_pool_tx, pool::ToPool::Spawn).await?;
	}

	Ok(())
}

async fn assign(queue: &mut Queue, worker: Worker, job: Job) -> Result<(), Fatal> {
	let job_data = &mut queue.jobs[job];

	let artifact_id = job_data.pvf.as_artifact_id();
	let artifact_path = artifact_id.path(&queue.cache_path);

	job_data.worker = dbg!(Some(worker));

	queue.workers[worker].job = Some(job);

	send_pool(
		&mut queue.to_pool_tx,
		pool::ToPool::StartWork {
			worker,
			code: job_data.pvf.code.clone(),
			artifact_path,
			background_priority: dbg!(job_data.priority.is_background()),
		},
	)
	.await?;

	Ok(())
}

fn reply(from_queue_tx: &mut mpsc::UnboundedSender<FromQueue>, m: FromQueue) -> Result<(), Fatal> {
	from_queue_tx.unbounded_send(m).map_err(|_| {
		// The host has hung up and thus it's fatal and we should shutdown ourselves.
		Fatal
	})
}

async fn send_pool(
	to_pool_tx: &mut mpsc::Sender<pool::ToPool>,
	m: pool::ToPool,
) -> Result<(), Fatal> {
	to_pool_tx.send(m).await.map_err(|_| {
		// The pool has hung up and thus we are no longer are able to fulfill our duties. Shutdown.
		Fatal
	})
}

pub fn start(
	soft_capacity: usize,
	hard_capacity: usize,
	cache_path: PathBuf,
	to_pool_tx: mpsc::Sender<pool::ToPool>,
	from_pool_rx: mpsc::UnboundedReceiver<pool::FromPool>,
) -> (
	mpsc::Sender<ToQueue>,
	mpsc::UnboundedReceiver<FromQueue>,
	impl Future<Output = ()>,
) {
	let (to_queue_tx, to_queue_rx) = mpsc::channel(150);
	let (from_queue_tx, from_queue_rx) = mpsc::unbounded();

	let run = Queue::new(
		soft_capacity,
		hard_capacity,
		cache_path,
		to_queue_rx,
		from_queue_tx,
		to_pool_tx,
		from_pool_rx,
	)
	.run();

	(to_queue_tx, from_queue_rx, run)
}

#[cfg(test)]
mod tests {
	use slotmap::SlotMap;
	use assert_matches::assert_matches;
	use futures::{FutureExt, future::BoxFuture};
	use std::task::Poll;
	use super::*;

	// TODO: respects priority for unscheduled
	// TODO: immune to rips

	/// Creates a new pvf which artifact id can be uniquely identified by the given number.
	fn pvf(descriminator: u32) -> Pvf {
		Pvf::from_discriminator(descriminator)
	}

	async fn run_until<R>(
		task: &mut (impl Future<Output = ()> + Unpin),
		mut fut: (impl Future<Output = R> + Unpin),
	) -> R {
		let start = std::time::Instant::now();
		let fut = &mut fut;
		loop {
			if start.elapsed() > std::time::Duration::from_secs(1) {
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

	struct Test {
		_tempdir: tempfile::TempDir,
		run: BoxFuture<'static, ()>,
		workers: SlotMap<Worker, ()>,
		from_pool_tx: mpsc::UnboundedSender<pool::FromPool>,
		to_pool_rx: mpsc::Receiver<pool::ToPool>,
		to_queue_tx: mpsc::Sender<ToQueue>,
		from_queue_rx: mpsc::UnboundedReceiver<FromQueue>,
	}

	impl Test {
		fn new(soft_capacity: usize, hard_capacity: usize) -> Self {
			let tempdir = tempfile::tempdir().unwrap();

			let (to_pool_tx, to_pool_rx) = mpsc::channel(10);
			let (from_pool_tx, from_pool_rx) = mpsc::unbounded();

			let workers: SlotMap<Worker, ()> = SlotMap::with_key();

			let (to_queue_tx, from_queue_rx, run) = start(
				soft_capacity,
				hard_capacity,
				tempdir.path().to_owned().into(),
				to_pool_tx,
				from_pool_rx,
			);

			Self {
				_tempdir: tempdir,
				run: run.boxed(),
				workers,
				from_pool_tx,
				to_pool_rx,
				to_queue_tx,
				from_queue_rx,
			}
		}

		fn send_queue(&mut self, to_queue: ToQueue) {
			self.to_queue_tx
				.send(to_queue)
				.now_or_never()
				.unwrap()
				.unwrap();
		}

		async fn poll_and_recv_from_queue(&mut self) -> FromQueue {
			let from_queue_rx = &mut self.from_queue_rx;
			run_until(
				&mut self.run,
				async { from_queue_rx.next().await.unwrap() }.boxed(),
			)
			.await
		}

		fn send_from_pool(&mut self, from_pool: pool::FromPool) {
			self.from_pool_tx
				.send(from_pool)
				.now_or_never()
				.unwrap()
				.unwrap();
		}

		async fn poll_and_recv_to_pool(&mut self) -> pool::ToPool {
			let to_pool_rx = &mut self.to_pool_rx;
			run_until(
				&mut self.run,
				async { to_pool_rx.next().await.unwrap() }.boxed(),
			)
			.await
		}
	}

	#[async_std::test]
	async fn properly_concludes() {
		let mut test = Test::new(2, 2);

		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Background,
			pvf: pvf(1),
		});
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);

		let w = test.workers.insert(());
		test.send_from_pool(pool::FromPool::Spawned(w));
		test.send_from_pool(pool::FromPool::Concluded(w));

		assert_eq!(
			test.poll_and_recv_from_queue().await,
			FromQueue::Prepared(pvf(1).as_artifact_id())
		);
	}

	#[async_std::test]
	async fn dont_spawn_over_soft_limit_unless_critical() {
		let mut test = Test::new(2, 3);

		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Normal,
			pvf: pvf(1),
		});
		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Normal,
			pvf: pvf(2),
		});
		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Normal,
			pvf: pvf(3),
		});

		// Receive only two spawns.
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);

		let w1 = test.workers.insert(());
		let w2 = test.workers.insert(());

		test.send_from_pool(pool::FromPool::Spawned(w1));
		test.send_from_pool(pool::FromPool::Spawned(w2));

		// Get two start works.
		assert_matches!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::StartWork { .. }
		);
		assert_matches!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::StartWork { .. }
		);

		test.send_from_pool(pool::FromPool::Concluded(w1));

		assert_matches!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::StartWork { .. }
		);

		// Enqueue a critical job.
		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Critical,
			pvf: pvf(4),
		});

		// 2 out of 2 are working, but there is a critical job incoming. That means that spawning
		// another worker is warranted.
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);
	}

	#[async_std::test]
	async fn cull_unwanted() {
		let mut test = Test::new(1, 2);

		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Normal,
			pvf: pvf(1),
		});
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);
		let w1 = test.workers.insert(());
		test.send_from_pool(pool::FromPool::Spawned(w1));
		assert_matches!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::StartWork { .. }
		);

		// Enqueue a critical job, which warrants spawning over the soft limit.
		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Critical,
			pvf: pvf(2),
		});
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);

		// However, before the new worker had a chance to spawn, the first worker finishes with its
		// job. The old worker will be killed while the new worker will be let live, even though
		// it's not instantiated.
		//
		// That's a bit silly in this context, but in production there will be an entire pool up
		// to the `soft_capacity` of workers and it doesn't matter which one to cull. Either way,
		// we just check that edge case of an edge case works.
		test.send_from_pool(pool::FromPool::Concluded(w1));
		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Kill(w1));
	}

	#[async_std::test]
	async fn bump_prio_on_urgency_change() {
		let mut test = Test::new(2, 2);

		test.send_queue(ToQueue::Enqueue {
			priority: Priority::Background,
			pvf: pvf(1),
		});

		assert_eq!(test.poll_and_recv_to_pool().await, pool::ToPool::Spawn);

		let w = test.workers.insert(());
		test.send_from_pool(pool::FromPool::Spawned(w));

		assert_matches!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::StartWork { .. }
		);
		test.send_queue(ToQueue::Amend {
			priority: Priority::Normal,
			artifact_id: pvf(1).as_artifact_id(),
		});

		assert_eq!(
			test.poll_and_recv_to_pool().await,
			pool::ToPool::BumpPriority(w)
		);
	}
}

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

//! A queue that handles requests for PVF execution.

use super::worker::Outcome;
use crate::worker_common::{IdleWorker, WorkerHandle};
use std::{collections::VecDeque, fmt, task::Poll};
use futures::{
	Future, FutureExt,
	channel::{mpsc, oneshot},
	future::BoxFuture,
	stream::{FuturesUnordered, StreamExt as _},
};
use async_std::path::PathBuf;
use polkadot_parachain::{
	primitives::ValidationResult,
	wasm_executor::{InvalidCandidate, ValidationError},
};
use slotmap::HopSlotMap;
use always_assert::always;

slotmap::new_key_type! { struct Worker; }

#[derive(Debug)]
pub enum ToQueue {
	Enqueue {
		artifact_path: PathBuf,
		params: Vec<u8>,
		result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
	},
}

struct ExecuteJob {
	artifact_path: PathBuf,
	params: Vec<u8>,
	result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
}

struct WorkerData {
	idle: Option<IdleWorker>,
	handle: WorkerHandle,
}

impl fmt::Debug for WorkerData {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "WorkerData(pid={})", self.handle.id())
	}
}

struct Workers {
	running: HopSlotMap<Worker, WorkerData>,

	spawn_inflight: usize,

	capacity: usize,
}

impl Workers {
	fn can_afford_one_more(&self) -> bool {
		self.spawn_inflight + self.running.len() < self.capacity
	}

	fn find_available(&self) -> Option<Worker> {
		self.running
			.iter()
			.find_map(|d| if d.1.idle.is_some() { Some(d.0) } else { None })
	}

	fn claim_idle(&mut self, worker: Worker) -> IdleWorker {
		let data = self
			.running
			.get_mut(worker)
			.expect("the worker doesn't exist");
		data.idle.take().expect("the worker has no idle token")
	}
}

enum QueueEvent {
	Spawn((IdleWorker, WorkerHandle)),
	StartWork(
		Worker,
		Outcome,
		oneshot::Sender<Result<ValidationResult, ValidationError>>,
	),
}

type Mux = FuturesUnordered<BoxFuture<'static, QueueEvent>>;

struct Queue {
	program_path: PathBuf,

	spawn_timeout_secs: u64,

	/// The receiver that receives messages to the pool.
	to_queue_rx: mpsc::Receiver<ToQueue>,

	/// The queue of jobs that are waiting for a worker to pick up.
	queue: VecDeque<ExecuteJob>,

	workers: Workers,

	mux: Mux,
}

impl Queue {
	fn new(
		program_path: PathBuf,
		worker_capacity: usize,
		spawn_timeout_secs: u64,
		to_queue_rx: mpsc::Receiver<ToQueue>,
	) -> Self {
		Self {
			program_path,
			spawn_timeout_secs,
			to_queue_rx,
			queue: VecDeque::new(),
			mux: Mux::new(),
			workers: Workers {
				running: HopSlotMap::with_capacity_and_key(10),
				spawn_inflight: 0,
				capacity: worker_capacity,
			},
		}
	}

	async fn run(mut self) {
		loop {
			futures::select! {
				to_queue = self.to_queue_rx.select_next_some() => // TODO: handle none
					handle_to_queue(&mut self, to_queue),
				ev = self.mux.select_next_some() => handle_mux(&mut self, ev).await,
			}

			purge_dead(&mut self.workers).await;
		}
	}
}

async fn purge_dead(workers: &mut Workers) {
	let mut to_remove = vec![];
	for (worker, data) in workers.running.iter_mut() {
		if let Poll::Ready(()) = futures::poll!(&mut data.handle) {
			// a resolved future means that the worker has terminated. Weed it out.
			to_remove.push(worker);
		}
	}
	for w in to_remove {
		let _ = workers.running.remove(w);
	}
}

fn handle_to_queue(queue: &mut Queue, to_queue: ToQueue) {
	let ToQueue::Enqueue {
		artifact_path,
		params,
		result_tx,
	} = to_queue;

	let job = ExecuteJob {
		artifact_path,
		params,
		result_tx,
	};

	if let Some(available) = queue.workers.find_available() {
		assign(queue, available, job);
	} else {
		if queue.workers.can_afford_one_more() {
			spawn_extra_worker(queue);
		}
		queue.queue.push_back(job);
	}
}

async fn handle_mux(queue: &mut Queue, event: QueueEvent) {
	match event {
		QueueEvent::Spawn((idle, handle)) => {
			queue.workers.spawn_inflight -= 1;

			let worker = queue.workers.running.insert(WorkerData {
				idle: Some(idle),
				handle,
			});

			if let Some(job) = queue.queue.pop_front() {
				assign(queue, worker, job);
			}
		}
		QueueEvent::StartWork(worker, outcome, result_tx) => {
			handle_job_finish(queue, worker, outcome, result_tx);
		}
	}
}

/// If there are pending jobs in the queue, schedules the next of them onto the just freed up
/// worker. Otherwise, puts back into the available workers list.
fn handle_job_finish(
	queue: &mut Queue,
	worker: Worker,
	outcome: Outcome,
	result_tx: oneshot::Sender<Result<ValidationResult, ValidationError>>,
) {
	let (idle_worker, result) = match outcome {
		Outcome::Ok {
			result_descriptor,
			duration_ms,
			idle_worker,
		} => {
			// TODO: propagate the soft timeout
			drop(duration_ms);

			(Some(idle_worker), Ok(result_descriptor))
		}
		Outcome::InvalidCandidate { err, idle_worker } => (
			Some(idle_worker),
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::ExternalWasmExecutor(err),
			)),
		),
		Outcome::HardTimeout => (
			None,
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::ExternalWasmExecutor("hard timeout".to_string()),
			)),
		),
		Outcome::IoErr => (
			None,
			Err(ValidationError::InvalidCandidate(
				InvalidCandidate::ExternalWasmExecutor(
					"io err communicating with worker".to_string(),
				),
			)),
		),
	};

	// First we send the result. It may fail due the other end of the channel being dropped, that's
	// legitimate and we don't treat that as a error.
	let _ = result_tx.send(result);

	// Then, we should deal with the worker:
	//
	// - if the `idle_worker` token was returned we should either schedule the next task or just put
	//   it back so that the next incoming job will be able to claim it
	//
	// - if the `idle_worker` token was consumed, all the metadata pertaining to that worker should
	//   be removed.
	if let Some(idle_worker) = idle_worker {
		if let Some(data) = queue.workers.running.get_mut(worker) {
			data.idle = Some(idle_worker);

			if let Some(job) = queue.queue.pop_front() {
				assign(queue, worker, job);
			}
		}
	} else {
		always!(queue.workers.running.remove(worker).is_some());

		if !queue.queue.is_empty() {
			// The worker has died and we still have work we have to do. Request an extra worker.
			//
			// That can potentially overshoot, but that should be OK.
			spawn_extra_worker(queue);
		}
	}
}

fn spawn_extra_worker(queue: &mut Queue) {
	let program_path = queue.program_path.clone();
	let spawn_timeout_secs = queue.spawn_timeout_secs;
	queue.mux.push(
		async move {
			loop {
				match super::worker::spawn(&program_path, spawn_timeout_secs).await {
					Ok((idle, handle)) => break QueueEvent::Spawn((idle, handle)),
					Err(_err) => {
						// TODO: log and retry
					}
				}
			}
		}
		.boxed(),
	);

	queue.workers.spawn_inflight += 1;
}

fn assign(queue: &mut Queue, worker: Worker, job: ExecuteJob) {
	let idle = queue.workers.claim_idle(worker);
	queue.mux.push(
		async move {
			let outcome = super::worker::start_work(idle, job.artifact_path, job.params).await;
			QueueEvent::StartWork(worker, outcome, job.result_tx)
		}
		.boxed(),
	);
}

pub fn start(
	program_path: PathBuf,
	worker_capacity: usize,
	spawn_timeout_secs: u64,
) -> (mpsc::Sender<ToQueue>, impl Future<Output = ()>) {
	let (to_queue_tx, to_queue_rx) = mpsc::channel(20);
	let run = Queue::new(
		program_path,
		worker_capacity,
		spawn_timeout_secs,
		to_queue_rx,
	)
	.run();
	(to_queue_tx, run)
}

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
	Priority,
	artifacts::Artifact,
	worker_common::{
		IdleWorker, SpawnErr, WorkerHandle, bytes_to_path, framed_recv, framed_send, path_to_bytes,
		spawn_with_program_path, tmpfile,
	},
};
use async_std::{
	io,
	os::unix::net::{UnixListener, UnixStream},
	path::{PathBuf, Path},
};
use futures::{
	AsyncRead, AsyncWrite, AsyncReadExt as _, AsyncWriteExt as _, FutureExt as _, StreamExt as _,
	channel::mpsc,
};
use futures_timer::Delay;
use rand::Rng;
use std::{
	borrow::Cow,
	mem,
	pin::Pin,
	str::{FromStr, from_utf8},
	sync::Arc,
	task::{Context, Poll},
	time::Duration,
};
use pin_project::pin_project;

const NICENESS_BACKGROUND: i32 = 5;
const NICENESS_FOREGROUND: i32 = 0;

pub async fn spawn(program_path: &Path) -> Result<(IdleWorker, WorkerHandle), SpawnErr> {
	let program_path = program_path.to_string_lossy();
	spawn_with_program_path(&program_path, &["prepare-worker"]).await
}

pub enum Outcome {
	/// The worker has finished the work assigned to it.
	Concluded(IdleWorker),
	/// The execution was interrupted abruptly and the worker is not available anymore. For example,
	/// this could've happen because the worker hadn't finished the work until the given deadline.
	///
	/// Note that in this case the artifact file is written (unless there was an error writing the
	/// the artifact).
	///
	/// This doesn't return an idle worker instance, thus this worker is no longer usable.
	DidntMakeIt,
}

pub async fn start_work(
	worker: IdleWorker,
	code: Arc<Vec<u8>>,
	artifact_path: PathBuf,
	background_priority: bool,
) -> Outcome {
	let IdleWorker { mut stream, pid } = worker;

	if background_priority {
		renice(pid, NICENESS_BACKGROUND);
	}

	if let Err(err) = send_request(&mut stream, code).await {
		// TODO: Log
		return Outcome::DidntMakeIt;
	}

	// Wait for the result from the worker, keeping in mind that there may be a timeout, the
	// worker may get killed, or something along these lines.
	//
	// In that case we should handle these gracefully by writing the artifact file by ourselves.
	// We may potentially overwrite the artifact in rare cases where the worker didn't make
	// it to report back the result.

	enum Selected {
		Done,
		IoErr,
		Deadline,
	}

	let selected = futures::select! {
		artifact_path_bytes = framed_recv(&mut stream).fuse() => {
			match artifact_path_bytes {
				Ok(bytes) => {
					let tmp_path = bytes_to_path(&bytes);
					async_std::fs::rename(tmp_path, &artifact_path)
						.await
						.map(|_| Selected::Done)
						.unwrap_or(Selected::IoErr)
				},
				Err(_) => Selected::IoErr,
			}
		},
		_ = Delay::new(Duration::from_secs(10)).fuse() => Selected::Deadline, // TODO: increased, because compiling takes a lot of time in debug mode, make this customizable
	};

	match selected {
		Selected::Done => {
			renice(pid, NICENESS_FOREGROUND);
			Outcome::Concluded(IdleWorker { stream, pid })
		}
		Selected::IoErr | Selected::Deadline => {
			let bytes = Artifact::DidntMakeIt.serialize();
			// best effort: there is nothing we can do here if the write fails.
			let _ = async_std::fs::write(&artifact_path, &bytes).await;
			Outcome::DidntMakeIt
		}
	}
}

async fn send_request(stream: &mut UnixStream, code: Arc<Vec<u8>>) -> io::Result<()> {
	framed_send(stream, &*code).await?;
	Ok(())
}

async fn recv_request(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
	let code = framed_recv(stream).await?;
	Ok(code)
}

pub fn bump_priority(handle: &WorkerHandle) {
	let pid = handle.id();
	renice(pid, NICENESS_FOREGROUND);
}

fn renice(pid: u32, niceness: i32) {
	// TODO: upstream to nix
	unsafe {
		if -1 == libc::setpriority(libc::PRIO_PROCESS, pid, niceness) {
			let err = std::io::Error::last_os_error();
			drop(err); // TODO: warn
		}
	}
}

pub fn worker_entrypoint(socket_path: &str) {
	let err = async_std::task::block_on::<_, io::Result<()>>(async {
		let mut stream = UnixStream::connect(socket_path).await?;

		loop {
			let code = recv_request(&mut stream).await?;

			let artifact_bytes = prepare_artifact(&code).serialize();

			// Write the serialized artifact into into a temp file.
			let dest = tmpfile("prepare-artifact-");
			async_std::fs::write(&dest, &artifact_bytes).await?;

			// Communicate the results back to the host.
			framed_send(&mut stream, &path_to_bytes(&dest)).await?;
		}
	})
	.unwrap_err();

	// TODO: proper handling
	drop(err);
}

fn prepare_artifact(code: &[u8]) -> Artifact {
	let blob = match crate::executor_intf::prevalidate(code) {
		Err(err) => {
			return Artifact::PrevalidationErr(format!("{:?}", err));
		}
		Ok(b) => b,
	};

	match crate::executor_intf::prepare(blob) {
		Ok(compiled_artifact) => Artifact::Compiled { compiled_artifact },
		Err(err) => Artifact::PreparationErr(format!("{:?}", err)),
	}
}

#[cfg(test)]
mod tests {
	// The logic is actually exercised using an integration test under `tests/it.rs`
}

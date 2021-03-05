use std::time::Instant;

use crate::{
	artifacts::Artifact,
	worker_common::{
		IdleWorker, SpawnErr, WorkerHandle, bytes_to_path, framed_recv, framed_send, path_to_bytes,
		spawn_with_program_path,
	},
};
use std::time::Duration;
use async_std::{
	io,
	os::unix::net::UnixStream,
	path::{Path, PathBuf},
};
use futures::FutureExt;
use futures_timer::Delay;
use polkadot_parachain::{primitives::ValidationResult, wasm_executor::ValidationError};
use parity_scale_codec::{Encode, Decode};

pub async fn spawn() -> Result<(IdleWorker, WorkerHandle), SpawnErr> {
	let current_exe = std::env::current_exe().map_err(|_| SpawnErr::CurrentExe)?;
	let program_path = current_exe.to_string_lossy();
	spawn_with_program_path(&*program_path, &[]).await
}

pub enum Outcome {
	Ok {
		result_descriptor: ValidationResult,
		duration_ms: u64,
		idle_worker: IdleWorker,
	},
	InvalidCandidate {
		err: String,
		idle_worker: IdleWorker,
	},
	HardTimeout,
	IoErr,
}

pub async fn start_work(
	worker: IdleWorker,
	artifact_path: PathBuf,
	validation_params: Vec<u8>,
) -> Outcome {
	let IdleWorker { mut stream, pid } = worker;

	if let Err(_err) = send_request(&mut stream, &artifact_path, &validation_params).await {
		return Outcome::IoErr;
	}

	let response = futures::select! {
		response = recv_response(&mut stream).fuse() => {
			match response {
				Err(_err) => return Outcome::IoErr,
				Ok(response) => response,
			}
		},
		_ = Delay::new(Duration::from_secs(3)).fuse() => return Outcome::HardTimeout,
	};

	match response {
		Response::Ok {
			result_descriptor,
			duration_ms,
		} => Outcome::Ok {
			result_descriptor,
			duration_ms,
			idle_worker: IdleWorker { stream, pid },
		},
		Response::InvalidCandidate(err) => Outcome::InvalidCandidate {
			err,
			idle_worker: IdleWorker { stream, pid },
		},
	}
}

async fn send_request(
	stream: &mut UnixStream,
	artifact_path: &Path,
	validation_params: &[u8],
) -> io::Result<()> {
	framed_send(stream, path_to_bytes(artifact_path)).await?;
	framed_send(stream, validation_params).await?;
	Ok(())
}

async fn recv_request(stream: &mut UnixStream) -> io::Result<(PathBuf, Vec<u8>)> {
	let artifact_path = framed_recv(stream).await?;
	let artifact_path = bytes_to_path(&artifact_path);
	let params = framed_recv(stream).await?;
	Ok((artifact_path, params))
}

async fn send_response(stream: &mut UnixStream, response: Response) -> io::Result<()> {
	framed_send(stream, &response.encode()).await?;
	Ok(())
}

async fn recv_response(stream: &mut UnixStream) -> io::Result<Response> {
	let response_bytes = framed_recv(stream).await?;
	let response = Response::decode(&mut &response_bytes[..])
		.map_err(|e| io::Error::new(io::ErrorKind::Other, "response decode error"))?;
	Ok(response)
}

#[derive(Encode, Decode)]
enum Response {
	Ok {
		result_descriptor: ValidationResult,
		duration_ms: u64,
	},
	InvalidCandidate(String),
}

impl Response {
	fn format_invalid(ctx: &'static str, msg: &str) -> Self {
		if msg.is_empty() {
			Self::InvalidCandidate(ctx.to_string())
		} else {
			Self::InvalidCandidate(format!("{}: {}", ctx, msg))
		}
	}
}

pub fn worker_entrypoint(socket_path: &str) {
	let err = async_std::task::block_on::<_, io::Result<()>>(async {
		let mut stream = UnixStream::connect(socket_path).await?;

		loop {
			let (artifact_path, params) = recv_request(&mut stream).await?;
			let artifact_bytes = async_std::fs::read(&artifact_path).await?;
			let artifact = Artifact::deserialize(&artifact_bytes).map_err(|e| {
				io::Error::new(
					io::ErrorKind::Other,
					format!("artifact deserialization error: {}", e),
				)
			})?;
			let response = validate_using_artifact(&artifact, &params);
			send_response(&mut stream, response).await?;
		}
	})
	.unwrap_err();

	drop(err)
}

fn validate_using_artifact(artifact: &Artifact, params: &[u8]) -> Response {
	let compiled_artifact = match artifact {
		Artifact::PrevalidationErr(msg) => {
			return Response::format_invalid("prevalidation", msg);
		}
		Artifact::PreparationErr(msg) => {
			return Response::format_invalid("preparation", msg);
		}
		Artifact::DidntMakeIt => {
			return Response::format_invalid("preparation timeout", "");
		}

		Artifact::Compiled { compiled_artifact } => compiled_artifact,
	};

	let validation_started_at = Instant::now();
	let descriptor_bytes = match crate::executor_intf::execute(compiled_artifact, params) {
		Err(err) => {
			return Response::format_invalid("execute", &err.to_string());
		}
		Ok(d) => d,
	};

	let duration_ms = validation_started_at.elapsed().as_millis() as u64;

	let result_descriptor = match ValidationResult::decode(&mut &descriptor_bytes[..]) {
		Err(err) => {
			return Response::InvalidCandidate(format!(
				"validation result decoding failed: {}",
				err
			))
		}
		Ok(r) => r,
	};

	Response::Ok {
		result_descriptor,
		duration_ms,
	}
}

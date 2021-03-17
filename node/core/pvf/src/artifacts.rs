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

use crate::LOG_TARGET;
use always_assert::always;
use async_std::{
	io,
	path::{Path, PathBuf},
};
use polkadot_core_primitives::Hash;
use std::{
	collections::HashMap,
	time::{Duration, SystemTime},
};
use parity_scale_codec::{Encode, Decode};
use futures::StreamExt;

#[derive(Encode, Decode)]
pub enum Artifact {
	PrevalidationErr(String),
	PreparationErr(String),
	/// This state indicates that the process assigned to prepare the artifact wasn't responsible
	/// or were killed.
	DidntMakeIt,
	Compiled {
		compiled_artifact: Vec<u8>,
	},
}

impl Artifact {
	/// Serializes this struct into a byte buffer.
	pub fn serialize(&self) -> Vec<u8> {
		self.encode()
	}

	pub fn deserialize(mut bytes: &[u8]) -> Result<Self, String> {
		Artifact::decode(&mut bytes).map_err(|e| format!("{:?}", e))
	}
}

/// NOTE if we get to multiple engine implementations the artifact ID should include the engine
/// type as well.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId {
	code_hash: Hash,
}

impl ArtifactId {
	const PREFIX: &'static str = "wasmtime_1_";

	pub fn new(code_hash: Hash) -> Self {
		Self { code_hash }
	}

	/// Tries to recover the artifact id from the given file name.
	pub fn from_file_name(file_name: &str) -> Option<Self> {
		use std::str::FromStr as _;

		let file_name = file_name.strip_prefix(Self::PREFIX)?;
		let code_hash = Hash::from_str(file_name).ok()?;

		Some(Self { code_hash })
	}

	pub fn path(&self, cache_path: &Path) -> PathBuf {
		let file_name = format!("{}{}", Self::PREFIX, self.code_hash.to_string());
		cache_path.join(file_name)
	}
}

pub enum ArtifactState {
	/// The artifact is ready to be used by the executor.
	///
	/// That means that the artifact should be accessible through the path obtained by the artifact
	/// id under (unless, it was removed externally).
	Prepared {
		/// The time when the artifact was the last time needed.
		///
		/// This is updated when we get the heads up for this artifact or when we just discover
		/// this file.
		last_time_needed: SystemTime,
	},
	/// A task to prepare this artifact is scheduled.
	Preparing,
}

pub struct Artifacts {
	artifacts: HashMap<ArtifactId, ArtifactState>,
}

impl Artifacts {
	pub async fn new(cache_path: &Path) -> Self {
		let artifacts = match scan_for_known_artifacts(cache_path).await {
			Ok(a) => a,
			Err(err) => {
				tracing::warn!(
					target: LOG_TARGET,
					"unable to seed the artifacts in memory cache: {:?}. Starting with a clean one",
					err,
				);
				HashMap::new()
			}
		};

		Self { artifacts }
	}

	#[cfg(test)]
	pub(crate) fn empty() -> Self {
		Self {
			artifacts: HashMap::new(),
		}
	}

	pub fn artifact_state_mut(&mut self, artifact_id: &ArtifactId) -> Option<&mut ArtifactState> {
		self.artifacts.get_mut(artifact_id)
	}

	pub fn insert_preparing(&mut self, artifact_id: ArtifactId) {
		always!(self
			.artifacts
			.insert(artifact_id, ArtifactState::Preparing)
			.is_none());
	}

	#[cfg(test)]
	pub fn insert_prepared(&mut self, artifact_id: ArtifactId, last_time_needed: SystemTime) {
		always!(self
			.artifacts
			.insert(artifact_id, ArtifactState::Prepared { last_time_needed })
			.is_none());
	}

	pub fn prune(&mut self, artifact_ttl: Duration) -> Vec<ArtifactId> {
		let now = SystemTime::now();

		let mut to_remove = vec![];
		for (k, v) in self.artifacts.iter() {
			if let ArtifactState::Prepared {
				last_time_needed, ..
			} = *v
			{
				if now
					.duration_since(last_time_needed)
					.map(|age| age > artifact_ttl)
					.unwrap_or(false)
				{
					to_remove.push(k.clone());
				}
			}
		}

		to_remove
	}
}

async fn scan_for_known_artifacts(
	cache_path: &Path,
) -> io::Result<HashMap<ArtifactId, ArtifactState>> {
	let mut result = HashMap::new();

	let mut dir = async_std::fs::read_dir(cache_path).await?;
	while let Some(res) = dir.next().await {
		let entry = res?;

		if entry.file_type().await?.is_dir() {
			tracing::debug!(
				target: LOG_TARGET,
				"{} is a dir, and dirs do not belong to us. Removing",
				entry.path().display(),
			);
			let _ = async_std::fs::remove_dir_all(entry.path()).await;
		}

		let path = entry.path();
		let file_name = match path.file_name() {
			None => {
				// A file without a file name? Weird, just skip it.
				continue;
			}
			Some(file_name) => file_name,
		};

		let file_name = match file_name.to_str() {
			None => {
				tracing::debug!(
					target: LOG_TARGET,
					"{} is not utf-8. Removing",
					path.display(),
				);
				let _ = async_std::fs::remove_file(&path).await;
				continue;
			}
			Some(file_name) => file_name,
		};

		let artifact_id = match ArtifactId::from_file_name(file_name) {
			None => {
				tracing::debug!(
					target: LOG_TARGET,
					"{} is not a recognized artifact. Removing",
					path.display(),
				);
				let _ = async_std::fs::remove_file(&path).await;
				continue;
			}
			Some(artifact_id) => artifact_id,
		};

		// A sanity check so that we really can access the artifact through the artifact id.
		if always!(artifact_id.path(cache_path).is_file().await) {
			result.insert(
				artifact_id,
				ArtifactState::Prepared {
					last_time_needed: SystemTime::now(),
				},
			);
		}
	}

	Ok(result)
}

#[cfg(test)]
mod tests {
	use super::ArtifactId;

	#[test]
	fn from_file_name() {
		assert!(ArtifactId::from_file_name("").is_none());
		assert!(ArtifactId::from_file_name("junk").is_none());

		assert_eq!(
			ArtifactId::from_file_name(
				"wasmtime_1_0x0022800000000000000000000000000000000000000000000000000000000000"
			),
			Some(ArtifactId::new(
				hex_literal::hex![
					"0022800000000000000000000000000000000000000000000000000000000000"
				]
				.into()
			)),
		);
	}
}

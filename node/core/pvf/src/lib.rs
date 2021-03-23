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

mod artifacts;
mod execute;
mod executor_intf;
mod host;
mod prepare;
mod priority;
mod pvf;
mod worker_common;

pub use priority::Priority;
pub use pvf::Pvf;

pub use host::{start, Config, ValidationHost};

pub use execute::worker_entrypoint as execute_worker_entrypoint;
pub use prepare::worker_entrypoint as prepare_worker_entrypoint;

const LOG_TARGET: &str = "parachain::pvf";

/// Exports for integration tests.
#[doc(hidden)]
pub mod integration_test {
	pub mod worker_common {
		pub use crate::worker_common::{spawn_with_program_path, SpawnErr};
	}
}

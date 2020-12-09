pub mod model;

mod remote;
pub use remote::*;

mod grpc_remote;
pub use grpc_remote::{GrpcRemote, GrpcRemoteFile};

#[cfg(test)]
mod dummy_remote;
#[cfg(test)]
pub use dummy_remote::{DummyRemote, DummyRemoteFile};

pub mod model;

mod remote;
pub use remote::*;

mod grpc_remote;
pub use grpc_remote::{GrpcRemote, GrpcRemoteFile};

mod dummy_remote;
pub use dummy_remote::{DummyRemote, DummyRemoteFile};

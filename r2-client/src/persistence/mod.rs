#[macro_use]
mod storage;
pub use storage::*;

mod fs_storage; // Note: MUST be after storage or the tests won't pass
pub use fs_storage::*;

#[cfg(test)]
pub mod test {
    pub use super::fs_storage::test::*;
}

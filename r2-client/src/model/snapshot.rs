use diffy::{Patch, apply};
use super::commit::Commit;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

pub struct Snapshot(String);

impl Snapshot {
    pub fn empty() -> Snapshot {
        Snapshot(String::new())
    }

    pub fn apply(&mut self, commit: &Commit) -> Result<(), Error> {
        let patch = Patch::from_str(&commit.patch)?;
        self.0 = apply(&self.0, &patch)?;

        Ok(())
    }
}

impl From<String> for Snapshot {
    fn from(s: String) -> Self {
        Snapshot(s)
    }
}

impl Into<String> for Snapshot {
    fn into(self) -> String {
        self.0
    }
}

impl AsRef<[u8]> for Snapshot {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

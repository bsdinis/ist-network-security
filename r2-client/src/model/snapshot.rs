use std::fmt::{self, Display};
use serde::{Serialize, Deserialize};
use diffy::{apply, create_patch, Patch};

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PatchStr(String);

#[derive(Clone, PartialEq, Debug)]
pub struct Snapshot(String);

impl Snapshot {
    pub fn empty() -> Snapshot {
        Snapshot(String::new())
    }

    pub fn apply(&self, patch: &PatchStr) -> Result<Self, Error> {
        let patch = Patch::from_str(patch.as_ref())?;
        let patched = apply(&self.0, &patch)?;

        Ok(Snapshot(patched))
    }

    pub fn diff(&self, other: &Snapshot) -> PatchStr {
        let patch = create_patch(self.as_ref(), other.as_ref());
        PatchStr(patch.to_string())
    }
}

impl PatchStr {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl From<String> for Snapshot {
    fn from(s: String) -> Self {
        Snapshot(s)
    }
}

impl From<&str> for Snapshot {
    fn from(s: &str) -> Self {
        Snapshot(s.to_owned())
    }
}

impl AsRef<str> for Snapshot {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for Snapshot {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for PatchStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let patch = Patch::from_str(&self.0)
            .map_err(|_| fmt::Error)?;
        Display::fmt(&patch, f)
    }
}

impl AsRef<str> for PatchStr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for PatchStr {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn diff_apply_ok() {
        let empty = Snapshot::empty();
        let a: Snapshot = "I am file A.\nOh yeah look at me.\n".to_owned().into();
        let b: Snapshot = "I am file B.\nOh yeah look at me.\n".into();

        let patch_a = empty.diff(&a);
        let patch_ab = a.diff(&b);

        let new_a = empty.apply(&patch_a).unwrap();
        let new_b = a.apply(&patch_ab).unwrap();

        assert_eq!(a, new_a, "Diff/patch broken");
        assert_eq!(b, new_b, "Diff/patch broken");
    }
}

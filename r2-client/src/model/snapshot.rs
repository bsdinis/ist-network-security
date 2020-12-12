use diffy::{apply, create_patch, Patch};
pub use diffy::{ApplyError, ParsePatchError};
use serde::Serialize;
use std::fmt::{self, Display};

use std::convert::TryFrom;

use iterutils::MapIntoExt;

/// A Patch
///
/// Note: Always represents a valid patch for [diffy].
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct PatchStr(String);

/// A snapshot of a file
#[derive(Clone, PartialEq, Debug)]
pub struct Snapshot(String);

impl Snapshot {
    /// Create a new empty file snapshot
    ///
    /// Useful for generating the initial commit
    pub fn empty() -> Snapshot {
        Snapshot(String::new())
    }

    /// Merge 3 snapshots together (similar to diff3 algorithm)
    ///
    /// See [diffy::merge]
    pub fn merge3(ancestor: Self, ours: Self, theirs: Self) -> Result<Self, Self> {
        diffy::merge(&ancestor.0, &ours.0, &theirs.0).map_into()
    }

    /// Get the result of applying a patch to this snapshot
    ///
    /// See [diffy::apply]
    pub fn apply(&self, patch: &PatchStr) -> Result<Self, ApplyError> {
        let patch = patch.as_patch();
        let patched = apply(&self.0, &patch)?;

        Ok(Snapshot(patched))
    }

    /// Compute patch that transforms this snapshot in the other modified snapshot
    ///
    /// See [diffy::create_patch]
    pub fn diff(&self, modified: &Snapshot) -> PatchStr {
        let patch = create_patch(self.as_ref(), modified.as_ref());
        PatchStr(patch.to_string())
    }
}

impl PatchStr {
    /// Create [PatchStr] from the string representation of the patch
    /// Will error if the string is not a valid patch.
    pub fn from_string(s: String) -> Result<Self, ParsePatchError> {
        // validate
        if let Err(e) = Patch::from_str(&s) {
            return Err(e);
        }

        Ok(PatchStr(s))
    }

    /// Create [PatchStr] from the string representation of the patch
    /// Skips patch validity checks.
    /// Safety: argument must contain a valid patch
    pub unsafe fn from_str_unchecked(s: String) -> Self {
        PatchStr(s)
    }

    /// Returns a byte slice of the contents of the patch's string representation
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Creates a [diffy::Patch] object from this patch
    pub fn as_patch<'a>(&'a self) -> Patch<'a, str> {
        // Panic-free: PatchStr by construction contains a valid patch
        Patch::from_str(self.as_ref()).unwrap()
    }

    /// Checks if the patch performs no changes
    pub fn is_empty(&self) -> bool {
        self.as_patch().hunks().is_empty()
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
        let patch = self.as_patch();
        Display::fmt(&patch, f)
    }
}

impl TryFrom<String> for PatchStr {
    type Error = ParsePatchError;

    fn try_from(s: String) -> Result<Self, ParsePatchError> {
        PatchStr::from_string(s)
    }
}

impl Into<String> for PatchStr {
    fn into(self) -> String {
        self.0
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

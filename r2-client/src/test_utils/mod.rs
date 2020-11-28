pub mod signature_keys {
    use crate::sigkey::new_unparsed_public_key;
    use ring::signature::{KeyPair, RsaKeyPair, UnparsedPublicKey};

    pub static RAW_RSA_KEYPAIR_A: &'static [u8] = include_bytes!("rsa_keypair_a.pk8");
    pub static RAW_RSA_KEYPAIR_B: &'static [u8] = include_bytes!("rsa_keypair_b.pk8");

    lazy_static! {
        pub static ref RSA_KEYPAIR_A: RsaKeyPair =
            RsaKeyPair::from_pkcs8(RAW_RSA_KEYPAIR_A).unwrap();
        pub static ref RSA_KEYPAIR_B: RsaKeyPair =
            RsaKeyPair::from_pkcs8(RAW_RSA_KEYPAIR_B).unwrap();
        pub static ref RAW_RSA_PUBKEY_A: Vec<u8> = RSA_KEYPAIR_A.public_key().as_ref().to_owned();
        pub static ref RAW_RSA_PUBKEY_B: Vec<u8> = RSA_KEYPAIR_B.public_key().as_ref().to_owned();
        pub static ref RSA_PUBKEY_A: UnparsedPublicKey<Vec<u8>> =
            new_unparsed_public_key(RAW_RSA_KEYPAIR_A.to_owned());
        pub static ref RSA_PUBKEY_B: UnparsedPublicKey<Vec<u8>> =
            new_unparsed_public_key(RAW_RSA_KEYPAIR_B.to_owned());
    }
}

pub mod user {
    use super::signature_keys::*;
    use crate::model::user::User;

    lazy_static! {
        pub static ref USER_A: User =
            User::new_with_pkcs8_keypair("aid".to_owned(), "A".to_owned(), RAW_RSA_KEYPAIR_A)
                .unwrap();
        pub static ref USER_B: User =
            User::new_with_pkcs8_keypair("bid".to_owned(), "B".to_owned(), RAW_RSA_KEYPAIR_B)
                .unwrap();
    }
}

pub mod patch {
    use crate::model::snapshot::{PatchStr, Snapshot};

    lazy_static! {
        pub static ref EMPTY: Snapshot = String::new().into();
        pub static ref DOC_A: Snapshot = "i'm version A\nlook at meeeee".to_owned().into();
        pub static ref DOC_B: Snapshot = "i'm version B\nlook at meeeee.\nI'm the best, it's true"
            .to_owned()
            .into();
        pub static ref PATCH_EMPTY_A: PatchStr = DOC_A.diff(&*EMPTY);
        pub static ref PATCH_A_B: PatchStr = DOC_B.diff(&*DOC_A);
    }
}

pub mod commit {
    use super::patch::{PATCH_A_B, PATCH_EMPTY_A};
    use super::user::{USER_A, USER_B};
    use crate::model::commit::{Commit, CommitBuilder};

    lazy_static! {
        pub static ref COMMIT_0: Commit =
            CommitBuilder::root_commit("initial commit".to_owned(), PATCH_EMPTY_A.to_owned())
                .author(&*USER_A)
                .unwrap();
        pub static ref COMMIT_1: Commit = CommitBuilder::from_commit(
            &*COMMIT_0,
            "fixing A's stuff".to_owned(),
            PATCH_A_B.to_owned()
        )
        .author(&*USER_B)
        .unwrap();
    }
}

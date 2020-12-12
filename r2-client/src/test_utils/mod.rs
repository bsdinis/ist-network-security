pub mod certs {
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;
    use openssl_utils::{ValidCertificate, X509Ext};

    pub const RAW_CA_CERT: &[u8] = include_bytes!("ca.cert.pem");
    pub const RAW_CLIENT_A_AUTH_KEY: &[u8] = include_bytes!("clientA-auth.key.pem");
    pub const RAW_CLIENT_A_AUTH_CERT: &[u8] = include_bytes!("clientA-auth.cert.pem");
    pub const RAW_CLIENT_A_SIGN_KEY: &[u8] = include_bytes!("clientA-sign.key.pem");
    pub const RAW_CLIENT_A_SIGN_CERT: &[u8] = include_bytes!("clientA-sign.cert.pem");
    pub const RAW_CLIENT_B_AUTH_KEY: &[u8] = include_bytes!("clientB-auth.key.pem");
    pub const RAW_CLIENT_B_AUTH_CERT: &[u8] = include_bytes!("clientB-auth.cert.pem");
    pub const RAW_CLIENT_B_SIGN_KEY: &[u8] = include_bytes!("clientB-sign.key.pem");
    pub const RAW_CLIENT_B_SIGN_CERT: &[u8] = include_bytes!("clientB-sign.cert.pem");

    lazy_static! {
        pub static ref CA_CERT: X509 = X509::from_pem(RAW_CA_CERT).unwrap();
        pub static ref CLIENT_A_AUTH_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(RAW_CLIENT_A_AUTH_KEY).unwrap();
        pub static ref CLIENT_A_AUTH_CERT: ValidCertificate =
            X509::from_pem(RAW_CLIENT_A_AUTH_CERT)
                .unwrap()
                .validate(&*CA_CERT, &vec![])
                .unwrap();
        pub static ref CLIENT_A_SIGN_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(RAW_CLIENT_A_SIGN_KEY).unwrap();
        pub static ref CLIENT_A_SIGN_CERT: ValidCertificate =
            X509::from_pem(RAW_CLIENT_A_SIGN_CERT)
                .unwrap()
                .validate(&*CA_CERT, &vec![])
                .unwrap();
        pub static ref CLIENT_B_AUTH_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(RAW_CLIENT_B_AUTH_KEY).unwrap();
        pub static ref CLIENT_B_AUTH_CERT: ValidCertificate =
            X509::from_pem(RAW_CLIENT_B_AUTH_CERT)
                .unwrap()
                .validate(&*CA_CERT, &vec![])
                .unwrap();
        pub static ref CLIENT_B_SIGN_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(RAW_CLIENT_B_SIGN_KEY).unwrap();
        pub static ref CLIENT_B_SIGN_CERT: ValidCertificate =
            X509::from_pem(RAW_CLIENT_B_SIGN_CERT)
                .unwrap()
                .validate(&*CA_CERT, &vec![])
                .unwrap();
    }
}

pub mod user {
    use super::certs::*;
    use crate::model::{CommitAuthor, DocCollaborator, Me};

    lazy_static! {
        pub static ref ME_A: Me = Me::from_certs(
            &*CA_CERT,
            CLIENT_A_SIGN_KEY.to_owned(),
            CLIENT_A_SIGN_CERT.cert.to_owned(),
            CLIENT_A_AUTH_KEY.to_owned(),
            CLIENT_A_AUTH_CERT.cert.to_owned(),
        )
        .unwrap();
        pub static ref COMMIT_AUTHOR_A: CommitAuthor =
            CommitAuthor::from_certificate(CLIENT_A_SIGN_CERT.cert.to_owned(), &*CA_CERT).unwrap();
        pub static ref DOC_COLLABORATOR_A: DocCollaborator =
            DocCollaborator::from_certificate(CLIENT_A_AUTH_CERT.cert.to_owned(), &*CA_CERT)
                .unwrap();
        pub static ref ME_B: Me = Me::from_certs(
            &*CA_CERT,
            CLIENT_B_SIGN_KEY.to_owned(),
            CLIENT_B_SIGN_CERT.cert.to_owned(),
            CLIENT_B_AUTH_KEY.to_owned(),
            CLIENT_B_AUTH_CERT.cert.to_owned(),
        )
        .unwrap();
        pub static ref COMMIT_AUTHOR_B: CommitAuthor =
            CommitAuthor::from_certificate(CLIENT_B_SIGN_CERT.cert.to_owned(), &*CA_CERT).unwrap();
        pub static ref DOC_COLLABORATOR_B: DocCollaborator =
            DocCollaborator::from_certificate(CLIENT_B_AUTH_CERT.cert.to_owned(), &*CA_CERT)
                .unwrap();
    }
}

pub mod patch {
    use crate::model::{PatchStr, Snapshot};

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
    use super::user::{ME_A, ME_B};
    use crate::model::{Commit, CommitBuilder};

    lazy_static! {
        pub static ref COMMIT_0: Commit =
            CommitBuilder::root_commit("initial commit".to_owned(), PATCH_EMPTY_A.to_owned())
                .author(&*ME_A)
                .unwrap();
        pub static ref COMMIT_1: Commit = CommitBuilder::from_commit(
            &*COMMIT_0,
            "fixing A's stuff".to_owned(),
            PATCH_A_B.to_owned()
        )
        .author(&*ME_B)
        .unwrap();
    }
}

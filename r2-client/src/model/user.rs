use ring::signature::{RsaKeyPair, UnparsedPublicKey};

pub struct User<B: AsRef<[u8]>> {
    pub id: String,
    pub name: String,
    pub pubkey: UnparsedPublicKey<B>,
    pub privkey: Option<RsaKeyPair>,
}

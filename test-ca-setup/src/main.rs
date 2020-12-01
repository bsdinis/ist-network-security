use maplit::hashmap;
use openssl::asn1::*;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::*;
use structopt::StructOpt;

use std::collections::HashMap;
use std::collections::HashSet;

use std::fs;

use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_SERIAL_NUMBER: AtomicU32 = AtomicU32::new(0);

type Error = Box<dyn std::error::Error>;

/// A CA/node key generator for the r2 test environment
///
/// Creates a (self-signed) CA (ca.{key,pem})
///
/// Creates (TLS)authentication and signature keypairs for clients with certificates signed by the CA (<client>-{auth,sig}.{cert,key}.pem)
///
/// Creates a keypair and certificate for the servers (TLS) (<server hostname>.{cert,key}.pem)
#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct Options {
    /// Client name (CN field in certificate). "ca" is reserved for the CA.
    #[structopt(short = "c", long = "client")]
    clients: Vec<String>,

    /// Server name (CN field and DNS hostname in certificate). "ca" is reserved for the CA.
    #[structopt(short = "s", long = "server")]
    pub servers: Vec<String>,

    /// Number of bits in RSA key
    #[structopt(short = "b", long = "bits", default_value = "4096")]
    pub rsa_bits: u32,

    /// Prefix to give all key file names
    #[structopt(short = "p", long = "prefix", default_value = "")]
    pub prefix: String,

    #[structopt(skip)]
    pub client_keys: Vec<String>,
}

impl Options {
    pub fn from_args_parsed() -> Self {
        let mut options: Options = Options::from_args();

        if !options.node_names().all(|name| name != "ca") {
            panic!("I told you: \"ca\" is not a valid name for a client/server");
        }

        options.client_keys = options
            .clients
            .iter()
            .flat_map(|c| vec![format!("{}-auth", c), format!("{}-sign", c)])
            .collect();

        let mut unique = HashSet::new();
        for name in options.node_key_names() {
            if !unique.insert(name) {
                panic!("Duplicate key name: {}", name);
            }
        }

        options
    }

    pub fn node_names(&self) -> impl Iterator<Item = &String> {
        self.clients.iter().chain(self.servers.iter())
    }

    pub fn node_key_names(&self) -> impl Iterator<Item = &String> {
        self.servers.iter().chain(self.client_keys.iter())
    }
}

fn main() -> Result<(), Error> {
    let options: Options = Options::from_args_parsed();

    let mut keys = HashMap::new();

    let ca_key = gen_key(&options);
    keys.insert("ca".to_owned(), ca_key.clone());

    for name in options.node_key_names() {
        let key = gen_key(&options);

        keys.insert(name.to_owned(), key);
    }

    let mut certs = HashMap::new();

    let ca_name = x509_name("ca")?;
    let mut ca_cert_builder = x509_builder(&ca_name, "ca", &ca_key)?;
    ca_cert_builder.add_extensions2(hashmap! {
        "basicConstraints" => "CA:true",
        "keyUsage" => "digitalSignature, nonRepudiation, keyCertSign, cRLSign",
    })?;
    ca_cert_builder.sign(&ca_key, MessageDigest::sha512())?;
    let ca_cert = ca_cert_builder.build();
    certs.insert("ca".to_owned(), ca_cert.clone());

    for ref name in options.servers {
        let key = &keys[name];
        let mut cert_builder = x509_builder(&ca_name, &name, key)?;

        let subject_alt_name = format!("DNS.0:{}", &name);
        cert_builder.add_extensions(
            &ca_cert,
            hashmap! {
                "basicConstraints" => "CA:false",
                "keyUsage" => "digitalSignature, keyEncipherment, keyAgreement",
                "extendedKeyUsage" => "serverAuth",
                "subjectAltName" => &subject_alt_name,
            },
        )?;

        cert_builder.sign(&ca_key, MessageDigest::sha512())?;
        let cert = cert_builder.build();
        certs.insert(name.to_owned(), cert);
    }

    for ref name in options.client_keys {
        let key = &keys[name];
        let mut cert_builder = x509_builder(&ca_name, &name, key)?;

        if name.ends_with("-auth") {
            cert_builder.add_extensions(
                &ca_cert,
                hashmap! {
                    "basicConstraints" => "CA:false",
                    "keyUsage" => "digitalSignature, keyAgreement, keyEncipherment",
                    "extendedKeyUsage" => "clientAuth",
                },
            )?;
        } else if name.ends_with("-sign") {
            cert_builder.add_extensions(
                &ca_cert,
                hashmap! {
                    "basicConstraints" => "CA:false",
                    "keyUsage" => "digitalSignature, nonRepudiation",
                },
            )?;
        } else {
            panic!("someone dun goofed making certificates");
        }

        cert_builder.sign(&ca_key, MessageDigest::sha512())?;
        let cert = cert_builder.build();
        certs.insert(name.to_owned(), cert);
    }

    for (name, key) in keys {
        let key = key.private_key_to_pem_pkcs8()?;

        fs::write(format!("{}{}.key.pem", options.prefix, &name), &key)
            .expect(&format!("failed to save key {}", name));
    }

    for (name, cert) in certs {
        let cert = cert.to_pem()?;

        fs::write(format!("{}{}.cert.pem", options.prefix, &name), &cert)
            .expect(&format!("failed to save cert {}", name));
    }

    Ok(())
}

fn gen_key(options: &Options) -> PKey<Private> {
    let rsa = Rsa::generate(options.rsa_bits).expect("Failed to generate RSA key");

    PKey::from_rsa(rsa).unwrap()
}

fn x509_name(cn: &str) -> Result<X509Name, Error> {
    let mut builder = X509NameBuilder::new()?;
    builder.append_entry_by_text("CN", &cn)?;
    builder.append_entry_by_text("C", "PT")?;
    builder.append_entry_by_text("L", "Lisboa")?;
    builder.append_entry_by_text("O", "Universidade de Lisboa")?;
    builder.append_entry_by_text("OU", "Instituto Superior Técnico / SIRS G41")?;
    Ok(builder.build())
}

fn x509_builder(
    ca_name: &X509Name,
    subj_name: &str,
    key: &PKey<Private>,
) -> Result<X509Builder, Error> {
    let now = Asn1Time::days_from_now(0)?;
    let now_1y = Asn1Time::days_from_now(365)?;
    let serial_number = NEXT_SERIAL_NUMBER.fetch_add(1, Ordering::Relaxed);
    let serial_number = BigNum::from_u32(serial_number)?;
    let serial_number = Asn1Integer::from_bn(&serial_number)?;
    let subj_name = x509_name(subj_name)?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_not_before(&now)?;
    builder.set_not_after(&now_1y)?;
    builder.set_serial_number(&serial_number)?;
    builder.set_issuer_name(&ca_name)?;
    builder.set_subject_name(&subj_name)?;
    builder.set_pubkey(&key)?;

    Ok(builder)
}

trait X509BuilderExt {
    fn add_extensions(&mut self, ca_cert: &X509, ext: HashMap<&str, &str>) -> Result<(), Error>;
    fn add_extensions2(&mut self, ext: HashMap<&str, &str>) -> Result<(), Error>;
}

impl X509BuilderExt for X509Builder {
    fn add_extensions(&mut self, ca_cert: &X509, ext: HashMap<&str, &str>) -> Result<(), Error> {
        for (k, v) in ext {
            let context = self.x509v3_context(Some(ca_cert), None);
            let extension = X509Extension::new(None, Some(&context), k, v)?;
            self.append_extension(extension)?;
        }

        Ok(())
    }

    fn add_extensions2(&mut self, ext: HashMap<&str, &str>) -> Result<(), Error> {
        for (k, v) in ext {
            let context = self.x509v3_context(None, None);
            let extension = X509Extension::new(None, Some(&context), k, v)?;
            self.append_extension(extension)?;
        }

        Ok(())
    }
}

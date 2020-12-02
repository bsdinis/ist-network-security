use argh::FromArgs;
use protos::identity_server::IdentityServer;
use service::IdentityService;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tonic::transport::Server;

use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;

mod service;

type Error = Box<dyn std::error::Error>;

/// Options
#[derive(FromArgs)]
struct Options {
    /// cert files
    #[argh(positional)]
    cert_paths: Vec<PathBuf>,

    /// bind addr
    #[argh(option, short = 'l')]
    addr: String,
}

fn load_certs(options: &Options) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut map = HashMap::new();

    for cert_path in &options.cert_paths {
        let (pubkey_fingerprint, cert_bytes) =
            load_cert(cert_path).expect(&format!("Failed to load certificate {:?}", cert_path));

        map.insert(pubkey_fingerprint, cert_bytes);
    }
    map
}

fn load_cert(path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let cert_bytes = fs::read(path)?;
    let cert = X509::from_pem(&cert_bytes)?;

    let pubkey_bytes = cert.public_key()?.rsa()?.public_key_to_der()?;

    let pubkey_fingerprint = hash(MessageDigest::sha3_256(), &pubkey_bytes)?.to_vec();

    Ok((pubkey_fingerprint, cert_bytes))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options: Options = argh::from_env();
    let map = load_certs(&options);

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let server = Server::builder()
        .add_service(IdentityServer::new(IdentityService::new(map)))
        .serve_with_shutdown(addr, ctrl_c());

    println!("Sever listening on {:?}", addr);
    server.await?;

    println!("Bye!");
    Ok(())
}

async fn ctrl_c() {
    use std::future;

    if let Err(_) = tokio::signal::ctrl_c().await {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

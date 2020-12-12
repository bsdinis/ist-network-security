use eyre::{Result, WrapErr};
use argh::FromArgs;
use protos::identity_server::IdentityServer;
use service::IdentityService;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;

mod service;

/// Options
#[derive(FromArgs)]
struct Options {
    /// cert files
    #[argh(positional)]
    cert_paths: Vec<PathBuf>,

    /// bind addr
    #[argh(option, short = 'l')]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// CA cert file (for client authentication)
    #[argh(option, short = 'a')]
    ca_cert: PathBuf,
}

fn load_certs(options: &Options) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let mut map = HashMap::new();

    for cert_path in &options.cert_paths {
        let (pubkey_fingerprint, cert_bytes) =
            load_cert(cert_path)
                .wrap_err_with(|| format!("Failed to load certificate {:?}", cert_path))?;

        map.insert(pubkey_fingerprint, cert_bytes);
    }

    Ok(map)
}

fn load_cert(path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert_bytes = fs::read(path)
        .wrap_err_with(|| format!("Failed to read certificate {:?}", path))?;
    let cert = X509::from_pem(&cert_bytes)
        .wrap_err_with(|| format!("Failed to parse certificate as PEM {:?}", path))?;

    let pubkey_bytes = cert.public_key()?.rsa()?.public_key_to_der()?;

    let pubkey_fingerprint = hash(MessageDigest::sha3_256(), &pubkey_bytes)?.to_vec();

    Ok((pubkey_fingerprint, cert_bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let options: Options = argh::from_env();
    let map = load_certs(&options)
        .wrap_err("Failed to load certificates into store")?;

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let cert = tokio::fs::read(options.cert).await
        .wrap_err("Failed to read server certificate")?;
    let key = tokio::fs::read(options.key).await
        .wrap_err("Failed to read server key")?;
    let server_identity = Identity::from_pem(cert, key);

    let ca_cert_file = tokio::fs::read(options.ca_cert).await
        .wrap_err("Failed to read CA certificate")?;
    let ca_cert = Certificate::from_pem(ca_cert_file);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(ca_cert);

    let server = Server::builder()
        .tls_config(tls_config)
            .wrap_err("Failed to configure TLS for server")?
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

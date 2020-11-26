use argh::FromArgs;
use protos::identity_server::IdentityServer;
use service::IdentityService;
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tonic::transport::Server;

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
}

fn load_certs(options: &Options) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut map = HashMap::new();

    for cert_path in &options.cert_paths {
        let file = std::fs::File::open(cert_path)
            .expect(&format!("Failed to open certificate {:?}", cert_path));

        let mut reader = BufReader::new(file);

        let cert = x509_parser::pem::Pem::read(&mut reader)
            .expect(&format!("Bad certificate {:?}", cert_path));
        let cert = cert
            .0
            .parse_x509()
            .expect(&format!("Bad certificate {:?}", cert_path));
        reader.seek(SeekFrom::Start(0)).unwrap();

        let mut cert_bytes: Vec<u8> = Vec::new();
        reader.read_to_end(&mut cert_bytes).unwrap();

        let pubkey = cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .as_ref()
            .to_owned();

        map.insert(pubkey, cert_bytes);
    }
    map
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

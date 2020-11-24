use std::fs;
use std::convert::{TryFrom, TryInto};
use std::path::PathBuf;

use argh::FromArgs;
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity, Uri};
use tonic::Request;
use protos::HelloWorldRequest;
use protos::client_api_client::ClientApiClient;

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// server URI
    #[argh(positional)]
    server_addr: Uri,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'a')]
    ca_cert_path: PathBuf,

    /// key
    #[argh(option, short = 'k')]
    key_path: PathBuf,

    /// cert
    #[argh(option, short = 'c')]
    cert_path: PathBuf,
}

struct ClientConfig {
    server_addr: Uri,
    tls_config: ClientTlsConfig,
}

impl TryFrom<Options> for ClientConfig {
    type Error = Box<dyn std::error::Error>;

    fn try_from(options: Options) -> Result<Self, Self::Error> {
        let cert = fs::read(options.cert_path)?;
        let key = fs::read(options.key_path)?;
        let identity = Identity::from_pem(cert, key);

        let ca_cert_file = fs::read(options.ca_cert_path)?;
        let ca_cert = Certificate::from_pem(ca_cert_file);

        let mut tls_config = ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(ca_cert);

        if let Some(domain) = options.domain {
            tls_config = tls_config.domain_name(domain);
        }

        Ok(ClientConfig {
            server_addr: options.server_addr,
            tls_config,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: ClientConfig = argh::from_env::<Options>().try_into()?;
    let channel = Channel::builder(config.server_addr)
        .tls_config(config.tls_config)?
        .connect().await?;

    let mut client = ClientApiClient::new(channel);
    let resp = client.hello(Request::new(HelloWorldRequest {
        name: "Pedro".to_owned()
    })).await?.into_inner();

    println!("Response: {}", resp.resp);

    Ok(())
}

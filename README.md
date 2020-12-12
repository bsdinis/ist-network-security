# r2-store

r2-store is a ransomware resistance document storage system, built to defend against ransomware attacks by replicating the storage and employing consensus to protect the document.

## Requirements
- Rust v1.48.0
- OpenSSL (with development headers)

## Compiling

`cargo build`

## Running tests

`cargo test`

## Running

All binaries will be in `./target/debug/`

Generate test certificates with `test-ca-setup`, passing `-c <client name>` for every client and `-s <server hostname>` for every server.

Start the identity server: `r2-identity <certificate 1> <certificate 2> <certificate 3> ... -l <hostname>:<port> -c <identity cert> -k <identity key>`

Start the server: `r2-server -c <server cert> -k <server key> -a <ca cert> <host>:<port>`

For the client set the relevant environment variables (can also be passed as command line parameters but this is easier):
```
export R2_AUTH_CERT=<path to clientname-auth.cert.pem>
export R2_AUTH_KEY=<path to clientname-auth.key.pem>
export R2_SIGN_CERT=<path to clientname-sign.cert.pem>
export R2_SIGN_KEY=<path to clientname-sign.key.pem>
export R2_IDENTITY_SERVER=https://<identity server hostname>:<identity server port>
export R2_SERVER=https://<r2 server hostname>:<r2 server port>
```

A repository can be created with `r2 <existing file name> init <initial commit message>`.

A repository can be cloned with `r2 <dest file name> clone <remote document id>`.

Commit data with `r2 <dest file name> commit <message>`.

Pull changes with `r2 <dest file name> pull`.

Other commands are available with a similar syntax to their `git` equivalents (`fetch`, `log`, `diff`, `reset`).

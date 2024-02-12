pub mod server;

use rustls::{Certificate, PrivateKey};
use server::Server;
use std::{error::Error, fs::File, io::BufReader, process};

#[tokio::main]
async fn main() {
    match run().await {
        Ok(_) => {
            // everything fine
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("server")
        .bin_name("server")
        .about("UDP-tunnel server")
        .arg(
            clap::arg!(-b --"bind" "Server end-point (i.e. 0.0.0.0:21473)")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(std::net::SocketAddr)),
        )
        .arg(
            clap::arg!(-c --"certificate-file" "Certificate to use for QUIC protocol")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            clap::arg!(-p --"private-key-file" "Private key to use for QUIC protocol")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)),
        );

    let args = cmd.get_matches();
    let bind = args.get_one::<std::net::SocketAddr>("bind").unwrap();
    let certificate_file = args.get_one::<String>("certificate-file").unwrap();
    let private_key_file = args.get_one::<String>("private-key-file").unwrap();

    let certs = load_certs(&certificate_file)?;
    let private_key = load_private_key(private_key_file)?;

    let server = Server::new();
    server.run(*bind, certs, private_key).await?;
    Ok(())
}

fn load_certs(filename: &String) -> Result<Vec<Certificate>, Box<dyn Error>> {
    let cert_file = File::open(filename)?;
    let mut reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader).map(|c| Certificate(c.unwrap().as_ref().to_vec())).collect();
    Ok(certs)
}

fn load_private_key(filename: &String) -> Result<PrivateKey, Box<dyn Error>> {
    let cert_file = File::open(filename)?;
    let mut reader = BufReader::new(cert_file);
    let private_key = PrivateKey(rustls_pemfile::private_key(&mut reader)?.unwrap().secret_der().to_vec());
    Ok(private_key)
}
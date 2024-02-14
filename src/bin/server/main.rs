pub mod server;
pub mod cert_resolver;

use cert_resolver::CertResolver;
use hole_punching::udp_hole_punching::protocol::DEFAULT_SERVER_PORT;
use server::Server;
use tokio::signal::unix::{signal, SignalKind};
use std::{error::Error, process, sync::Arc};

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
    let default_bind = format!("0.0.0.0:{}", DEFAULT_SERVER_PORT);

    let cmd = clap::Command::new("server")
        .bin_name("server")
        .about("UDP-tunnel server")
        .arg(
            clap::Arg::new("bind")
                .short('b')
                .long("bind")
                .help(format!("Server end-point (i.e. {})", default_bind))
                .default_value(default_bind)
                .action(clap::ArgAction::Set)
                .value_parser(clap::value_parser!(std::net::SocketAddr)),
        )
        .arg(
            clap::Arg::new("certificate-file")
                .short('c')
                .long("certificate-file")
                .help("Certificate to use for QUIC protocol")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            clap::Arg::new("private-key-file")
                .short('k')
                .long("private-key-file")
                .help("Private key to use for QUIC protocol")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)),
        );

    let args = cmd.get_matches();
    let bind = args.get_one::<std::net::SocketAddr>("bind").unwrap();
    let certificate_file = args.get_one::<String>("certificate-file").unwrap();
    let private_key_file = args.get_one::<String>("private-key-file").unwrap();

    let cert_resolver = Arc::new(CertResolver::new(certificate_file.clone(), private_key_file.clone()));
    cert_resolver.reload().await?;

    let mut sighup = signal(SignalKind::hangup())?;
    let copy = cert_resolver.clone();
    tokio::spawn(async move {
        loop {
            sighup.recv().await;
            match copy.reload().await {
                Ok(_) => {},
                Err(e) => eprintln!("error loading certificates: {}", e)
            }
        }
    });

    let server = Server::new();
    server.run(*bind, cert_resolver).await?;
    Ok(())
}

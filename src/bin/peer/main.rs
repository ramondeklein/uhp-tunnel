pub mod client;
pub mod packet;
pub mod tunnel;

use client::{connect, listen};
use hole_punching::udp_hole_punching::common::send_command;
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::Certificate;
use std::{env, error::Error, sync::Arc, time::Duration};
use std::net::ToSocketAddrs;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("peer")
        .bin_name("peer")
        .subcommand_required(true)
        .subcommand(
            clap::command!("connect")
                .about("connects to another peer")
                .arg(
                    clap::arg!(-s --"server" "Server end-point (i.e. 192.145.12.1:21473)")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    clap::arg!(-l --"local-id" "Local identifier")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    clap::arg!(-r --"remote-id" "Remote identifier (where to connect to)")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    clap::arg!(-e --"tunnel-endpoint" "Remote end-point")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            clap::command!("listen")
                .about("listens for incoming connections")
                .arg(
                    clap::arg!(-s --"server" "Server end-point (i.e. 192.145.12.1:21473)")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    clap::arg!(-l --"local-id" "Local identifier")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                ),
        );

    match cmd.get_matches().subcommand() {
        Some(("listen", args)) => {
            let server = args.get_one::<String>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();

            let cert = rcgen::generate_simple_self_signed(vec![local_id.into()]).unwrap();
            let pub_cert = rustls::Certificate(cert.serialize_der()?);
            let priv_key = rustls::PrivateKey(cert.serialize_private_key_der());

            println!("about to listen on server '{}' for incoming connections", server);

            let server_addr = server.to_socket_addrs().unwrap().next().unwrap();
            let config = ServerConfig::with_single_cert(vec![pub_cert.clone()], priv_key)?;
            let mut endpoint = quinn::Endpoint::server(config, "0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(get_client_config());
            let conn = endpoint.connect(server_addr, "local.int.ramondeklein.nl")?.await?;
            let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

            // advertise
            let advertise_cmd = ProtocolCommand::Advertise { id: local_id.clone(), pub_cert: pub_cert.as_ref().to_vec() };
            send_command(&mut send_stream, &advertise_cmd).await?;

            loop {
                match listen(&mut recv_stream).await {
                    Ok(remote_peer) => {
                        match endpoint.accept().await {
                            Some(c) => {
                                println!(
                                    "{}: accepted connection from '{}'",
                                    remote_peer.addr, remote_peer.id
                                );
        
                                let conn = c.await?;
                                let tunnel_endpoint = remote_peer.tunnel_endpoint.parse()?;
                                
                                tokio::spawn(async move {
                                    tunnel::listen(conn, tunnel_endpoint).await;
                                });
                            },
                            None => {
                                return Ok(());
                            }
                        }    
                    },
                    Err(err) => {
                        eprintln!("unable to listen: {}", err);
                        break;
                    }
                }
            }
        }
        Some(("connect", args)) => {
            let server = args.get_one::<String>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();
            let remote_id = args.get_one::<String>("remote-id").unwrap();
            let tunnel_endpoint = args.get_one::<String>("tunnel-endpoint").unwrap();

            let server_addr = server.to_socket_addrs().unwrap().next().unwrap();
            
            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(get_client_config());
            let conn = endpoint.connect(server_addr, "local.int.ramondeklein.nl")?.await?;
            let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

            println!(
                "about to connect to server '{}' to set up the '{}' tunnel to '{}'",
                server, tunnel_endpoint, remote_id
            );
            let remote_peer =
                connect(&mut send_stream, &mut recv_stream, local_id, remote_id, tunnel_endpoint).await?;
            
            let mut certs = rustls::RootCertStore::empty();
            certs.add(&remote_peer.pub_cert)?;
            let mut transport = TransportConfig::default();
            transport.keep_alive_interval(Some(Duration::from_secs(3)));
            let mut client_config = quinn::ClientConfig::with_root_certificates(certs);
            client_config.transport_config(Arc::new(transport));
            let connection = endpoint.connect_with(client_config, remote_peer.addr, remote_peer.id.as_str())?.await?;
            sleep(Duration::from_millis(1000)).await; // wait one second to ensure both sides punched holes

            println!("connected to '{}' (end-point: {})", remote_peer.id, remote_peer.addr);
            tunnel::connect(connection).await;
        }
        _ => {}
    };

    Ok(())
}

fn get_client_config() -> ClientConfig {
    let native_certs = rustls_native_certs::load_native_certs().expect("could not load platform certs");
    let mut roots = rustls::RootCertStore::empty();
    for cert in native_certs {
        let c = Certificate(cert.as_ref().to_vec());
        roots.add(&c).unwrap();
    }
    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Option::Some(Duration::from_secs(5)));
    cfg.transport_config(Arc::new(transport));
    cfg
}
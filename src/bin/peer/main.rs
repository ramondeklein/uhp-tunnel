pub mod client;
pub mod tunnel;

use client::{connect, listen};
use hole_punching::udp_hole_punching::common::send_command;
use hole_punching::udp_hole_punching::protocol::{ProtocolCommand, DEFAULT_SERVER_PORT};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::Certificate;
use std::net::{SocketAddr, ToSocketAddrs};
use std::{env, error::Error, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

const DEFAULT_CLIENT_PORT: u16 = 21473;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    macro_rules! const_ids {
        ($($name:ident) *) => { $( const $name: &str = stringify!($name); )* };
    }
    
    const_ids!(SERVER_ARG LOCAL_ID_ARG TLS_HOSTNAME_ARG REMOTE_ID_ARG BIND_ARG TUNNEL_ENDPOINT_ARG);

    let server_arg = clap::Arg::new(SERVER_ARG)
        .short('s')
        .long("server")
        .help(format!("Server end-point (i.e. uhp-server.example.com:{})", DEFAULT_SERVER_PORT))
        .action(clap::ArgAction::Set)
        .required(true)
        .value_parser(clap::value_parser!(String));

    let local_id_arg = clap::Arg::new(LOCAL_ID_ARG)
        .short('l')
        .long("local-id")
        .help("Local identifier")
        .action(clap::ArgAction::Set)
        .required(true)
        .value_parser(clap::value_parser!(String));

    let tls_hostname_arg = clap::Arg::new(TLS_HOSTNAME_ARG)
        .short('t')
        .long("tls-hostname")
        .help("Use the specified hostname for the TLS handshake")
        .action(clap::ArgAction::Set)
        .value_parser(clap::value_parser!(String));

    let default_bind = format!("0.0.0.0:{}", DEFAULT_CLIENT_PORT);

    let cmd = clap::Command::new("peer")
        .bin_name("peer")
        .subcommand_required(true)
        .subcommand(
            clap::command!("connect")
                .about("connects to another peer")
                .arg(server_arg.clone())
                .arg(tls_hostname_arg.clone())
                .arg(local_id_arg.clone())
                .arg(
                    clap::Arg::new(BIND_ARG)
                        .short('b')
                        .long("bind")
                        .help(format!("Server end-point (i.e. {})", default_bind))
                        .action(clap::ArgAction::Set)
                        .default_value(default_bind)
                        .value_parser(clap::value_parser!(std::net::SocketAddr)),
                )
                        .arg(
                    clap::Arg::new(REMOTE_ID_ARG)
                        .short('r')
                        .long("remote-id")
                        .help("Remote identifier (where to connect to)")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    clap::Arg::new(TUNNEL_ENDPOINT_ARG)
                        .short('e')
                        .long("tunnel-endpoint")
                        .help("Remote end-point")
                        .action(clap::ArgAction::Set)
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            clap::command!("listen")
                .about("listens for incoming connections")
                .arg(server_arg)
                .arg(tls_hostname_arg)
                .arg(local_id_arg)
        );

    match cmd.get_matches().subcommand() {
        Some(("listen", args)) => {
            let server = args.get_one::<String>(SERVER_ARG).unwrap();
            let tls_hostname = args.get_one::<String>(TLS_HOSTNAME_ARG);
            let local_id = args.get_one::<String>(LOCAL_ID_ARG).unwrap();

            let HostAndPort {hostname, port} = split_server(server)?;

            let cert = rcgen::generate_simple_self_signed(vec![local_id.into()]).unwrap();
            let pub_cert = rustls::Certificate(cert.serialize_der()?);
            let priv_key = rustls::PrivateKey(cert.serialize_private_key_der());

            let server_addr = format!("{}:{}", hostname, port).to_socket_addrs()?.next().unwrap();
            let config = ServerConfig::with_single_cert(vec![pub_cert.clone()], priv_key)?;
            let mut endpoint = quinn::Endpoint::server(config, "0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(get_client_config());

            let effective_hostname = match tls_hostname {
                Some(hostname) => hostname,
                None => &hostname,
            };

            loop {
                match endpoint.connect(server_addr, effective_hostname.as_str())?.await
                {
                    Ok(conn) => {
                        println!("connected to server '{}'", server);
                        let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

                        // advertise
                        let advertise_cmd = ProtocolCommand::Advertise {
                            id: local_id.clone(),
                            pub_cert: pub_cert.as_ref().to_vec(),
                        };
                        send_command(&mut send_stream, &advertise_cmd).await?;

                        loop {
                            match listen(&mut recv_stream).await {
                                Ok(remote_peer) => {
                                    // Issue a dummy connect (will never be accepted)
                                    // to register the remote address in the NAT table
                                    punch_hole(remote_peer.addr, &endpoint).await;
                                    loop {
                                        match endpoint.accept().await {
                                            Some(c) => {
                                                println!("{}: accepted connection from '{}'", remote_peer.addr, remote_peer.id);
    
                                                match c.await {
                                                    Ok(conn) => {
                                                        tokio::spawn(async move {
                                                            tunnel::listen(conn, remote_peer.tunnel_endpoint).await;
                                                        });        
                                                        break;
                                                    },
                                                    Err(e) => {
                                                        eprintln!("{}: ignoring error: {}", remote_peer.addr, e);
                                                    }
                                                }
                                            }
                                            None => {
                                                return Ok(());
                                            }
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
                    Err(err) => {
                        eprintln!("unable to connect to '{}': {}", server, err);
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }
        Some(("connect", args)) => {
            let server = args.get_one::<String>(SERVER_ARG).unwrap();
            let tls_hostname = args.get_one::<String>(TLS_HOSTNAME_ARG);
            let local_id = args.get_one::<String>(LOCAL_ID_ARG).unwrap();
            let bind = args.get_one::<SocketAddr>(BIND_ARG).unwrap();
            let remote_id = args.get_one::<String>(REMOTE_ID_ARG).unwrap();
            let tunnel_endpoint = args.get_one::<String>(TUNNEL_ENDPOINT_ARG).unwrap();

            let HostAndPort {hostname, port} = split_server(server)?;

            let server_addr = format!("{}:{}", hostname, port).to_socket_addrs()?.next().unwrap();
            
            let effective_hostname = match tls_hostname {
                Some(hostname) => hostname,
                None => &hostname,
            };

            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(get_client_config());
            let conn = endpoint.connect(server_addr, &effective_hostname.as_str())?.await?;
            let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

            println!("about to connect to server '{}' to set up the '{}' tunnel to '{}'", server, tunnel_endpoint, remote_id);
            let remote_peer = connect(&mut send_stream, &mut recv_stream, local_id, remote_id, tunnel_endpoint).await?;

            punch_hole(remote_peer.addr, &endpoint).await;
            sleep(Duration::from_millis(500)).await; // wait one second to ensure both sides punched holes

            let mut certs = rustls::RootCertStore::empty();
            certs.add(&remote_peer.pub_cert)?;
            let mut transport = TransportConfig::default();
            transport.keep_alive_interval(Some(Duration::from_secs(3)));
            let mut client_config = quinn::ClientConfig::with_root_certificates(certs);
            client_config.transport_config(Arc::new(transport));
            let connection = endpoint.connect_with(client_config, remote_peer.addr, remote_peer.id.as_str())?.await?;

            println!("{}: connected to '{}'", remote_peer.addr, remote_peer.id);
            tunnel::connect(&bind, connection).await;
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

struct HostAndPort {
    hostname: String,
    port: u16,
}

fn split_server(server: &str) -> Result<HostAndPort, Box<dyn Error>> {
    let mut server_parts = server.splitn(2, ":");
    let hostname = server_parts.next().unwrap();
    let port = match server_parts.next() {
        Some(text) => text.parse::<u16>()?,
        None => DEFAULT_SERVER_PORT,
    };

    Ok(HostAndPort {
        hostname: hostname.into(),
        port: port,
    })
}

async fn punch_hole(remote_addr: SocketAddr, endpoint: &Endpoint) {
    // Issue a dummy connect (will never be accepted)
    // to register the remote address in the NAT table
    println!("{}: punching hole...", remote_addr);
    for _ in 1..3 {
        let c = endpoint.connect(remote_addr, "dummy.example.com").unwrap();
        let _ = timeout(Duration::from_millis(100), c).await;    
    }
}
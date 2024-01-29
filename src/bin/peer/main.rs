pub mod client;
pub mod packet;

use client::{connect, listen};
use futures::executor::block_on;
use futures::{future::FutureExt, pin_mut, select};
use quinn::{IdleTimeout, RecvStream, SendStream, VarInt};
use std::net::UdpSocket;
use std::thread;
use std::{env, error::Error, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
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
                        .value_parser(clap::value_parser!(std::net::SocketAddr)),
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
                        .value_parser(clap::value_parser!(std::net::SocketAddr)),
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
            let server = args.get_one::<std::net::SocketAddr>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();

            let cert = rcgen::generate_simple_self_signed(vec![local_id.into()]).unwrap();
            let pub_cert = rustls::Certificate(cert.serialize_der()?);
            let priv_key = rustls::PrivateKey(cert.serialize_private_key_der());

            println!(
                "about to listen on server '{}' for incoming connections",
                server
            );

            let socket = UdpSocket::bind("0.0.0.0:0")?;
            let remote_peer = listen(&socket, server, local_id, &pub_cert).await?;

            sleep(Duration::from_millis(1000)).await; // wait one second to ensure both sides punched holes

            println!(
                "accepted connection from '{}' (end-point: {})",
                remote_peer.id, remote_peer.addr
            );

            let mut server_config =
                quinn::ServerConfig::with_single_cert(vec![pub_cert], priv_key)?;
            let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
            transport_config.max_concurrent_uni_streams(1_u8.into());
            transport_config.max_concurrent_bidi_streams(4_u8.into());
            transport_config
                .max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(300))?));
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

            let runtime = quinn::default_runtime().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "no async runtime found")
            })?;
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket,
                runtime,
            )?;

            loop {
                println!("waiting for an incoming QUIC connection");
                match endpoint.accept().await {
                    Some(c) => {
                        let connection = c.await.unwrap();
                        let remote_addr = connection.remote_address();
                        println!("{}: got a new QUIC connection", remote_addr);

                        while let Ok(quic_stream) = connection.accept_bi().await {
                            let quic_id = quic_stream.0.id().index();
                            println!("{}/{}: got a new QUIC stream", remote_addr, quic_id);
                            match TcpStream::connect(&remote_peer.tunnel_endpoint).await {
                                Ok(mut tcp_stream) => {
                                    println!(
                                        "{}/{}: connected to connect to '{}'",
                                        remote_addr, quic_id, remote_peer.tunnel_endpoint
                                    );
                                    thread::spawn(move || {
                                        let msg = format!("{}/{}: ", remote_addr, quic_id);
                                        let (qtt, ttq) = block_on(forward_traffic(
                                            &msg,
                                            &mut tcp_stream,
                                            quic_stream,
                                        ));
                                        println!(
                                            "{}/{}: finished ({} bytes read, {} bytes written)",
                                            remote_addr, quic_id, qtt, ttq
                                        );
                                    });
                                }
                                Err(e) => {
                                    println!(
                                        "{}/{}: unable to connect to '{}': {}",
                                        remote_addr, quic_id, remote_peer.tunnel_endpoint, e
                                    );
                                    connection.close(VarInt::from_u32(0), e.to_string().as_bytes())
                                }
                            }
                        }
                    }
                    None => {
                        return Ok(());
                    }
                };
            }
        }
        Some(("connect", args)) => {
            let server = args.get_one::<std::net::SocketAddr>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();
            let remote_id = args.get_one::<String>("remote-id").unwrap();
            let tunnel_endpoint = args.get_one::<String>("tunnel-endpoint").unwrap();

            let socket = UdpSocket::bind("0.0.0.0:0")?;

            println!(
                "about to connect to server '{}' to set up the '{}' tunnel to '{}'",
                server, tunnel_endpoint, remote_id
            );
            let remote_peer =
                connect(&socket, server, local_id, remote_id, tunnel_endpoint).await?;
            sleep(Duration::from_millis(1000)).await; // wait one second to ensure both sides punched holes
            println!(
                "connected to '{}' (end-point: {})",
                remote_peer.id, remote_peer.addr
            );

            let runtime = quinn::default_runtime().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "no async runtime found")
            })?;
            let endpoint =
                quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;

            let mut certs = rustls::RootCertStore::empty();
            certs.add(&remote_peer.pub_cert)?;
            let client_config = quinn::ClientConfig::with_root_certificates(certs);
            let connection = endpoint
                .connect_with(client_config, remote_peer.addr, remote_peer.id.as_str())?
                .await?;

            let remote_addr = connection.remote_address();
            println!("{}: established QUIC connection", remote_addr);

            let listen_addr = SocketAddr::from(([127, 0, 0, 1], 21473));
            let tcp_listener = TcpListener::bind(listen_addr).await?;
            println!(
                "{}: waiting for TCP to accept on {}",
                remote_addr, listen_addr
            );

            while let Ok((mut tcp_stream, peer_addr)) = tcp_listener.accept().await {
                println!(
                    "{}: accepted TCP connection from {}",
                    remote_addr, peer_addr
                );

                let quic_stream = connection.open_bi().await.unwrap();
                let quic_id = quic_stream.0.id().index();
                println!("{}/{}: opened QUIC connection", remote_addr, quic_id);
                thread::spawn(move || {
                    let msg = format!("{}/{}: ", remote_addr, quic_id);
                    let (qtt, ttq) = block_on(forward_traffic(&msg, &mut tcp_stream, quic_stream));
                    println!(
                        "{}/{}: finished ({} bytes read, {} bytes written)",
                        remote_addr, quic_id, qtt, ttq
                    );
                });
            }
        }
        _ => {}
    };

    Ok(())
}

async fn forward_traffic(
    name: &String,
    tcp_stream: &mut TcpStream,
    quic_stream: (SendStream, RecvStream),
) -> (usize, usize) {
    let (mut bytes_read, mut bytes_written) = (0usize, 0usize);
    {
        let (s, r) = quic_stream;
        let (mut tr, mut ts) = split(tcp_stream);
        let qtt = quic_to_tcp(name, r, &mut ts, &mut bytes_read).fuse();
        let ttq = tcp_to_quic(name, &mut tr, s, &mut bytes_written).fuse();
        pin_mut!(qtt, ttq);
        select! {
            _ = qtt => {},
            _ = ttq => {},
        }
    }

    return (bytes_read, bytes_written);
}

async fn quic_to_tcp(
    name: &String,
    mut r: RecvStream,
    ts: &mut WriteHalf<&mut TcpStream>,
    bytes: &mut usize,
) {
    let mut rx_bytes = [0u8; 1000];

    loop {
        match r.read(&mut rx_bytes).await {
            Ok(Some(n)) => match ts.write_all(&rx_bytes[..n]).await {
                Ok(_) => *bytes = *bytes + n,
                Err(e) => {
                    println!("{}QUIC->TCP - Error writing: {}", name, e);
                    return;
                }
            },
            Ok(None) => return,
            Err(e) => {
                println!("{}QUIC->TCP - Error reading: {}", name, e);
                return;
            }
        }
    }
}

async fn tcp_to_quic(
    name: &String,
    tr: &mut ReadHalf<&mut TcpStream>,
    mut s: SendStream,
    bytes: &mut usize,
) {
    let mut rx_bytes = [0u8; 1000];
    loop {
        match tr.read(&mut rx_bytes).await {
            Ok(n) => {
                if n == 0 {
                    return;
                }
                match s.write_all(&rx_bytes[..n]).await {
                    Ok(_) => *bytes = *bytes + n,
                    Err(e) => {
                        println!("{}TCP->QUIC - Error writing: {}", name, e);
                        return;
                    }
                }
            }
            Err(e) => {
                println!("{}TCP->QUIC - Error reading: {}", name, e);
                return;
            }
        }
    }
}

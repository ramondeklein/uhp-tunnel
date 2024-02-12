use std::net::SocketAddr;

use futures::{future::FutureExt, pin_mut, select};
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};

pub async fn listen(connection: Connection, tunnel_endpoint: SocketAddr) {
    let remote_addr = connection.remote_address();
    println!("{}: listening for incoming connections", remote_addr);

    loop {
        match connection.accept_bi().await {
            Ok(quic_stream) => {
                let quic_id = quic_stream.0.id().index();
                println!("{}/{}: got a new QUIC stream", remote_addr, quic_id);
        
                tokio::task::spawn(async move {
                    match TcpStream::connect(&tunnel_endpoint).await {
                        Ok(mut tcp_stream) => {
                            println!(
                                "{}/{}: connected to connect to '{}'",
                                remote_addr, quic_id, tunnel_endpoint
                            );
                            let msg = format!("{}/{}: ", remote_addr, quic_id);
                            let (qtt, ttq) =
                                forward_traffic(&msg, &mut tcp_stream, quic_stream).await;
                            println!(
                                "{}/{}: finished ({} bytes read, {} bytes written)",
                                remote_addr, quic_id, qtt, ttq
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{}/{}: unable to connect to '{}': {}",
                                remote_addr, quic_id, tunnel_endpoint, e
                            );
                        }
                    }
                });
            },
            Err(err) => {
                eprintln!("{}: error listening for incoming connections: {}", remote_addr, err);
                break;
            }
        }
    }
}

pub async fn connect(connection: Connection) {
    let remote_addr = connection.remote_address();
    println!("{}: established QUIC connection", remote_addr);

    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 21473));
    match TcpListener::bind(listen_addr).await {
        Ok(tcp_listener) => {
            println!(
                "{}: waiting for TCP to accept on {}",
                remote_addr, listen_addr
            );
        
            while let Ok((mut tcp_stream, peer_addr)) = tcp_listener.accept().await {
                println!(
                    "{}: accepted TCP connection from {}",
                    remote_addr, peer_addr
                );
        
                match connection.open_bi().await {
                    Ok(quic_stream) => {
                        let quic_id = quic_stream.0.id().index();
                        println!("{}/{}: opened QUIC connection", remote_addr, quic_id);
                        tokio::task::spawn(async move {
                            let msg = format!("{}/{}: ", remote_addr, quic_id);
                            let (qtt, ttq) = forward_traffic(&msg, &mut tcp_stream, quic_stream).await;
                            println!(
                                "{}/{}: finished ({} bytes read, {} bytes written)",
                                remote_addr, quic_id, qtt, ttq
                            );
                        });
                    },
                    Err(err) => {
                        eprintln!("{}: error opening QUIC channel to listener: {}", remote_addr, err);
                        break;
                    }
                }
            }
        },
        Err(err) => {
            eprintln!("{}: error binding to local endpoint: {}", remote_addr, err);
        }
    }
}

async fn forward_traffic(
    name: &String,
    tcp_stream: &mut TcpStream,
    quic_stream: (SendStream, RecvStream),
) -> (usize, usize) {
    let (mut bytes_read, mut bytes_written) = (0_usize, 0_usize);
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

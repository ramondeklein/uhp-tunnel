use std::{error::Error, net::SocketAddr, time::Duration};
use hole_punching::udp_hole_punching::common::{send_command, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;
use quinn::{RecvStream, SendStream};
use tokio::time::timeout;

pub struct PeerInfoConnect {
    pub id: String,
    pub addr: SocketAddr,
    pub pub_cert: rustls::Certificate,
}

pub struct PeerInfoListen {
    pub id: String,
    pub addr: SocketAddr,
    pub tunnel_endpoint: String,
}

/// Listen for an incoming tunnel
/// 
/// This method is called by the peer that can be used as a tunnel target.
/// It will advertise itself to the server every 30 seconds using the
/// given certificate. The function returns when a peer has connected to
/// it.
/// 
/// The `socket` should already be bound and it will advertise itself to
/// `host`. The returned peer information will hold the identifier and
/// IP address of the remote peer.
pub async fn listen(recv_stream: &mut RecvStream) -> Result<PeerInfoListen, Box<dyn Error>> {
    let mut buf = vec![0u8; CTRL_SIZE];
    loop {
        match recv_stream.read(&mut buf).await {
            Ok(Some(n)) => {
                if n == 0 {
                    eprintln!("endpoint sent 0 bytes (ignored)");
                    continue;
                }
                if n >= CTRL_SIZE {
                    eprintln!("endpoint sent {n} bytes (ignored)");
                    continue;
                }
    
                // deserialize the incoming command
                match bincode::deserialize::<ProtocolCommand>(&buf)? {
                    // a connection is request
                    ProtocolCommand::ConnectRequest { id, addr, tunnel_endpoint } => {
                        return Ok(PeerInfoListen { addr: addr, id: id, tunnel_endpoint: tunnel_endpoint });
                    },
                    _ => eprintln!("endpoint sent invalid command"),
                };
            },
            Ok(None) => {
                /* NOP */
            }
            Err(e) => {
                return Err(Box::new(e));
            }
        }
    }
}

pub async fn connect(send_stream: &mut SendStream, recv_stream: &mut RecvStream, src_id: &String, dest_id: &String, tunnel_endpoint: &String) -> Result<PeerInfoConnect, Box<dyn Error>> {
    let connect_cmd = ProtocolCommand::Connect { src_id: src_id.clone(), dest_id: dest_id.clone(), tunnel_endpoint: tunnel_endpoint.clone() };
    send_command(send_stream, &connect_cmd).await?;

    let mut buf = vec![0u8; CTRL_SIZE];
    let connect_timeout = Duration::from_millis(30 * 1000);
    let n = timeout(connect_timeout, recv_stream.read(&mut buf)).await??.unwrap();
    if n == 0 {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "empty data")));
    }
    if n >= CTRL_SIZE {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "too much data")));
    }

    match bincode::deserialize::<ProtocolCommand>(&buf)? {
        ProtocolCommand::ConnectResponse { id, addr, pub_cert } => {
            return Ok(PeerInfoConnect { addr: addr, id: id, pub_cert: rustls::Certificate(pub_cert.unwrap()) });
        },
        _ => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "unexpected command"))),
    }
}


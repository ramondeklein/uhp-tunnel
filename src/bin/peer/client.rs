use std::net::UdpSocket;
use std::{error::Error, net::SocketAddr, time::Duration};
use hole_punching::udp_hole_punching::common::{send_command, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;

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
pub async fn listen(socket: &UdpSocket, host_addr: &SocketAddr, id: &String, pub_cert: &rustls::Certificate) -> Result<PeerInfoListen, Box<dyn Error>> {
    // keep advertising every 30 seconds, until a remote peer connects
    let advertisement_interval = Duration::from_secs(30);
    let advertise_cmd = ProtocolCommand::Advertise { id: id.clone(), pub_cert: pub_cert.as_ref().to_vec() };
    let mut buf = vec![0u8; CTRL_SIZE];
    loop {
        send_command(&socket, &host_addr, &advertise_cmd)?;

        socket.set_read_timeout(Some(advertisement_interval))?;
        while let Ok((n, addr)) = socket.recv_from(&mut buf) {
            if n == 0 {
                eprintln!("endpoint {addr} sent 0 bytes (ignored)");
                continue;
            }
            if n >= CTRL_SIZE {
                eprintln!("endpoint {addr} sent {n} bytes (ignored)");
                continue;
            }

            // deserialize the incoming command
            match bincode::deserialize::<ProtocolCommand>(&buf)? {
                // a connection is request
                ProtocolCommand::ConnectRequest { id, addr, tunnel_endpoint } => {
                    send_command(&socket, &addr, &ProtocolCommand::Hi { id: id.clone() })?;
                    return Ok(PeerInfoListen { addr: addr, id: id, tunnel_endpoint: tunnel_endpoint });
                },
                _ => eprintln!("endpoint {addr} sent invalid command"),
            };
        }
    }
}

pub async fn connect(socket: &UdpSocket, host: &SocketAddr, src_id: &String, dest_id: &String, tunnel_endpoint: &String) -> Result<PeerInfoConnect, Box<dyn Error>> {
    // advertise every 30s to keep the NAT hole intact
    let connect_cmd = ProtocolCommand::Connect { src_id: src_id.clone(), dest_id: dest_id.clone(), tunnel_endpoint: tunnel_endpoint.clone() };
    send_command(&socket, &host, &connect_cmd)?;

    let mut buf = vec![0u8; CTRL_SIZE];
    let connect_timeout = Duration::from_millis(30 * 1000);
    socket.set_read_timeout(Some(connect_timeout))?;
    let (n, _) = socket.recv_from(&mut buf)?;
    if n == 0 {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "empty data")));
    }
    if n >= CTRL_SIZE {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "too much data")));
    }

    match bincode::deserialize::<ProtocolCommand>(&buf)? {
        ProtocolCommand::ConnectResponse { id, addr, pub_cert } => {
            send_command(&socket, &addr, &ProtocolCommand::Hi { id: id.clone() })?;
            return Ok(PeerInfoConnect { addr: addr, id: id, pub_cert: rustls::Certificate(pub_cert.unwrap()) });
        },
        _ => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "unexpected command"))),
    }
}


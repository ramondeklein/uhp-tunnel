use std::net::UdpSocket;
use std::{collections::HashMap, error::Error, net::SocketAddr};

use hole_punching::udp_hole_punching::common::{send_command, send_error, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;

/// Peer structure holding all the information of an advertised peer.
pub struct PeerInfo {
    /// IP address of the peer
    addr: SocketAddr,
    /// Public certificate that should be used to encrypt data that is sent to
    /// the peer
    certificate: rustls::Certificate,
}

/// Server structure holding all the information about peers that have
/// advertised themselves to the server.
pub struct Server {
    /// Peers that have advertised to the server. The key is the peer
    /// identifier that is used to uniquely identify targets.
    /// 
    /// TODO: Expire identifier if no advertisement has been received
    ///       for a while.
    peers: HashMap<String, PeerInfo>,
}

impl Server {
    /// Creates a new socket server
    pub fn new() -> Server {
        Server {
            peers: HashMap::<String, PeerInfo>::new(),
        }
    }

    /// Run the server on the specified endpoint.
    ///
    /// This method actually creates a UDP socket on the given endpoint
    /// and starts listening for incoming commands.
    pub async fn run(&mut self, addr: &String) -> Result<(), Box<dyn Error>> {
        let socket = UdpSocket::bind(addr)?;
        loop {
            if let Err(e) = self.handle(&socket).await {
                eprintln!("{e}");
            }
        }
    }

    /// Handle an incoming message on the server UDP socket
    ///
    /// The command is deserialize and the appropriate handler will be called.
    async fn handle(&mut self, socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
        // receive the incoming message into the buffer
        let mut buf = vec![0u8; CTRL_SIZE];
        let (n, src_addr) = socket.recv_from(&mut buf)?;
        if n == 0 {
            send_error(socket, &src_addr, "no-command")?
        }
        if n >= CTRL_SIZE {
            send_error(socket, &src_addr, "command-too-large")?
        }

        // deserialize and call the appropriate handler
        match bincode::deserialize::<ProtocolCommand>(&buf)? {
            ProtocolCommand::Advertise { id, pub_cert } => {
                self.advertise_handler(src_addr, id, pub_cert)
            }
            ProtocolCommand::Connect { src_id, dest_id, tunnel_endpoint } => {
                self.connect_handler(socket, src_addr, src_id, dest_id, tunnel_endpoint)
                    .await
            }
            _ => send_error(&socket, &src_addr, "invalid-command"),
        }
    }

    /// Handle a peer's advertisement message
    ///
    /// The handler stores the advertised information in its administration for
    /// the specified peer identifier.
    fn advertise_handler(
        &mut self,
        src_addr: SocketAddr,
        id: String,
        cert: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        println!("Listener '{id}' is on endpoint '{src_addr}'");
        self.peers.insert(
            id,
            PeerInfo {
                addr: src_addr,
                certificate: rustls::Certificate(cert),
            },
        );
        Ok(())
    }

    /// Handle a peer's connect message
    /// 
    /// The connect message is received when a peer wants to initiate a tunnel
    /// with another peer. The handler checks if the requested peer is in its
    /// administration and if so, then it sends a `ProtocolCommand::ConnectResponse`
    /// to both the peer that requests the tunnel and the target peer.
    async fn connect_handler(
        &mut self,
        socket: &UdpSocket,
        src_addr: SocketAddr,
        src_id: String,
        dest_id: String,
        tunnel_endpoint: String
    ) -> Result<(), Box<dyn Error>> {
        println!("Peer '{src_id}' is on endpoint '{src_addr}'");
        match self.peers.get(&dest_id) {
            None => {
                eprintln!("'{src_id}' wants to connect to unknown destination '{dest_id}'");
                send_error(&socket, &src_addr, "destination-not-found")?
            }
            Some(peer_info) => {
                println!(
                    "'{src_id}' wants to connect to destination '{}' on end-point '{}'",
                    dest_id, peer_info.addr
                );
                send_command(
                    &socket,
                    &peer_info.addr,
                    &ProtocolCommand::ConnectRequest {
                        id: src_id,
                        addr: src_addr,
                        tunnel_endpoint: tunnel_endpoint,
                    },
                )?;
                // send to the source peer
                send_command(
                    &socket,
                    &src_addr,
                    &ProtocolCommand::ConnectResponse {
                        id: dest_id,
                        addr: peer_info.addr,
                        pub_cert: Some(peer_info.certificate.as_ref().to_vec()),
                    },
                )?;
            }
        }
        Ok(())
    }
}

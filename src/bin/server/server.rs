use std::sync::Arc;
use std::{collections::HashMap, error::Error, net::SocketAddr};

use hole_punching::udp_hole_punching::common::{send_command, send_error, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;
use quinn::SendStream;
use rustls::{Certificate, PrivateKey};
use tokio::sync::Mutex;

/// Peer structure holding all the information of an advertised peer.
pub struct PeerInfo {
    /// IP address of the peer
    addr: SocketAddr,
    /// Public certificate that should be used to encrypt data that is sent to
    /// the peer
    certificate: rustls::Certificate,
    /// Stream that is used to contact the peer
    send_stream: Arc<Mutex<SendStream>>,
}

/// Server structure holding all the information about peers that have
/// advertised themselves to the server.
pub struct Server {
    /// Peers that have advertised to the server. The key is the peer
    /// identifier that is used to uniquely identify targets.
    ///
    /// TODO: Expire identifier if no advertisement has been received
    ///       for a while.
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
}

impl Server {
    /// Creates a new socket server
    pub fn new() -> Server {
        Server {
            peers: Arc::new(Mutex::new(HashMap::<String, PeerInfo>::new())),
        }
    }

    /// Run the server on the specified endpoint.
    ///
    /// This method actually creates a UDP socket on the given endpoint
    /// and starts listening for incoming commands.
    pub async fn run(
        &self,
        addr: SocketAddr,
        certs: Vec<Certificate>,
        priv_key: PrivateKey,
    ) -> Result<(), Box<dyn Error>> {
        let server_config = quinn::ServerConfig::with_single_cert(certs, priv_key)?;
        let endpoint = quinn::Endpoint::server(server_config, addr)?;

        println!("waiting for an incoming QUIC connection");
        loop {
            match endpoint.accept().await {
                Some(c) => match c.await {
                    Ok(connection) => {
                        let src_addr = connection.remote_address();
                        println!("{}: got a new QUIC connection", src_addr);
    
                        let peers = self.peers.clone();
    
                        tokio::spawn(async move {
                            while let Ok((send_stream, mut recv_stream)) = connection.accept_bi().await
                            {
                                let quic_id = recv_stream.id().index();
                                println!("{}/{}: got a new QUIC stream", src_addr, quic_id);
                                let mut buf = vec![0u8; CTRL_SIZE];
                                match recv_stream.read(&mut buf).await {
                                    Ok(Some(n)) => {
                                        match bincode::deserialize::<ProtocolCommand>(&buf[..n]).unwrap()
                                        {
                                            ProtocolCommand::Advertise { id, pub_cert } 
                                                => advertise_handler(&peers, src_addr, id, pub_cert, send_stream).await,
                                            ProtocolCommand::Connect { src_id, dest_id, tunnel_endpoint } 
                                                => connect_handler(&peers, src_addr, send_stream, src_id, dest_id, tunnel_endpoint).await,
                                            _ => { 
                                                eprintln!("{}/{}: invalid command received.", src_addr, quic_id);
                                                break;
                                            }
                                        }
                                    },
                                    Ok(None) => eprintln!("{}/{}: nothing read", src_addr, quic_id),
                                    Err(e) => eprintln!("{e}"),
                                }
                            }
                            println!("{}: QUIC connection closed.", src_addr);
                            unadvertise_handler(&peers,src_addr).await;
                        });
    
                    },
                    Err(err) => eprintln!("Error during handshake: {}", err)
                }
                None => return Ok(())
            };
        }
    }
}

/// Handle a peer's advertisement message
///
/// The handler stores the advertised information in its administration for
/// the specified peer identifier.
async fn advertise_handler(peers: &Arc<Mutex<HashMap<String, PeerInfo>>>, src_addr: SocketAddr, id: String, cert: Vec<u8>, send_stream: SendStream) {
    println!("{src_addr}: Listener '{id}' registered");
    let mut peers = peers.lock().await;
    let data = Arc::new(Mutex::new(send_stream));
    let peer_info = PeerInfo {
        addr: src_addr,
        certificate: rustls::Certificate(cert),
        send_stream: data,
    };
    peers.insert(id, peer_info);
}

/// Handle a peer's un-advertisement
///
/// The handler stores the advertised information in its administration for
/// the specified peer identifier.
async fn unadvertise_handler(
    peers: &Arc<Mutex<HashMap<String, PeerInfo>>>,
    src_addr: SocketAddr
) {
    let mut peers = peers.lock().await;
    match find_id_by_addr(&peers, src_addr) {
        Some(id) => {
            println!("{}: Listener '{}' unregistered.", src_addr, id);
            peers.remove(&id);
        },
        None => println!("{}: Listener disconnected, but has never registered.", src_addr)
    }  
}

/// Handle a peer's connect message
///
/// The connect message is received when a peer wants to initiate a tunnel
/// with another peer. The handler checks if the requested peer is in its
/// administration and if so, then it sends a `ProtocolCommand::ConnectResponse`
/// to both the peer that requests the tunnel and the target peer.
async fn connect_handler(
    peers: &Arc<Mutex<HashMap<String, PeerInfo>>>,
    src_addr: SocketAddr,
    mut src_send_stream: SendStream,
    src_id: String,
    dest_id: String,
    tunnel_endpoint: String,
) {
    println!("Peer '{src_id}' is on endpoint '{src_addr}'");
    let peers = peers.lock().await;
    match peers.get(&dest_id) {
        None => {
            eprintln!("'{src_id}' wants to connect to unknown destination '{dest_id}'");
            if let Err(err) = send_error(&mut src_send_stream, "destination-not-found").await {
                eprintln!("unable to send error to '{}' ('{}'): {}", src_id, src_addr, err);
                return
            }
        }
        Some(peer_info) => {
            println!("Peer '{src_id}' requests connection to peer '{}' ({})", dest_id, peer_info.addr);
            let mut dest_send_stream = peer_info.send_stream.lock().await;

            // send to the receiving peer
            let cmd = ProtocolCommand::ConnectRequest {
                id: src_id.clone(),
                addr: src_addr,
                tunnel_endpoint: tunnel_endpoint,
            };
            if let Err(err) = send_command(&mut dest_send_stream, &cmd).await
            {
                eprintln!("unable to send 'ConnectRequest' to '{}' ('{}'): {}", src_id, src_addr, err);
                return
            }

            // send to the source peer
            let cmd = ProtocolCommand::ConnectResponse {
                id: dest_id.clone(),
                addr: peer_info.addr,
                pub_cert: Some(peer_info.certificate.as_ref().to_vec()),
            };
            if let Err(err) = send_command(&mut src_send_stream, &cmd).await {
                eprintln!("unable to send 'ConnectResponse' to '{}' ('{}'): {}", dest_id, peer_info.addr, err);
                return
            }
        }
    }
}

fn find_id_by_addr(peers: &HashMap<String, PeerInfo>, addr: SocketAddr) -> Option<String> {
    for (id, peer_info) in peers.iter() {
        if peer_info.addr == addr {
            return Some(id.clone());
        }
    }
    None
}
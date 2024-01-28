use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// A UHP command that is sent via the command channel
/// 
/// Peers and servers communicate via simple commands that are sent via the
/// UDP channel, before the actual tunnel is established.
#[repr(u8)]
#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolCommand {
    /// Error message (server to peer).
    Error(String) = 0,
    /// Peer advertisement holding the peer's identifier and public
    /// certificate (peer to server).
    Advertise { id: String, pub_cert: Vec<u8> } = 1,
    /// Request a connection with the specified peer (peer to server).
    Connect { src_id: String, dest_id: String, tunnel_endpoint: String } = 2,
    /// Peer (with the given identifier and IP address) requests a tunnel
    /// to the specified endpoint (server to peer).
    ConnectRequest { id: String, addr: SocketAddr, tunnel_endpoint: String } = 3,
    /// The connect response that is sent back to the requesting peer and
    /// it also holds the public certificate that the remote peer uses for
    /// communication (server to peer)
    ConnectResponse { id: String, addr: SocketAddr, pub_cert: Option<Vec<u8>> } = 4,
    /// Hello handshake message that is sent between peers to actually punch
    /// a hole in the UDP NAT table (peer to peer)
    Hi { id: String } = 5,
}

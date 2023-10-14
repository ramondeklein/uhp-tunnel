use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug)]
pub enum ProtocolCommand {
    Error(String) = 0,                                      // S2C: send error back to the client
    Advertise { id: String } = 1,                           // C2S: advertise to the server with the given identifier
    Connect { src_id: String, dest_id: String } = 2,        // C2S: request connection with specified identifier
    ConnectResponse { id: String, addr: SocketAddr } = 3,   // S2C: client with given source id/addr requests a connection
    Hi { id: String} = 4,                                   // C2C: punch hole
}

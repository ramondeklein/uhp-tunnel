use std::{net::{SocketAddr, UdpSocket}, error::Error};

use super::protocol::ProtocolCommand;

/// Send an error message to the given peer
pub fn send_error(socket: &UdpSocket, addr: &SocketAddr, msg: &str) -> Result<(), Box<dyn Error>> {
    send_command(&socket, addr, &ProtocolCommand::Error(String::from(msg)))
}

/// Send a protocol message to the given peer
pub fn send_command(socket: &UdpSocket, addr: &SocketAddr, cmd: &ProtocolCommand) -> Result<(), Box<dyn Error>> {
    let buf: Vec<u8> = bincode::serialize(&cmd).unwrap();
    socket.send_to(&buf, addr)?;
    Ok(())
}

/// Maximum control packet size
pub const CTRL_SIZE: usize = 1000;

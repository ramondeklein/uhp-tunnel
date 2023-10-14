use std::{net::SocketAddr, error::Error};

use tokio::net::UdpSocket;

use super::protocol::ProtocolCommand;

pub async fn send_error(socket: &UdpSocket, dest: &SocketAddr, msg: &str) -> Result<(), Box<dyn Error>> {
    send_command(&socket, dest, ProtocolCommand::Error(String::from(msg))).await
}

pub async fn send_command(socket: &UdpSocket, dest: &SocketAddr, cmd: ProtocolCommand) -> Result<(), Box<dyn Error>> {
    let buf: Vec<u8> = bincode::serialize(&cmd).unwrap();
    socket.send_to(&buf, dest).await?;
    Ok(())
}

pub const CTRL_SIZE: usize = 100;

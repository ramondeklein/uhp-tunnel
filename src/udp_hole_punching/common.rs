use std::error::Error;
use quinn::SendStream;

use super::protocol::ProtocolCommand;

/// Send an error message to the given peer
pub async fn send_error(send_stream: &mut SendStream, msg: &str) -> Result<(), Box<dyn Error>> {
    send_command(send_stream, &ProtocolCommand::Error(String::from(msg))).await
}

/// Send a protocol message to the given peer
pub async fn send_command(send_stream: &mut SendStream, cmd: &ProtocolCommand) -> Result<(), Box<dyn Error>> {
    let buf: Vec<u8> = bincode::serialize(&cmd).unwrap();
    send_stream.write_all(&buf).await?;
    Ok(())
}

/// Maximum control packet size
pub const CTRL_SIZE: usize = 1000;

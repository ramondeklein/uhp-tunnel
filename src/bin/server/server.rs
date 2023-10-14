use std::{error::Error, net::SocketAddr, collections::HashMap};
use tokio::net::UdpSocket;

use hole_punching::udp_hole_punching::common::{send_error, send_command, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;

pub struct Server {
    clients: HashMap::<String, SocketAddr>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            clients: HashMap::<String, SocketAddr>::new()
        }
    }

    pub async fn run(&mut self, host: &String) -> Result<(), Box<dyn Error>> {
        let socket = UdpSocket::bind(host).await?;
        loop {
            if let Err(e) = self.handle(&socket).await {
                eprintln!("{e}");
            }
        }
    }

    async fn handle(&mut self, socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
        let mut buf = vec![0u8; CTRL_SIZE];
        let (n, me) = socket.recv_from(&mut buf).await?;
        if n == 0 {
            send_error(socket, &me, "no-command").await?
        }
        if n >= CTRL_SIZE {
            send_error(socket, &me, "command-too-large").await?
        }
    
        match bincode::deserialize::<ProtocolCommand>(&buf)? {
            ProtocolCommand::Advertise { id } => self.advertise(me, id),
            ProtocolCommand::Connect { src_id, dest_id } => self.connect(socket, me, src_id, dest_id).await,
            _ => send_error(socket, &me, "invalid-command").await,
        }    
    }
    
    fn advertise(&mut self, src_addr: SocketAddr, id: String) -> Result<(), Box<dyn Error>> {    
        println!("'{id}' is on endpoint '{src_addr}'");
        self.clients.insert(id, src_addr);
        Ok(())
    }
    
    async fn connect(&mut self, socket: &UdpSocket, src_addr: SocketAddr, src_id: String, dest_id: String) -> Result<(), Box<dyn Error>> {    
        self.advertise(src_addr, src_id.clone())?;   // connect is also an implicit advertise
        match self.clients.get(&dest_id) {
            None => {
                eprintln!("'{src_id}' wants to connect to unknown destination '{dest_id}'");
                send_error(&socket, &src_addr, "destination-not-found").await?
            },
            Some(dest_addr) => {
                println!("'{src_id}' wants to connect to destination '{dest_id}' on end-point '{dest_addr}'");
                send_command(&socket, &dest_addr, ProtocolCommand::ConnectResponse { id: src_id, addr: src_addr }).await?;
                send_command(&socket, &src_addr, ProtocolCommand::ConnectResponse { id: dest_id, addr: *dest_addr }).await?;
            },
        }
        Ok(())
    }
}

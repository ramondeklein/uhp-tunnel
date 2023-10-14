use std::{error::Error, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};
use hole_punching::udp_hole_punching::common::{send_command, CTRL_SIZE};
use hole_punching::udp_hole_punching::protocol::ProtocolCommand;

pub struct Client {
}

impl Client {
    pub async fn listen(host: &SocketAddr, id: &String) -> Result<(UdpSocket, String, SocketAddr), Box<dyn Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let advertisement_interval = Duration::from_millis(30 * 1000);
        loop {
            // advertise every 30s to keep the NAT hole intact
            send_command(
                &socket,
                &host,
                ProtocolCommand::Advertise { id: id.clone() },
            )
            .await?;

            let mut buf = vec![0u8; CTRL_SIZE];
            while let Ok(r) = timeout(advertisement_interval, socket.recv_from(&mut buf)).await {
                let (n, addr) = r.unwrap();
                if n == 0 {
                    eprintln!("endpoint {addr} sent 0 bytes (ignored)");
                    continue;
                }
                if n >= CTRL_SIZE {
                    eprintln!("endpoint {addr} sent {n} bytes (ignored)");
                    continue;
                }

                match bincode::deserialize::<ProtocolCommand>(&buf)? {
                    ProtocolCommand::ConnectResponse { id, addr } => {
                        send_command(&socket, &addr, ProtocolCommand::Hi { id: id.clone() }).await?;
                        return Ok((socket, id, addr));
                    },
                    _ => eprintln!("endpoint {addr} sent invalid command"),
                };
            }
        }
    }

    pub async fn connect(host: &SocketAddr, src_id: &String, dest_id: &String) -> Result<(UdpSocket, String, SocketAddr), Box<dyn Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // advertise every 30s to keep the NAT hole intact
        send_command(&socket, &host, ProtocolCommand::Connect { src_id: src_id.clone(), dest_id: dest_id.clone() }).await?;

        let mut buf = vec![0u8; CTRL_SIZE];
        let connect_timeout = Duration::from_millis(30 * 1000);
        let r = timeout(connect_timeout, socket.recv_from(&mut buf)).await?;
        let (n, _) = r.unwrap();
        if n == 0 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "empty data")));
        }
        if n >= CTRL_SIZE {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "too much data")));
        }

        match bincode::deserialize::<ProtocolCommand>(&buf)? {
            ProtocolCommand::ConnectResponse { id, addr } => {
                send_command(&socket, &addr, ProtocolCommand::Hi { id: id.clone() }).await?;
                Ok((socket, id, addr))
            },
            _ => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "unexpected command"))),
        }
    }
}

use std::{error::Error, net::{SocketAddr, Ipv4Addr}, sync::Arc};
use tokio::{io::AsyncReadExt, net::UdpSocket, io::AsyncWriteExt};

use crate::packet::print_packet;

pub async fn tuntap_loop(socket: UdpSocket, remote_addr: SocketAddr, our_ip: Option<&Ipv4Addr>) -> Result<(), Box<dyn Error>> {
    let mut tun_builder = tokio_tun::Tun::builder()
        .name("")   // set by kernel
        .tap(false)
        .packet_info(false)
        .up();

    if let Some(our_ip) = our_ip {
        tun_builder = tun_builder.address(*our_ip);
    }
    
    let tun = tun_builder.try_build()?;

    let s1 = Arc::new(socket);
    let s2 = s1.clone();

    let mtu: usize = tun.mtu()?.try_into()?;

    println!("tun '{}' created (mtu: {} bytes)", tun.name(), mtu);

    let (mut tr, mut tw) = tokio::io::split(tun);
    
    tokio::spawn(async move {
        println!("<- starting TUN to SOCKET loop");
        let mut buf = [0u8; 1500];//Vec::with_capacity(mtu);
        loop {
            let r = tr.read(&mut buf).await?;
            let s = s2.send_to(&buf[..r], remote_addr).await?;
            print_packet("<- ", &buf)
        }
    
        Ok::<_, std::io::Error>(())
    });

    println!("<- starting SOCKET to TUN loop");
    let mut buf = [0u8; 1500];//Vec::with_capacity(mtu);
    loop {
        let (r, addr) = s1.recv_from(&mut buf).await?;
        if addr != remote_addr { 
            eprintln!("<- dropping {} bytes (received from {} instead of {})", r, addr, remote_addr);
            continue; 
        }

        let buf = &buf[..r];
        match tw.write(&buf).await {
            Ok(_)  => print_packet("-> ", &buf),
            Err(e) => eprintln!("Unable to write {} bytes to the TUN adapter (ignored): {}", r, e),
        };
        
    }
}

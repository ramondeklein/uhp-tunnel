use std::{error::Error, net::{SocketAddr, Ipv4Addr}, sync::Arc};
use tokio::net::UdpSocket;

use crate::packet::print_packet;

pub async fn tuntap_loop(socket: UdpSocket, remote_addr: SocketAddr, our_ip: Option<&Ipv4Addr>) -> Result<(), Box<dyn Error>> {
    let wintun = unsafe { wintun::load_from_path("wintun.dll") }.expect("Unable to load wintun.dll");

    let adapter_name = std::env::var_os("UHP_ADAPTER_NAME").unwrap_or("tuntap1".into());
    let adapter_name_str = adapter_name.to_str().unwrap();
    let tun = match wintun::Adapter::open(&wintun, adapter_name_str) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("unable to open adapter '{}': {}", adapter_name_str, e);
            wintun::Adapter::create(&wintun, adapter_name_str, "Wintun", None)?
        }
    };

    //Specify the size of the ring buffer the wintun driver should use.
    let session = Arc::new(tun.start_session(wintun::MAX_RING_CAPACITY).unwrap());

    if let Some(our_ip) = our_ip {
        tun.set_address(*our_ip)?;
    }

    let s1 = Arc::new(socket);
    let s2 = s1.clone();
    let t1 = &session;
    let t2 = session.clone();

    let mtu: usize = tun.get_mtu()?;

    println!("tun '{}' created (mtu: {} bytes)", tun.get_name()?, mtu);

    tokio::spawn(async move {
        println!("<- starting TUN to SOCKET loop");
        loop {
            let packet = t2.receive_blocking()?;
            s2.send_to(&packet.bytes(), remote_addr).await?;
            print_packet("<- ", packet.bytes());
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

        let mut packet = t1.allocate_send_packet(r.try_into()?)?;
        packet.bytes_mut().clone_from_slice(&buf[..r]); // not very efficient to copy data :-(

        print_packet("-> ", packet.bytes());
        session.send_packet(packet);        
    }
}
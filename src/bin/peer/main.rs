pub mod client;

use client::Client;
use std::{error::Error, env, time::Duration, net::{SocketAddr, Ipv4Addr}, sync::Arc};
use tokio::{io::AsyncReadExt, time::sleep, net::UdpSocket, io::AsyncWriteExt};
use tokio_tun::Tun;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let cmd = clap::Command::new("peer")
        .bin_name("peer")
        .subcommand_required(true)
        .subcommand(clap::command!("connect")
            .about("connects to another peer")
            .arg(clap::arg!(-s --"server" "Server end-point (i.e. 192.145.12.1:21473)")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(std::net::SocketAddr)))
            .arg(clap::arg!(-l --"local-id" "Local identifier")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)))
            .arg(clap::arg!(-r --"remote-id" "Remote identifier (where to connect to)")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)))
            .arg(clap::arg!(-i --"ip" "Assign the IP address after connecting")
                .action(clap::ArgAction::Set)
                .required(false)
                .value_parser(clap::value_parser!(std::net::Ipv4Addr))))
        .subcommand(clap::command!("listen")
            .about("listens for incoming connections")
            .arg(clap::arg!(-s --"server" "Server end-point (i.e. 192.145.12.1:21473)")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(std::net::SocketAddr)))
            .arg(clap::arg!(-l --"local-id" "Local identifier")
                .action(clap::ArgAction::Set)
                .required(true)
                .value_parser(clap::value_parser!(String)))
            .arg(clap::arg!(-i --"ip" "Assign the IP address after connecting")
                .action(clap::ArgAction::Set)
                .required(false)
                .value_parser(clap::value_parser!(std::net::Ipv4Addr))));
    
    match cmd.get_matches().subcommand() {
        Some(("listen", args)) => {
            let server = args.get_one::<std::net::SocketAddr>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();
            let our_ip = args.get_one::<Ipv4Addr>("ip");
            
            let (socket, id, addr) = Client::listen(server, local_id).await?;
            sleep(Duration::from_millis(1000)).await;   // wait one second to ensure both sides punched holes
            println!("connected to '{}' on end-point '{}'", id, addr);
            
            tuntap_loop(socket, addr, our_ip).await?
        
        },
        Some(("connect", args)) => {
            let server = args.get_one::<std::net::SocketAddr>("server").unwrap();
            let local_id = args.get_one::<String>("local-id").unwrap();
            let remote_id = args.get_one::<String>("remote-id").unwrap();
            let our_ip = args.get_one::<Ipv4Addr>("ip");

            let (socket, id, addr) = Client::connect(server, local_id, remote_id).await?;
            sleep(Duration::from_millis(1000)).await;   // wait one second to ensure both sides punched holes
            println!("connected to '{}' on end-point '{}'", id, addr);
            
            tuntap_loop(socket,  addr, our_ip).await?
        },
        _ => {}
    };

    Ok(())
}

async fn tuntap_loop(socket: UdpSocket, remote_addr: SocketAddr, our_ip: Option<&Ipv4Addr>) -> Result<(), Box<dyn Error>> {
    let mut tun_builder = Tun::builder()
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
            println!("<- received {} bytes, sent {} bytes", r, s);
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
            Ok(s)  => println!("-> received {} bytes, sent {} bytes", r, s),
            Err(e) => eprintln!("Unable to write {} bytes to the TUN adapter (ignored): {}", r, e),
        };
        
    }
}

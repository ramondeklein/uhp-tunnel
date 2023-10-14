pub mod client;
pub mod packet;

#[cfg(target_os = "linux")]   pub mod tuntap_linux;
#[cfg(target_os = "windows")] pub mod tuntap_windows;
#[cfg(target_os = "linux")]   use crate::tuntap_linux::tuntap_loop;
#[cfg(target_os = "windows")] use crate::tuntap_windows::tuntap_loop;

use client::Client;
use std::{error::Error, env, time::Duration, net::Ipv4Addr};
use tokio::time::sleep;


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

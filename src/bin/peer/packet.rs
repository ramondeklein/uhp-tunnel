use std::net::{Ipv4Addr, Ipv6Addr};

pub fn print_packet(prefix: &str, buf: &[u8]) {
    if buf.len() < 20 {
        println!("{} Packet too short, no IP packet ({} bytes)", prefix, buf.len());
        return;
    }
    let ip_version = buf[0] >> 4;
    if ip_version == 4 {
        let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
        if buf.len() < ip_header_len{
            println!("{} Ipv4 packet too short ({} bytes)", prefix, buf.len());
            return;
        }

        let ttl = buf[8];
        let proto = match buf[9] {
            1 => "ICMP",
            2 => "IGMP",
            6 => "TCP",
            17 => "UDP",
            _ => "???",
        };
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dest = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        let body = &buf[20..];

        match proto {
            "ICMP" => {
                let (typ, code) = match body[0] {
                    0 => ("echo reply", ""),
                    3 => ("destination unreachable", match body[1] {
                        0 => "net unreachable",
                        1 => "host unreachable",
                        2 => "protocol unreachable",
                        3 => "port unreachable",
                        4 => "fragmentation needed but DF bit set",
                        5 => "source route failed",
                        _ => "???",
                    }),
                    4 => ("source quench", match body[1] {
                        0 => "congestion control",
                        _ => "???",
                    }),
                    5 => ("redirect", match body[1] {
                        0 => "redirect datagrams for the network",
                        1 => "redirect datagrams for the host",
                        2 => "redirect datagrams for the type of service and network",
                        3 => "redirect datagrams for the type of service and host",
                        _ => "???",
                    }),
                    8 => ("echo request", ""),
                    11 => ("time exceeded", match body[1] {
                        0 => "time to live exceeded in transit",
                        1 => "fragment reassembly time exceeded",
                        _ => "???",
                    }),
                    12 => ("parameter problem", match body[1] {
                        0 => "pointer indicates the error",
                        1 => "missing a required option",
                        2 => "bad length",
                        _ => "???",
                    }),
                    13 => ("timestamp request", ""),
                    14 => ("timestamp reply", ""),
                    15 => ("information request", ""),
                    16 => ("information reply", ""),
                    _ => ("???","???"),
                };
                let data = &body[8..];
                println!("{} IPv4 ICMP packet {} from {} to {}: {} (TTL {}, {} bytes)", prefix, typ, src, dest, code, ttl, data.len());
            },
            "TCP" => {
                let src_port = ((body[0] as u16) << 8) | body[1] as u16;
                let dest_port = ((body[2] as u16) << 8) | body[3] as u16;
                let seq_number = ((body[4] as u32) << 24) | ((body[5] as u32) << 16) | ((body[6] as u32) << 8) | body[7] as u32;
                let data = &body[20..];
                println!("{} IPv4 TCP packet {} from {}:{} to {}:{}: (TTL {}, {} bytes)", prefix, seq_number, src, src_port, dest, dest_port, ttl, data.len());
            }
            "UDP" => {
                let src_port = ((body[0] as u16) << 8) | body[1] as u16;
                let dest_port = ((body[2] as u16) << 8) | body[3] as u16;
                let length = (((body[4] as u16) << 8) | body[5] as u16) as usize;
                println!("{} IPv4 UDP packet from {}:{} to {}:{}: (TTL {}, {} bytes)", prefix, src, src_port, dest, dest_port, ttl, body.len());
                if body.len() != length {
                    println!("{} - UDP payload length {} does not match UDP header length {}", prefix, body.len(), length);
                }
            }
            _ => println!("{} IPv4 {} packet from {} to {} (TTL {}, {} bytes)", prefix, proto, src, dest, ttl, body.len()),
        }
        
    } else if ip_version == 6 {
        if buf.len() < 40 {
            println!("{} IPv6 packet too short ({} bytes)", prefix, buf.len());
            return;
        }
        let payload_len = (((buf[4] as u16) << 8) | (buf[5] as u16)) as usize;
        if buf.len() < 40 + payload_len {
            println!("{} Ipv6 packet too short ({} bytes)", prefix, buf.len());
            return;
        }

        let hop_limit = buf[7];
        let src_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
        let dest_bytes: [u8; 16] = buf[24..40].try_into().unwrap();
        let src = Ipv6Addr::from(src_bytes);
        let dest = Ipv6Addr::from(dest_bytes);

        let body = &buf[40..];

        println!("{} IPv6 packet from {} to {} (hop-limit {}, {} bytes)", prefix, src, dest, hop_limit, body.len());

    } else {
        println!("{} Unknown IP packet version {}", prefix, ip_version);
    }
}

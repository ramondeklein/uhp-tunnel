pub mod server;

use std::{process, error::Error, env};
use server::Server;

fn usage() {
    let exe = std::env::current_exe().unwrap();
    let prg = exe.as_path().to_str().unwrap();
    eprintln!("Usage: {} <bind-endpoint>", prg);
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(_) => {
            // everything fine
        },
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        },
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(1);
    }
    let bind = &args[1];

    let mut server = Server::new();
    server.run(&bind).await?;
    Ok(())
}

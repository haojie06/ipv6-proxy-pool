use clap::Parser;
use ipnet::Ipv6Net;
use ipv6_proxy_pool::{start_proxy_server, ProxyServerConfig};
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    bind_addr: SocketAddr,
    #[arg(short, long, required = true)]
    sub_net: Ipv6Net,
    #[arg(short, long, default_value = "password")]
    password: String,
    #[arg(
        short,
        long,
        default_value = "false",
        help = "Assign a fixed ipv6 address based on username"
    )]
    assign_ipv6_by_username: bool,
}

fn main() {
    let cli = Cli::parse();
    run(
        cli.bind_addr,
        cli.sub_net,
        cli.password,
        cli.assign_ipv6_by_username,
    );
}

#[tokio::main]
async fn run(
    bind_addr: SocketAddr,
    ipv6_subnet: Ipv6Net,
    password: String,
    assign_ipv6_by_username: bool,
) {
    let config = ProxyServerConfig::new(bind_addr, ipv6_subnet, password, assign_ipv6_by_username);
    if let Err(e) = start_proxy_server(config).await {
        eprintln!("Error: {}", e);
    }
}

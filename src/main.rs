use clap::Parser;
use ipnet::Ipv6Net;
use ipv6_proxy_pool::start;
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
}

fn main() {
    let cli = Cli::parse();
    start(cli.bind_addr, cli.sub_net, cli.password);
}

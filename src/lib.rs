use ipnet::Ipv6Net;
use std::net::SocketAddr;

#[tokio::main]
pub async fn start(bind_addr: SocketAddr, ipv6_subnet: Ipv6Net, password: String) {
    println!("bind_addr: {}", bind_addr);
    println!("ipv6_subnet: {}", ipv6_subnet);
    println!("password: {}", password)
}

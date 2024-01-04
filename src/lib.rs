use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body, Request, Response, Version};
use hyper_util::rt::TokioIo;
use ipnet::Ipv6Net;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

struct ProxyService {
    ipv6_subnet: Ipv6Net,
    password: String,
}

impl ProxyService {
    fn new(ipv6_subnet: Ipv6Net, password: String) -> Self {
        Self {
            ipv6_subnet,
            password,
        }
    }
}

pub async fn start_proxy_server(
    bind_addr: SocketAddr,
    ipv6_subnet: Ipv6Net,
    password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("bind_addr: {}", bind_addr);
    println!("ipv6_subnet: {}", ipv6_subnet);
    println!("password: {}", password);
    let listener = TcpListener::bind(bind_addr).await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        let ipv6_subnet = ipv6_subnet.clone();
        let password = password.clone();
        let io = TokioIo::new(stream);
        println!("accept request from: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|_req| async {
                        // Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("Hello, World!"))))
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "Hello! {} {} {}",
                            addr, ipv6_subnet, password
                        )))))
                    }),
                )
                .await
            {
                eprintln!("Error: {}", e);
            }
        });
    }
}

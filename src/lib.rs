use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, Empty, Full};
use hyper::upgrade::Upgraded;
use hyper::{
    body::Incoming, header::PROXY_AUTHORIZATION, server::conn::http1, service::service_fn, Method,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use ipnet::Ipv6Net;
use rand::{self, seq::IteratorRandom, Rng};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket};

// proxy http request
async fn proxy_http(
    _bind_addr: SocketAddr,
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    unimplemented!("proxy_http")
}
async fn proxy_connect(
    bind_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    // 代理的方法不应该作为结构体的方法，因为我们希望使用同一个结构体来处理多个请求
    tokio::task::spawn(async move {
        let remote_addr = req.uri().authority().map(|a| a.to_string()).unwrap();
        let upgraded = hyper::upgrade::on(req).await.unwrap();
        if let Err(e) = tunnel(bind_addr, upgraded, remote_addr).await {
            eprintln!("Tunnel error: {}", e);
        }
    });
    Ok(Response::new(BoxBody::new(Empty::new())))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    bind_addr: SocketAddr,
    upgraded: Upgraded,
    remote_addr_str: String,
) -> std::io::Result<()> {
    let remote_addr = remote_addr_str.to_socket_addrs()?.next().unwrap();
    let mut upgraded = TokioIo::new(upgraded);
    let socket = TcpSocket::new_v6()?;
    socket.bind(bind_addr)?;
    let mut stream = socket.connect(remote_addr).await?;
    println!("bind_addr: {} connecting {}", bind_addr, remote_addr);
    match tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await {
        Ok((from_client, from_server)) => {
            println!(
                "client wrote {} bytes and received {} bytes",
                from_client, from_server
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
            // println!("client closed connection");
        }
        Err(e) => {
            eprintln!("copy bidirectional: {}", e);
        }
    }
    Ok(())
}
struct Ipv6Pool {
    ipv6_subnet: Ipv6Net,
}

impl Ipv6Pool {
    fn new(ipv6_subnet: Ipv6Net) -> Self {
        Self { ipv6_subnet }
    }

    fn get_random_ipv6(&self) -> Ipv6Addr {
        self.ipv6_subnet
            .hosts()
            .choose(&mut rand::thread_rng())
            .expect("no available ipv6 address")
    }

    fn get_random_ipv6_socket_addr(&self) -> SocketAddr {
        let port: u16 = rand::thread_rng().gen_range(1024..65535);
        SocketAddr::new(IpAddr::V6(self.get_random_ipv6()), port)
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
    let ipv6_pool = Arc::new(Ipv6Pool::new(ipv6_subnet));
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("accept request from: {}", addr);
        let ipv6_pool = ipv6_pool.clone();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req| async {
                        println!("req: {:?}", req);
                        if let Some(header) = req.headers().get(PROXY_AUTHORIZATION) {
                            if let Ok(auth) = header.to_str() {
                                let encoded_auth_str = auth.strip_prefix("Basic ").unwrap();
                                let auth_bytes = general_purpose::STANDARD
                                    .decode(encoded_auth_str.as_bytes())
                                    .unwrap();
                                let decode_str = String::from_utf8(auth_bytes).unwrap();
                                let (_username, password) = decode_str.split_once(':').unwrap();
                                // only verify password, use username to map ipv6 address
                                if password != password {
                                    return Ok(Response::new(BoxBody::new(Full::new(
                                        "Proxy Authorization password error\n".into(),
                                    ))));
                                }
                                let bind_addr = ipv6_pool.get_random_ipv6_socket_addr();
                                if req.method() == Method::CONNECT {
                                    proxy_connect(bind_addr, req).await
                                } else {
                                    proxy_http(bind_addr, req).await
                                }
                            } else {
                                Ok(Response::new(BoxBody::new(Full::new(
                                    "Proxy Authorization decode error\n".into(),
                                ))))
                            }
                        } else {
                            println!("no proxy authorization");
                            Ok(Response::new(BoxBody::new(Full::new(
                                "No Proxy Authorization\n".into(),
                            ))))
                        }
                        // proxy_service.proxy(req).await
                    }),
                )
                .with_upgrades()
                .await
            {
                eprintln!("Error: {}", e);
            }
        });
    }
}

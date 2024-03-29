use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::{combinators::BoxBody, Empty, Full};
use hyper::{
    body::Incoming, client::conn::http1 as http1_client, header::PROXY_AUTHORIZATION,
    server::conn::http1 as http1_server, service::service_fn, upgrade::Upgraded, Method, Request,
    Response,
};
use hyper_util::rt::TokioIo;
use ipnet::Ipv6Net;
use rand::{self, seq::IteratorRandom};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Mutex;

struct Ipv6Pool {
    ipv6_subnet: Ipv6Net,
    user_ipv6_map: Mutex<HashMap<String, Ipv6Addr>>, // make user use the same ipv6 address
}

impl Ipv6Pool {
    fn new(ipv6_subnet: Ipv6Net) -> Self {
        Self {
            ipv6_subnet,
            user_ipv6_map: Mutex::new(HashMap::new()),
        }
    }

    async fn get_ipv6(&self, username: String) -> Ipv6Addr {
        let mut ipv6_user_map = self.user_ipv6_map.lock().await;
        match ipv6_user_map.get(&username) {
            Some(&ipv6_addr) => ipv6_addr,
            None => {
                let ipv6_addr = self
                    .ipv6_subnet
                    .hosts()
                    .choose(&mut rand::thread_rng())
                    .expect("no available ipv6 address");
                ipv6_user_map.insert(username, ipv6_addr);
                ipv6_addr
            }
        }
    }

    async fn get_random_ipv6(&self) -> Ipv6Addr {
        self.ipv6_subnet
            .hosts()
            .choose(&mut rand::thread_rng())
            .expect("no available ipv6 address")
    }

    async fn get_ipv6_socket_addr(
        &self,
        username: String,
        assign_ipv6_by_username: bool,
    ) -> SocketAddr {
        // let port: u16 = rand::thread_rng().gen_range(1024..65535);
        if assign_ipv6_by_username {
            SocketAddr::new(IpAddr::V6(self.get_ipv6(username).await), 0)
        } else {
            SocketAddr::new(IpAddr::V6(self.get_random_ipv6().await), 0)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn proxy_connect(
    bind_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // 代理的方法不应该作为结构体的方法，因为我们希望使用同一个结构体来处理多个请求
    tokio::task::spawn(async move {
        let remote_addr = req.uri().authority().map(|a| a.to_string()).unwrap();
        let upgraded = hyper::upgrade::on(req).await.unwrap();
        if let Err(e) = tunnel(bind_addr, upgraded, remote_addr).await {
            eprintln!("Tunnel error: {}", e);
        }
    });
    // Ok(Response::new(
    //     Empty::<Bytes>::new()
    //         .map_err(|never| match never {})
    //         .boxed(),
    // ))
    Ok(Response::new(empty()))
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

// proxy http request
async fn proxy_http(
    bind_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let remote_host = req.uri().host().expect("no host");
    let remote_port = req.uri().port_u16().unwrap_or(80);
    let remote_addr = (remote_host, remote_port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let socket = TcpSocket::new_v6().unwrap();
    socket.bind(bind_addr).unwrap();
    let stream = socket.connect(remote_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1_client::Builder::new().handshake(io).await.unwrap();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Error: {}", e);
        }
    });
    let resp = sender.send_request(req).await.unwrap();
    Ok(resp.map(|b| b.boxed()))
}
#[derive(Debug)]

pub struct ProxyServerConfig {
    pub bind_addr: SocketAddr,
    pub ipv6_subnet: Ipv6Net,
    pub password: String,
    pub assign_ipv6_by_username: bool,
}

impl ProxyServerConfig {
    pub fn new(
        bind_addr: SocketAddr,
        ipv6_subnet: Ipv6Net,
        password: String,
        assign_ipv6_by_username: bool,
    ) -> Self {
        Self {
            bind_addr,
            ipv6_subnet,
            password,
            assign_ipv6_by_username,
        }
    }
}

pub async fn start_proxy_server(cfg: ProxyServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    println!("start proxy server:\n{:?}", cfg);
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    let ipv6_pool = Arc::new(Ipv6Pool::new(cfg.ipv6_subnet));
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("accept request from: {}", addr);
        let ipv6_pool = ipv6_pool.clone();
        let io = TokioIo::new(stream);
        let password_cfg = cfg.password.clone();
        let assign_ipv6_by_username = cfg.assign_ipv6_by_username;
        tokio::spawn(async move {
            if let Err(e) = http1_server::Builder::new()
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
                                let (username, password) = decode_str.split_once(':').unwrap();
                                // only verify password, use username to map ipv6 address
                                if password_cfg != password {
                                    return Ok(Response::new(full(
                                        "Proxy Authorization password error\n",
                                    )));
                                }
                                // use username to map ipv6 address
                                let bind_addr = ipv6_pool
                                    .get_ipv6_socket_addr(
                                        username.to_string(),
                                        assign_ipv6_by_username,
                                    )
                                    .await;
                                if req.method() == Method::CONNECT {
                                    proxy_connect(bind_addr, req).await
                                } else {
                                    proxy_http(bind_addr, req).await
                                }
                            } else {
                                Ok(Response::new(full("Proxy Authorization decode error\n")))
                            }
                        } else {
                            println!("no proxy authorization");
                            // Ok(Response::new(BoxBody::new(Full::new(
                            //     "No Proxy Authorization\n".into(),
                            // ))))
                            Ok(Response::new(full("No Proxy Authorization\n")))
                        }
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

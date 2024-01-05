use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use hyper::header::PROXY_AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body, Request, Response, Version};
use hyper_util::rt::TokioIo;
use ipnet::Ipv6Net;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
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

    fn proxy(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        println!("req: {:?}", req);
        if let Some(header) = req.headers().get(PROXY_AUTHORIZATION) {
            if let Ok(auth) = header.to_str() {
                let encoded_auth_str = auth.strip_prefix("Basic ").unwrap();
                let auth_bytes = general_purpose::STANDARD
                    .decode(encoded_auth_str.as_bytes())
                    .unwrap();
                let decode_str = String::from_utf8(auth_bytes).unwrap();
                let (username, password) = decode_str.split_once(':').unwrap();
                println!("username: {}, password: {}", username, password);
                // only verify password, use username to map ipv6 address
                if self.password != password {
                    return Ok(Response::new(Full::new(
                        "Proxy Authorization password error".into(),
                    )));
                }
                Ok(Response::new(Full::new(decode_str.into())))
            } else {
                Ok(Response::new(Full::new(
                    "Proxy Authorization decode error".into(),
                )))
            }
        } else {
            println!("no proxy authorization");
            Ok(Response::new(Full::new("No Proxy Authorization".into())))
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
    let proxy_service = Arc::new(ProxyService::new(ipv6_subnet.clone(), password.clone()));
    loop {
        let (stream, addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        println!("accept request from: {}", addr);
        let proxy_service = proxy_service.clone();
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req| async {
                        proxy_service.proxy(req)
                        // Ok::<_, Infallible>(Response::new(format!(
                        //     "Hello! {} {} {}",
                        //     addr, ipv6_subnet, password
                        // )))
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

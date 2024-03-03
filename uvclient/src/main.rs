use std::{fs::File, io::{BufReader, Cursor, Read, Write}, net::Ipv4Addr, sync::Arc};

use serde::{Deserialize, Serialize};
use tcpmux::client::MuxClient;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, webpki, TlsConnector};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    server: String,
    #[serde(rename = "ssl-cert")]
    ssl_cert: String,
    routes: Vec<String>,
}

impl Config {
    fn from_file(filename: &str) -> Self {
        let f = File::open(filename);
        match f {
            Ok(mut file) => {
                let mut c = String::new();
                file.read_to_string(&mut c).unwrap();
                let cfg: Config = serde_yaml::from_str(&c).unwrap();
                cfg
            }
            Err(e) => {
                panic!("error {}", e)
            }
        }
    }
}

pub fn tls_cert(cert: &[u8], name: &str) -> (TlsConnector, rustls::ServerName) {
    let cs = Cursor::new(cert);
    let mut br = BufReader::new(cs);
    let certs = rustls_pemfile::certs(&mut br).unwrap();
    let trust_anchors = certs.iter().map(|cert| {
        let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    });
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(trust_anchors);
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls::ServerName::try_from(name).unwrap();
    (connector, server_name)
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    if cfg!(target_os = "windows") {
        // 包含wintun
        let wintun_dll = include_bytes!("../wintun.dll");
        if let Err(_) = std::fs::metadata("wintun.dll") {
            // 文件不存在
            let mut file = File::create("wintun.dll").expect("Failed to create file");
            file.write_all(wintun_dll).expect("Failed to write to file");
        }
    }
    let cfg = Config::from_file("client-config.yml");
    let mut cert = Vec::<u8>::new();
    match File::open(cfg.ssl_cert) {
        Ok(mut f) => f.read_to_end(&mut cert).unwrap(),
        Err(e) => panic!("{}", e)
    };

    let (connector, domain) = tls_cert(&cert, "unrealvpn");

    let ctrl_conn = TcpStream::connect(cfg.server).await.unwrap();
    let ctrl_conn = connector.connect(domain.clone(), ctrl_conn).await.unwrap();
    
    let tun = tun2layer4::os_tun::new(
        String::from("unrealvpn"),
        Ipv4Addr::new(10, 28, 13, 0),
        24,
        Some(cfg.routes),
    );

    let (mut mux_client, _) = tcpmux::client::StreamMuxClient::init(ctrl_conn);

    // 面向于inside端
    while let Ok(tcp_accept) = tun.accept_tcp() {
        log::info!("dst: {}", tcp_accept.dst);
        let (id, recv, send, mut vec_pool) = mux_client.new_channel().await;
        tokio::spawn(async move {
            let conn = tcp_accept.stream.try_clone().unwrap();
            conn.set_nonblocking(true).unwrap();
            let src_stream = tokio::net::TcpStream::from_std(conn).unwrap();
            let mut _data = vec_pool.get().await;
            let target = format!("{}:{}", tcp_accept.dst.ip().to_string(), tcp_accept.dst.port());
            _data.extend(target.as_bytes());
            send.send((tcpmux::cmd::PKG, id, Some(_data))).unwrap();
            tcpmux::bicopy(id, recv, send, src_stream, vec_pool).await;
        });
    }
}

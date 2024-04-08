use std::{fs::File, io::{BufReader, Cursor, Read, Write}, net::Ipv4Addr, num::NonZeroU64, str::FromStr, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, net::TcpStream, time};
use tokio_rustls::{rustls, webpki, TlsConnector};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TunConfig {
    ip: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    server: String,
    #[serde(rename = "ssl-cert")]
    ssl_cert: String,
    routes: Vec<String>,
    tun: TunConfig,
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

    let ctrl_conn = TcpStream::connect(cfg.server.clone()).await.unwrap();
    let ctrl_conn = connector.connect(domain.clone(), ctrl_conn).await.unwrap();
    let tun_ip = Ipv4Addr::from_str(&cfg.tun.ip).expect("error tun ip");
    let tun = tun2layer4::os_tun::new(
        cfg.tun.name,
        tun_ip,
        24,
        Some(cfg.routes),
    );

    let (mut mux_connector, _, mut mux_worker) = async_smux::MuxBuilder::client().with_keep_alive_interval(NonZeroU64::new(30).unwrap()).with_connection(ctrl_conn).build();
    tokio::spawn(mux_worker);


    // 面向于inside端
    while let Ok(tcp_accept) = tun.accept_tcp() {
        log::info!("dst: {}", tcp_accept.dst);
        let mut _mux_stream = match mux_connector.connect() {
            Ok(cc) => cc,
            Err(e) => {
                log::info!("{}->{}", line!(), e);
                loop {
                    time::sleep(time::Duration::from_secs(1)).await;
                    let connector = connector.clone();
                    let ctrl_conn = match TcpStream::connect(cfg.server.clone()).await {
                        Ok(cc) => cc,
                        Err(e) => {
                            log::info!("{}->{}", line!(), e);
                            continue;
                        }
                    };
                    let ctrl_conn = match connector.connect(domain.clone(), ctrl_conn).await {
                        Ok(cc) => cc,
                        Err(e) => {
                            log::info!("{}->{}", line!(), e);
                            continue;
                        }
                    };
                    (mux_connector, _, mux_worker) = async_smux::MuxBuilder::client().with_keep_alive_interval(NonZeroU64::new(30).unwrap()).with_connection(ctrl_conn).build();
                    tokio::spawn(mux_worker);
                    match mux_connector.connect() {
                        Ok(cc) => break cc,
                        Err(e) => {
                            log::info!("{}->{}", line!(), e);
                            continue;
                        }
                    };
                }
            }
        };
        
        tokio::spawn(async move {
            let conn = tcp_accept.stream.try_clone().unwrap();
            conn.set_nonblocking(true).unwrap();
            let mut src_stream = tokio::net::TcpStream::from_std(conn).unwrap();
            let target = format!("{}:{}", tcp_accept.dst.ip().to_string(), tcp_accept.dst.port());
            _mux_stream.write_u16(target.len() as u16).await.unwrap();
            _mux_stream.write_all(target.as_bytes()).await.unwrap();
            _mux_stream.flush().await.unwrap();
            _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut src_stream).await;
            _ = _mux_stream.shutdown().await;
        });
    }
}

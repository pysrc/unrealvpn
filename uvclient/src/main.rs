use std::{
    fs::File,
    io::{BufReader, Cursor, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU64,
    str::FromStr,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::{rustls, webpki, TlsConnector};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TunConfig {
    ip: String,
    name: String,
}


fn default_false() -> bool {
    return false;
}

fn default_true() -> bool {
    return true;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    server: String,
    #[serde(rename = "enable-tcp", default = "default_true")]
    enable_tcp: bool,
    #[serde(rename = "enable-udp", default = "default_false")]
    enable_udp: bool,
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

const CMD_UDP: u8 = 1;
const CMD_TCP: u8 = 2;

fn main() {
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
        Err(e) => panic!("{}", e),
    };

    let (connector, domain) = tls_cert(&cert, "unrealvpn");

    let mut opt = 0u8;
    if cfg.enable_tcp {
        opt |= tun2layer4::EN_TCP;
    }
    if cfg.enable_udp {
        opt |= tun2layer4::EN_UDP;
    }
    let tun_ip: Ipv4Addr = Ipv4Addr::from_str(&cfg.tun.ip).expect("error tun ip");
    let (otcp_worker, oudp_worker) =
        tun2layer4::os_tun::new(cfg.tun.name, opt, tun_ip, 24, Some(cfg.routes));
    
    let mut joins = Vec::with_capacity(2);

    if let Some(udp_worker) = oudp_worker {
        let server_udp: String = cfg.server.clone();
        let connector_udp = connector.clone();
        let domain_udp = domain.clone();
        let jn = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // udp
                let udp_ctrl_conn = TcpStream::connect(server_udp.clone()).await.unwrap();
                let mut udp_ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> = connector_udp
                    .connect(domain_udp.clone(), udp_ctrl_conn)
                    .await
                    .unwrap();
                udp_ctrl_conn.write_u8(CMD_UDP).await.unwrap();
                let (mut r, mut w) = split(udp_ctrl_conn);
                let udp_worker2 = udp_worker.clone();
                tokio::spawn(async move {
                    let mut key = [0u8; 12];
                    let mut buf = vec![0u8; 2048];
                    loop {
                        r.read_exact(&mut key).await.unwrap();
                        let src = SocketAddrV4::new(
                            Ipv4Addr::new(key[0], key[1], key[2], key[3]),
                            u16::from_be_bytes([key[4], key[5]]),
                        );
                        let dst = SocketAddrV4::new(
                            Ipv4Addr::new(key[6], key[7], key[8], key[9]),
                            u16::from_be_bytes([key[10], key[11]]),
                        );
                        let _len = r.read_u16().await.unwrap() as usize;
                        r.read_exact(&mut buf[.._len]).await.unwrap();
                        udp_worker2.send_back(&buf[.._len], src, dst).unwrap();
                    }
                });
                let mut key = [0u8; 12];
                let mut buf = vec![0u8; 2048];
                // 阻塞操作提出去
                while let Ok((src, dst, size)) = udp_worker.recv_from(&mut buf) {
                    key[..4].copy_from_slice(&src.ip().octets());
                    key[4..6].copy_from_slice(&src.port().to_be_bytes());
                    key[6..10].copy_from_slice(&dst.ip().octets());
                    key[10..12].copy_from_slice(&dst.port().to_be_bytes());
                    w.write_all(&key).await.unwrap();
                    w.write_u16(size as u16).await.unwrap();
                    w.write_all(&buf[..size]).await.unwrap();
                    w.flush().await.unwrap();
                }
            });
        });
        joins.push(jn);
    }

    // tcp
    if let Some(tcp_worker) = otcp_worker {
        let jn = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let ctrl_conn = TcpStream::connect(cfg.server.clone()).await.unwrap();
                let mut ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> =
                    connector.connect(domain.clone(), ctrl_conn).await.unwrap();
                ctrl_conn.write_u8(CMD_TCP).await.unwrap();
                let (mut mux_connector, _, mut mux_worker) = async_smux::MuxBuilder::client()
                    .with_keep_alive_interval(NonZeroU64::new(30).unwrap())
                    .with_connection(ctrl_conn)
                    .build();
                tokio::spawn(mux_worker);
                // 面向于inside端
                while let Ok(tcp_accept) = tcp_worker.accept() {
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
                                let ctrl_conn =
                                    match connector.connect(domain.clone(), ctrl_conn).await {
                                        Ok(cc) => cc,
                                        Err(e) => {
                                            log::info!("{}->{}", line!(), e);
                                            continue;
                                        }
                                    };
                                (mux_connector, _, mux_worker) = async_smux::MuxBuilder::client()
                                    .with_keep_alive_interval(NonZeroU64::new(30).unwrap())
                                    .with_connection(ctrl_conn)
                                    .build();
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
                        let target = format!(
                            "{}:{}",
                            tcp_accept.dst.ip().to_string(),
                            tcp_accept.dst.port()
                        );
                        _mux_stream.write_u16(target.len() as u16).await.unwrap();
                        _mux_stream.write_all(target.as_bytes()).await.unwrap();
                        _mux_stream.flush().await.unwrap();
                        _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut src_stream).await;
                        _ = _mux_stream.shutdown().await;
                    });
                }
            });
        });
        joins.push(jn);
    }
    for ele in joins {
        ele.join().unwrap();
    }
}

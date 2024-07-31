use std::{fs::File, io::{BufReader, Cursor, Read, Write}, net::{Ipv4Addr, SocketAddrV4}, str::FromStr, sync::{Arc, Mutex}};

use futures::{future, stream, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{io::{split, AsyncReadExt, AsyncWriteExt}, net::TcpStream, task};
use tokio_rustls::{rustls, webpki, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Connection, Mode};

pub async fn noop_server(c: impl Stream<Item = Result<yamux::Stream, yamux::ConnectionError>>) {
    c.for_each(|maybe_stream| {
        drop(maybe_stream);
        future::ready(())
    })
    .await;
}

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

const CMD_UDP: u8= 1;
const CMD_TCP: u8= 2;

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
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

    let tun_ip: Ipv4Addr = Ipv4Addr::from_str(&cfg.tun.ip).expect("error tun ip");
    let (tcp_worker, udp_worker) = tun2layer4::os_tun::new(
        cfg.tun.name,
        tun_ip,
        24,
        Some(cfg.routes),
    );
    // udp
    let server_udp: String = cfg.server.clone();
    let connector_udp = connector.clone();
    let domain_udp = domain.clone();
    let udp_ctrl_conn = TcpStream::connect(server_udp.clone()).await.unwrap();
    let mut udp_ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> = connector_udp.connect(domain_udp.clone(), udp_ctrl_conn).await.unwrap();
    udp_ctrl_conn.write_u8(CMD_UDP).await.unwrap();
    let (mut r, mut w) = split(udp_ctrl_conn);
    let udp_worker2 = udp_worker.clone();
    tokio::spawn(async move {
        let mut key = [0u8;12];
        let mut buf = vec![0u8; 2048];
        loop {
            r.read_exact(&mut key).await.unwrap();
            let src = SocketAddrV4::new(Ipv4Addr::new(key[0], key[1], key[2], key[3]), u16::from_be_bytes([key[4], key[5]]));
            let dst = SocketAddrV4::new(Ipv4Addr::new(key[6], key[7], key[8], key[9]), u16::from_be_bytes([key[10], key[11]]));
            let _len = r.read_u16().await.unwrap() as usize;
            r.read_exact(&mut buf[.._len]).await.unwrap();
            udp_worker2.send_back(&buf[.._len], src, dst).unwrap();
        }
    });
    tokio::spawn(async move {
        let mut key = [0u8;12];
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
    // tcp
    let ctrl_conn = TcpStream::connect(cfg.server.clone()).await.unwrap();
    let mut ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> = connector.connect(domain.clone(), ctrl_conn).await.unwrap();
    ctrl_conn.write_u8(CMD_TCP).await.unwrap();
    
    let mconn = Connection::new(
        ctrl_conn.compat(),
        yamux::Config::default(),
        Mode::Client,
    );
    let mconn = Arc::new(Mutex::new(mconn));
    let _mconn = mconn.clone();
    task::spawn(noop_server(stream::poll_fn(move |cx| {
        _mconn.lock().unwrap().poll_next_inbound(cx)
    })));
    // 面向于inside端
    while let Ok(tcp_accept) = tcp_worker.accept() {
        log::info!("dst: {}", tcp_accept.dst);
        let stream = future::poll_fn(|cx| mconn.lock().unwrap().poll_new_outbound(cx)).await.unwrap();
        let mut _mux_stream = stream.compat();
        
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

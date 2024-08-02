use std::{
    fs::File,
    io::{BufReader, Cursor, Read, Write},
    net::Ipv4Addr,
    str::FromStr,
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio_rustls::{rustls, webpki, TlsConnector};

mod udp;
mod tcp;
mod delay;

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

    if let Some(mut udp_worker) = oudp_worker {
        let server_udp: String = cfg.server.clone();
        let connector_udp = connector.clone();
        let domain_udp = domain.clone();
        let jn = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let r = delay::Delay::new();
                loop {
                    udp_worker = udp::worker(server_udp.clone(), connector_udp.clone(), domain_udp.clone(), udp_worker.clone()).await;
                    r.delay().await;
                }
            });
        });
        joins.push(jn);
    }

    // tcp
    if let Some(mut tcp_worker) = otcp_worker {
        let jn = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let r = delay::Delay::new();
                loop {
                    tcp_worker = tcp::worker(cfg.server.clone(), connector.clone(), domain.clone(), tcp_worker).await;
                    r.delay().await;
                }
            });
        });
        joins.push(jn);
    }
    for ele in joins {
        ele.join().unwrap();
    }
}

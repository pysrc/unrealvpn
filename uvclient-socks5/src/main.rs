use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_rustls::{rustls, webpki, TlsConnector};

mod tcp;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    bind: String,
    server: String,
    #[serde(default)]
    full: bool,
    #[serde(rename = "ssl-cert")]
    ssl_cert: String,
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
    let domain_cache_cfg = "domain_cache.yml";
    let cfg = Config::from_file("s5client-config.yml");
    let mut cert = Vec::<u8>::new();
    match File::open(cfg.ssl_cert) {
        Ok(mut f) => f.read_to_end(&mut cert).unwrap(),
        Err(e) => panic!("{}", e),
    };
    let (connector, domain) = tls_cert(&cert, "unrealvpn");
    let mut listener = TcpListener::bind(&cfg.bind).await.unwrap();
    log::info!("bind on: {}", cfg.bind);
    // 加载缓存
    let _domain_cache = match std::fs::read_to_string(domain_cache_cfg) {
        Ok(ymlstr) => {
            let wrapper: tcp::HashSetWrapper =
                serde_yaml::from_str(&ymlstr).expect("Unable to parse YAML");
            wrapper
        }
        Err(_) => tcp::HashSetWrapper {
            local: HashSet::new(),
            server: HashSet::new(),
        },
    };
    let mut _domain_cache = Arc::new(RwLock::new(_domain_cache));

    let mut t = 1;
    loop {
        listener = tcp::worker(
            listener,
            cfg.full,
            cfg.server.clone(),
            connector.clone(),
            domain.clone(),
            domain_cache_cfg,
            _domain_cache.clone(),
        )
        .await;
        // 指数退让
        log::info!("tcp waite for {t} secs.");
        tokio::time::sleep(tokio::time::Duration::from_secs(t)).await;
        t <<= 1;
        if t > 60 {
            // 1 min 重置
            t = 1;
        }
    }
}

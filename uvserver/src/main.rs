use std::{fs::File, io::{BufReader, Cursor, Read}, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};
mod tcpmuxserver;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    bind: String,
    #[serde(rename = "ssl-cert")]
    ssl_cert: String,
    #[serde(rename = "ssl-key")]
    ssl_key: String,
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

#[inline]
pub fn u16_convert(data: &[u8]) -> u16 {
    let a = data[0] as u16;
    let b = data[1] as u16;
    (a<<8) | b
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let cfg = Config::from_file("server-config.yml");
    let mut cert = Vec::<u8>::new();
    match File::open(cfg.ssl_cert) {
        Ok(mut f) => f.read_to_end(&mut cert).unwrap(),
        Err(e) => panic!("{}", e)
    };
    let mut key = Vec::<u8>::new();
    match File::open(cfg.ssl_key) {
        Ok(mut f) => f.read_to_end(&mut key).unwrap(),
        Err(e) => panic!("{}", e)
    };
    let listener = TcpListener::bind(&cfg.bind)
        .await
        .unwrap();

    let pubcs = Cursor::new(cert);
    let mut br = BufReader::new(pubcs);
    let cetrs = rustls_pemfile::certs(&mut br).unwrap();
    let prics = Cursor::new(key);
    let mut brk = BufReader::new(prics);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut brk).unwrap();
    let certificate = rustls::Certificate(cetrs[0].clone());
    let private_key = rustls::PrivateKey(keys[0].clone());
    let cert_chain = vec![certificate];
    let tlsconfig = Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .unwrap(),
    );
    let tlsacceptor = TlsAcceptor::from(tlsconfig);
    log::info!("bind on: {}", cfg.bind);
    loop {
        match listener.accept().await {
            Ok((income_conn, _addr)) => {
                let tlsacceptor = tlsacceptor.clone();
                tokio::spawn(async move {
                    let ctrl_conn = match tlsacceptor.accept(income_conn).await {
                        Ok(x) => x,
                        Err(e) => {
                            log::error!("peer error {} {}", _addr, e);
                            return;
                        }
                    };
                    tcpmuxserver::start_mux(tokio_rustls::TlsStream::Server(ctrl_conn)).await;
                });
            }
            Err(e) => {
                log::error!("listener error {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }

}

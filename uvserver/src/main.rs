use std::{fs::File, io::{BufReader, Cursor, Read}, num::NonZeroU64, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tokio_rustls::{rustls, TlsAcceptor};

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
                    log::info!("client income {}", _addr);
                    let (_, mut mux_acceptor, mux_worker) = async_smux::MuxBuilder::server().with_keep_alive_interval(NonZeroU64::new(30).unwrap()).with_connection(ctrl_conn).build();
                    tokio::spawn(mux_worker);
                    loop {
                        let mut _stream = match mux_acceptor.accept().await {
                            Some(_cc) => _cc,
                            None => {
                                log::info!("client break {}", _addr);
                                return;
                            }
                        };
                        tokio::spawn(async move {
                            let _len = _stream.read_u16().await.unwrap() as usize;
                            let mut _dst_data = vec![0u8; _len];
                            _stream.read_exact(&mut _dst_data).await.unwrap();
                            // 解析地址
                            let dst = String::from_utf8_lossy(&_dst_data).to_string();
                            log::info!("{} open dst {}", line!(), dst);
                            match TcpStream::connect(&dst).await {
                                Ok(mut stream) => {
                                    log::info!("{} open dst success {}", line!(), dst);
                                    _ = tokio::io::copy_bidirectional(&mut stream, &mut _stream).await;
                                }
                                Err(e) => {
                                    log::error!("{} -> {} open dst error {}", line!(), dst, e);
                                    _ = _stream.shutdown().await;
                                }
                            }
                            
                            log::info!("{} close dst {}", line!(), dst);
                        });
                    }
                });
            }
            Err(e) => {
                log::error!("listener error {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }

}

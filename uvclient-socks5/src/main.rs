use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::{rustls, webpki, TlsConnector};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
mod tcpmuxclient;

async fn handle_client(
    mut stream: TcpStream, 
    smc: tcpmuxclient::StreamMuxClient,
    _server_domainc: Arc<RwLock<HashSet<String>>>,
) -> Result<(), Box<dyn Error>> {
    // 读取第一个字节，这是版本号，应该是 5
    let mut buffer = [0; 2];
    stream.read_exact(&mut buffer).await?;
    if buffer[0] != 5 {
        // 非 SOCKS5 协议，关闭连接
        log::error!("{}->{}", line!(), buffer[0]);
        return Ok(());
    }
    if buffer[1] > 0 {
        let mut met = vec![0u8; buffer[1] as usize];
        stream.read_exact(&mut met).await?;
        if met[0] != 0 {
            log::error!("{}->{}", line!(), met[0]);
            return Ok(());
        }
    }

    // 发送协商响应，告诉客户端不需要认证
    stream.write_all(&[5, 0]).await?;

    // 读取客户端的连接请求
    let mut buffer = [0; 4];
    stream.read_exact(&mut buffer).await?;

    // 解析连接请求
    let address = match buffer[3] {
        1 => {
            let mut ip_buffer = [0; 4];
            stream.read_exact(&mut ip_buffer).await?;
            let ip = SocketAddr::from((ip_buffer, 0));
            ip.ip().to_string()
        },
        3 => {
            // 域名
            let mut domain_len = [0; 1];
            stream.read_exact(&mut domain_len).await?;
            let mut domain = vec![0u8; domain_len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        },
        _ => {
            log::error!("{}->{}", line!(), buffer[3]);
            return Ok(()); // 不支持的地址类型
        }
    };
    let mut port_buffer = [0; 2];
    stream.read_exact(&mut port_buffer).await?;
    let port = u16::from_be_bytes(port_buffer);

    log::info!("dst: {}:{}", address, port);

    // 响应连接请求
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    
    // up_stream(stream, address, port, mtx, _channel_mapc, _global_vec_poolc, _global_idc).await;
    // 检查domain是否在远程列表里面
    let _user_server = match _server_domainc.read() {
        Ok(r) => {
            r.contains(&address)
        }
        Err(_) => {
            false
        }
    };
    // 连接目标服务器
    if _user_server {
        // 直接交给上游服务端解析
        smc.add(stream, address, port).await;
        return Ok(());
    }
    let mut target_stream = match timeout(std::time::Duration::from_millis(3000), TcpStream::connect((address.as_str(), port))).await {
        Ok(cc) => match cc {
            Ok(cc) => cc,
            Err(e) => {
                log::error!("dst error {}: {}:{}", e, address, port);
                return Ok(());
            }
        },
        Err(_) => {
            // 超时，交给上游服务端解析
            match _server_domainc.write() {
                Ok(mut _w) => {
                    _w.insert(address.clone());
                }
                Err(_) => {}
            }
            smc.add(stream, address, port).await;
            return Ok(());
        }
    };

    // 转发数据
    let (mut client_reader, mut client_writer) = stream.split();
    let (mut target_reader, mut target_writer) = target_stream.split();

    tokio::try_join!(
        tokio::io::copy(&mut client_reader, &mut target_writer),
        tokio::io::copy(&mut target_reader, &mut client_writer),
    )?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    bind: String,
    server: String,
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

#[derive(Serialize, Deserialize)]
struct HashSetWrapper {
    set: HashSet<String>,
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
async fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let server_domain_cfg = "server_domain.yml";
    let cfg = Config::from_file("s5client-config.yml");
    let mut cert = Vec::<u8>::new();
    match File::open(cfg.ssl_cert) {
        Ok(mut f) => f.read_to_end(&mut cert).unwrap(),
        Err(e) => panic!("{}", e)
    };

    let (connector, domain) = tls_cert(&cert, "unrealvpn");

    let ctrl_conn = TcpStream::connect(cfg.server).await.unwrap();
    let ctrl_conn = connector.connect(domain.clone(), ctrl_conn).await.unwrap();

    let listener = TcpListener::bind(&cfg.bind).await?;
    log::info!("bind on: {}", cfg.bind);

    let smc = tcpmuxclient::StreamMuxClient::init(tokio_rustls::TlsStream::Client(ctrl_conn)).await;

    // 加载服务端缓存
    let _server_domain = match std::fs::read_to_string(server_domain_cfg) {
        Ok(ymlstr) => {
            let wrapper: HashSetWrapper = serde_yaml::from_str(&ymlstr).expect("Unable to parse YAML");
            wrapper.set
        }
        Err(_) => {
            HashSet::<String>::new()
        }
    };
    let mut _server_domain = Arc::new(RwLock::new(_server_domain));
    let _server_domainc = _server_domain.clone();
    tokio::spawn(async move {
        // 检测服务端域名是否新增，是的话写入文件
        let mut _len = match _server_domainc.read() {
            Ok(_r) => _r.len(),
            Err(_) => 0,
        };
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let _current_len = match _server_domainc.read() {
                Ok(_r) => _r.len(),
                Err(_) => 0,
            };
            if _current_len == _len {
                continue;
            }
            _len = _current_len;
            // 将 HashSet 包装到结构体中以进行序列化
            match _server_domainc.read() {
                Ok(_data) => {
                    let wrapper = HashSetWrapper { set: _data.clone() };

                    // 将数据序列化为 YAML 格式
                    let yaml_data = serde_yaml::to_string(&wrapper).unwrap();
        
                    // 将 YAML 数据写入文件
                    if let Ok(mut file) = File::create(server_domain_cfg) {
                        let _ = file.write_all(yaml_data.as_bytes());
                    }
                }
                Err(_) => {}
            }
        }
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let smcc = smc.clone();
        let _server_domainc = _server_domain.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, smcc, _server_domainc).await {
                log::error!("{}->{}", line!(), e);
            }
        });
    }
}

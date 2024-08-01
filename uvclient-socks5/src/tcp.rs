use std::{
    collections::HashSet, error::Error, fs::File, io::Write, net::SocketAddr, num::NonZeroU64, sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    }
};

use async_smux::MuxStream;
use serde::{Deserialize, Serialize};
use tokio::{ io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::timeout};
use tokio_rustls::{client::TlsStream, rustls::ServerName, TlsConnector};

#[derive(Serialize, Deserialize)]
pub struct HashSetWrapper {
    // 走本地的域名
    pub local: HashSet<String>,
    // 走服务的域名
    pub server: HashSet<String>,
}

async fn handle_client(
    mut stream: TcpStream, 
    mut _mux_stream: MuxStream<TlsStream<TcpStream>>,
    _domain_cachec: Arc<RwLock<HashSetWrapper>>,
    full: bool,
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
    
    if full {
        // 直接交给上游服务端解析
        let target = format!("{}:{}", address, port);
        _mux_stream.write_u16(target.len() as u16).await.unwrap();
        _mux_stream.write_all(target.as_bytes()).await.unwrap();
        _mux_stream.flush().await.unwrap();
        _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut stream).await;
        _ = _mux_stream.shutdown().await;
        return Ok(());
    }
    // 检查domain是远程还是本地解析
    
    let _domain_parse = match _domain_cachec.read() {
        Ok(r) => {
            (r.local.contains(&address), r.server.contains(&address))
        }
        Err(_) => {
            (false, false)
        }
    };
    // 连接目标服务器
    if _domain_parse.0 {
        // 必须本地解析
        let mut target_stream = match TcpStream::connect((address.as_str(), port)).await {
            Ok(_conn) => _conn,
            Err(e) => {
                log::error!("dst error {} {}: {}:{}", line!(), e, address, port);
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

        return Ok(())
    }
    if _domain_parse.1 {
        // 直接交给上游服务端解析
        let target = format!("{}:{}", address, port);
        _mux_stream.write_u16(target.len() as u16).await.unwrap();
        _mux_stream.write_all(target.as_bytes()).await.unwrap();
        _mux_stream.flush().await.unwrap();
        _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut stream).await;
        _ = _mux_stream.shutdown().await;
        return Ok(());
    }
    match timeout(std::time::Duration::from_millis(3000), TcpStream::connect((address.as_str(), port))).await {
        Ok(cc) => match cc {
            Ok(mut target_stream) => {
                // 本地解析
                match _domain_cachec.write() {
                    Ok(mut _w) => {
                        _w.local.insert(address.clone());
                    }
                    Err(_) => {
                        return Ok(());
                    }
                }
                // 转发数据
                let (mut client_reader, mut client_writer) = stream.split();
                let (mut target_reader, mut target_writer) = target_stream.split();

                tokio::try_join!(
                    tokio::io::copy(&mut client_reader, &mut target_writer),
                    tokio::io::copy(&mut target_reader, &mut client_writer),
                )?;

                return Ok(());
            },
            Err(e) => {
                log::error!("dst error {}: {}:{}", e, address, port);
                return Ok(());
            }
        },
        Err(_) => {
            // 超时，交给上游服务端解析
            match _domain_cachec.write() {
                Ok(mut _w) => {
                    _w.server.insert(address.clone());
                }
                Err(_) => {
                    return Ok(());
                }
            }
            let target = format!("{}:{}", address, port);
            _mux_stream.write_u16(target.len() as u16).await.unwrap();
            _mux_stream.write_all(target.as_bytes()).await.unwrap();
            _mux_stream.flush().await.unwrap();
            _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut stream).await;
            _ = _mux_stream.shutdown().await;
            return Ok(());
        }
    };
}

const CMD_TCP: u8 = 2;

pub async fn worker (
    listener: TcpListener,
    proxy_full: bool,
    server: String,
    connector: TlsConnector,
    domain: ServerName,
    domain_cache_cfg: &'static str,
    domain_cache: Arc<RwLock<HashSetWrapper>>
) -> TcpListener {
    let ctrl_conn = match TcpStream::connect(server.clone()).await {
        Ok(_conn) => _conn,
        Err(_) => {
            return listener;
        }
    };
    let mut ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> =
        match connector.connect(domain.clone(), ctrl_conn).await {
            Ok(_conn) => _conn,
            Err(_) => {
                return listener;
            }
        };
    if let Err(_) = ctrl_conn.write_u8(CMD_TCP).await {
        return listener;
    }
    log::info!("Connection established.");
    let (mux_connector, _, mux_worker) = async_smux::MuxBuilder::client()
        .with_keep_alive_interval(NonZeroU64::new(30).unwrap())
        .with_connection(ctrl_conn)
        .build();
    tokio::spawn(mux_worker);
    let runing = Arc::new(AtomicBool::new(true));
    let runingr = runing.clone();
    let _domain_cachec = domain_cache.clone();    
    if !proxy_full {
        tokio::spawn(async move {
            // 检测服务端域名是否新增，是的话写入文件
            let mut lens = match _domain_cachec.read() {
                Ok(_cache) => {
                    (_cache.local.len(), _cache.server.len())
                }
                Err(_) => {
                    runingr.store(false, Ordering::Relaxed);
                    return;
                }
            };
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let lens_temp = match _domain_cachec.read() {
                    Ok(_cache) => {
                        (_cache.local.len(), _cache.server.len())
                    }
                    Err(_) => {
                        runingr.store(false, Ordering::Relaxed);
                        return;
                    }
                };
                if lens == lens_temp {
                    continue;
                }
                lens = lens_temp;
                // 将 HashSet 包装到结构体中以进行序列化
                match _domain_cachec.read() {
                    Ok(_data) => {
                        // let wrapper = HashSetWrapper { set: _data.clone() };
                        let wrapper = HashSetWrapper {
                            local: _data.local.clone(),
                            server: _data.server.clone(),
                        };
                        // 将数据序列化为 YAML 格式
                        let yaml_data = match serde_yaml::to_string(&wrapper) {
                            Ok(f) => f,
                            Err(_) => {
                                runingr.store(false, Ordering::Relaxed);
                                return;
                            }
                        };
            
                        // 将 YAML 数据写入文件
                        if let Ok(mut file) = File::create(domain_cache_cfg) {
                            let _ = file.write_all(yaml_data.as_bytes());
                        }
                    }
                    Err(_) => {
                    }
                }
            }
        });
    }
    while runing.load(Ordering::Relaxed) {
        let (stream, _) = match listener.accept().await {
            Ok(t) => t,
            Err(_) => {
                return listener;
            }
        };
        let _domain_cachec = domain_cache.clone();
        let mut _mux_stream = match mux_connector.connect() {
            Ok(cc) => cc,
            Err(_) => {
                return listener;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, _mux_stream, _domain_cachec, proxy_full).await {
                log::error!("{}->{}", line!(), e);
            }
        });
    }
    return listener;
    
}

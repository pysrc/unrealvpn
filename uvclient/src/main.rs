use std::{collections::{HashMap, VecDeque}, fs::File, io::{BufReader, Cursor, Read, Write}, net::Ipv4Addr, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, select, sync::{mpsc, Mutex}};
use tokio_rustls::{rustls, webpki, TlsConnector};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    uvserver: String,
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
    let cfg = Config::from_file("config.yml");
    let mut cert = Vec::<u8>::new();
    match File::open(cfg.ssl_cert) {
        Ok(mut f) => f.read_to_end(&mut cert).unwrap(),
        Err(e) => panic!("{}", e)
    };

    let (connector, domain) = tls_cert(&cert, "unrealvpn");

    let ctrl_conn = TcpStream::connect(cfg.uvserver).await.unwrap();
    let mut ctrl_conn = connector.connect(domain.clone(), ctrl_conn).await.unwrap();
    
    let tun = tun2layer4::os_tun::new(
        String::from("unrealvpn"),
        Ipv4Addr::new(10, 28, 13, 0),
        24,
        Some(cfg.routes),
    );

    // 主连接channel
    let (mtx, mut mrx) = mpsc::channel::<Vec<u8>>(10);
    // 发送channel
    let mut _channel_map = Arc::new(Mutex::new(HashMap::<[u8;12], mpsc::Sender<Vec<u8>>>::new()));
    // 全局数组池
    let _global_vec_pool = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
    let _channel_mapmw = _channel_map.clone();
    let _global_vec_poolc = _global_vec_pool.clone();
    let mmtx = mtx.clone();
    tokio::spawn(async move {
        let mut _meta_buffer = [0u8;12];
        loop {
            select! {
                _datao = mrx.recv() => {
                    // 发给inside
                    match _datao {
                        Some(_data) => {
                            if let Err(_) = ctrl_conn.write_all(&_data).await {
                                {
                                    let mut _gvp = _global_vec_poolc.lock().await;
                                    _gvp.push_back(_data);
                                }
                                _ = ctrl_conn.shutdown().await;
                                log::error!("ctrl_conn break");
                                return;
                            } else {
                                let mut _gvp = _global_vec_poolc.lock().await;
                                _gvp.push_back(_data);
                            }
                        }
                        None => {
                            _ = ctrl_conn.shutdown().await;
                            log::error!("mtx break");
                            return;
                        }
                    }
                }
                _cmd = ctrl_conn.read_u8() => {
                    match _cmd {
                        Ok(_cmd) => {
                            match _cmd {
                                0b1000_1000 => {
                                    // inside交付数据包
                                    if let Err(e) = ctrl_conn.read_exact(&mut _meta_buffer).await {
                                        _ = ctrl_conn.shutdown().await;
                                        log::error!("{} read from inside error {}", line!(), e);
                                        return;
                                    }
                                    let _data_len = match ctrl_conn.read_u16().await {
                                        Ok(n) => n as usize,
                                        Err(e) => {
                                            _ = ctrl_conn.shutdown().await;
                                            log::error!("{} read from inside error {}", line!(), e);
                                            return;
                                        }
                                    };
                                    let mut _read_buf = {
                                        let mut _gvp = _global_vec_poolc.lock().await;
                                        match _gvp.pop_back() {
                                            Some(mut _vec) => {
                                                unsafe {
                                                    _vec.set_len(0);
                                                }
                                                if _vec.capacity() < _data_len {
                                                    _vec.reserve(_data_len);
                                                }
                                                _vec
                                            },
                                            None => {
                                                Vec::<u8>::with_capacity(_data_len)
                                            }
                                        }
                                    };
                                    unsafe {
                                        _read_buf.set_len(_data_len);
                                    }
                                    if let Err(e) = ctrl_conn.read_exact(&mut _read_buf).await {
                                        _ = ctrl_conn.shutdown().await;
                                        log::error!("read from inside error {}", e);
                                        return;
                                    }
                                    {
                                        let mut _channel_mapmw = _channel_mapmw.lock().await;
                                        match _channel_mapmw.get_mut(&_meta_buffer) {
                                            Some(tx) => {
                                                _ = tx.send(_read_buf).await;
                                            }
                                            None => {
                                                log::error!("{}", line!());
                                            }
                                        }
                                        
                                    }
                                    
                                }
                                0b1000_1010 => {
                                    // inside连接远端成功
                                    log::info!("remote success {}", line!());
                                    if let Err(e) = ctrl_conn.read_exact(&mut _meta_buffer).await {
                                        _ = ctrl_conn.shutdown().await;
                                        log::error!("{} read from inside error {}", line!(), e);
                                        return;
                                    }
                                    let _data_len = match ctrl_conn.read_u16().await {
                                        Ok(n) => n as usize,
                                        Err(e) => {
                                            _ = ctrl_conn.shutdown().await;
                                            log::error!("{} read from inside error {}", line!(), e);
                                            return;
                                        }
                                    };
                                    let mut _read_buf = {
                                        let mut _gvp = _global_vec_poolc.lock().await;
                                        match _gvp.pop_back() {
                                            Some(mut _vec) => {
                                                unsafe {
                                                    _vec.set_len(0);
                                                }
                                                if _vec.capacity() < _data_len {
                                                    _vec.reserve(_data_len);
                                                }
                                                _vec
                                            },
                                            None => {
                                                Vec::<u8>::with_capacity(_data_len)
                                            }
                                        }
                                    };
                                    _read_buf.push(0b1000_1010);
                                    {
                                        let mut _channel_mapmw = _channel_mapmw.lock().await;
                                        match _channel_mapmw.get_mut(&_meta_buffer) {
                                            Some(tx) => {
                                                _ = tx.send(_read_buf).await;
                                            }
                                            None => {
                                                // todo 远端成功，我方超时关闭连接，通知远端关闭连接
                                                log::error!("{}->inside success and outside close", line!());
                                                let mut _gvp = _global_vec_poolc.lock().await;
                                                _gvp.push_back(_read_buf);
                                                // 通知inside关闭连接
                                                let _data_len = 13;
                                                let mut _kill_buf = {
                                                    let mut _gvp = _global_vec_poolc.lock().await;
                                                    match _gvp.pop_back() {
                                                        Some(mut _vec) => {
                                                            unsafe {
                                                                _vec.set_len(0);
                                                            }
                                                            if _vec.capacity() < _data_len {
                                                                _vec.reserve(_data_len);
                                                            }
                                                            _vec
                                                        },
                                                        None => {
                                                            Vec::<u8>::with_capacity(_data_len)
                                                        }
                                                    }
                                                };
                                                _kill_buf.push(0b1010_0100);
                                                _kill_buf.extend_from_slice(&_meta_buffer);
                                                _ = mmtx.send(_kill_buf).await;
                                            }
                                        }
                                    }
                                }
                                0b1000_1001 => {
                                    // inside连接远端失败
                                    log::error!("remote error {}", line!());
                                    if let Err(e) = ctrl_conn.read_exact(&mut _meta_buffer).await {
                                        _ = ctrl_conn.shutdown().await;
                                        log::error!("{} read from inside error {}", line!(), e);
                                        return;
                                    }
                                    match ctrl_conn.read_u16().await {
                                        Ok(n) => n as usize,
                                        Err(e) => {
                                            _ = ctrl_conn.shutdown().await;
                                            log::error!("{} read from inside error {}", line!(), e);
                                            return;
                                        }
                                    };
                                    {
                                        let mut _channel_mapmw = _channel_mapmw.lock().await;
                                        _ = _channel_mapmw.remove(&_meta_buffer);
                                    }
                                }
                                0b1010_1000 => {
                                    // inside连接关闭，关闭outside连接
                                    let mut _meta_buffer = [0u8;12];
                                    match ctrl_conn.read_exact(&mut _meta_buffer).await {
                                        Ok(_) => {
                                            log::info!("i->{} close {:?}", line!(), _meta_buffer);
                                            let mut _channel_mapw = _channel_mapmw.lock().await;
                                            _channel_mapw.remove(&_meta_buffer);
                                        }
                                        Err(e) => {
                                            log::error!("{}->{}", line!(), e);
                                        }
                                    }
                                }
                                _ => {
                                    log::error!("no cmd map {}", _cmd);
                                }
                            }
                        }
                        Err(e) => {
                            _ = ctrl_conn.shutdown().await;
                            log::error!("{}->{}", line!(), e);
                            return;
                        }
                    }
                }
            }
        }
    });
    // 面向于inside端
    while let Ok(tcp_accept) = tun.accept_tcp() {
        log::info!("dst: {}", tcp_accept.dst);
        let mtx = mtx.clone();
        let _channel_mapc = _channel_map.clone();
        let _global_vec_poolc = _global_vec_pool.clone();
        tokio::spawn(async move {
            let mut _meta_buffer = [0u8;12];
            _meta_buffer[0..4].copy_from_slice(&tcp_accept.src.ip().octets());
            _meta_buffer[4] = (tcp_accept.src.port() >> 8) as u8;
            _meta_buffer[5] = tcp_accept.src.port() as u8;

            _meta_buffer[6..10].copy_from_slice(&tcp_accept.dst.ip().octets());
            _meta_buffer[10] = (tcp_accept.dst.port() >> 8) as u8;
            _meta_buffer[11] = tcp_accept.dst.port() as u8;
            let _data_len = 13;
            let mut sv = {
                let mut _gvp = _global_vec_poolc.lock().await;
                match _gvp.pop_back() {
                    Some(mut _vec) => {
                        unsafe {
                            _vec.set_len(0);
                        }
                        if _vec.capacity() < _data_len {
                            _vec.reserve(_data_len);
                        }
                        _vec
                    },
                    None => {
                        Vec::<u8>::with_capacity(_data_len)
                    }
                }
            };
            sv.push(0b1100_0100);
            sv.extend_from_slice(&_meta_buffer);
            if let Err(_) = mtx.send(sv).await {
                log::error!("main channel stop");
                return;
            }
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
            {
                let mut _channel_mapcw = _channel_mapc.lock().await;
                _channel_mapcw.insert(_meta_buffer, tx);
            }
            // 等待inside确认目标端口已经连接上
            select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    // 如果60秒还没连接上目标端口，直接按超时处理
                    tcp_accept.stream.shutdown(std::net::Shutdown::Both).unwrap();
                    {
                        let mut _channel_mapcw = _channel_mapc.lock().await;
                        _ = _channel_mapcw.remove(&_meta_buffer);
                    }
                    log::error!("{}->dst error overtime: {}", line!(), tcp_accept.dst);
                    return;
                }
                _data = rx.recv() => {
                    match _data {
                        Some(mut _data) => {
                            log::info!("{}->{:?}", line!(), _data);
                            let success = if _data.len() == 1 {
                                let _res = _data.remove(0);
                                if _res == 0b1000_1010 {
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                            {
                                let mut _gvp = _global_vec_poolc.lock().await;
                                _gvp.push_back(_data);
                            }
                            if !success {
                                log::error!("{}->dst error: {}", line!(), tcp_accept.dst);
                                // 目标端口拒绝
                                {
                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                    _ = _channel_mapcw.remove(&_meta_buffer);
                                }
                                tcp_accept.stream.shutdown(std::net::Shutdown::Both).unwrap();
                                return;
                            }
                            log::info!("{}->dst success: {}", line!(), tcp_accept.dst);
                        }
                        None => {
                            log::error!("{}->dst error: {}", line!(), tcp_accept.dst);
                            // 目标端口拒绝
                            {
                                let mut _channel_mapcw = _channel_mapc.lock().await;
                                _ = _channel_mapcw.remove(&_meta_buffer);
                            }
                            tcp_accept.stream.shutdown(std::net::Shutdown::Both).unwrap();
                            return;
                        }
                    }
                }
            }
            let conn = tcp_accept.stream.try_clone().unwrap();
            conn.set_nonblocking(true).unwrap();
            let mut conn = tokio::net::TcpStream::from_std(conn).unwrap();
            let _data_len = 1600;
            let mut _read_buf = {
                let mut _gvp = _global_vec_poolc.lock().await;
                match _gvp.pop_back() {
                    Some(mut _vec) => {
                        unsafe {
                            _vec.set_len(0);
                        }
                        if _vec.capacity() < _data_len {
                            _vec.reserve(_data_len);
                        }
                        _vec
                    },
                    None => {
                        Vec::<u8>::with_capacity(_data_len)
                    }
                }
            };
            _read_buf.push(0b1000_0100);
            _read_buf.extend_from_slice(&_meta_buffer);
            _read_buf.push(0);
            _read_buf.push(0);
            loop {
                select! {
                    _data = rx.recv() => {
                        match _data {
                            Some(_data) => {
                                if let Err(e) = conn.write_all(&_data).await {
                                    {
                                        let mut _gvp = _global_vec_poolc.lock().await;
                                        _gvp.push_back(_data);
                                    }
                                    _ = conn.shutdown().await;
                                    rx.close();
                                    {
                                        let mut _channel_mapcw = _channel_mapc.lock().await;
                                        _channel_mapcw.remove(&_meta_buffer);
                                    }
                                    log::error!("{}->close dst: {} {}", line!(), tcp_accept.dst, e);
                                    return;
                                } else {
                                    let mut _gvp = _global_vec_poolc.lock().await;
                                    _gvp.push_back(_data);
                                }
                            }
                            None => {
                                _ = conn.shutdown().await;
                                rx.close();
                                {
                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                    _channel_mapcw.remove(&_meta_buffer);
                                }
                                log::error!("{}->close dst: {}", line!(), tcp_accept.dst);
                                return;
                            }
                        }
                    },
                    _rn = conn.read_buf(&mut _read_buf) => {
                        match _rn {
                            Ok(n) => {
                                if n > 0 {
                                    if n > 0xffff {
                                        log::error!("buffer over 0xffff {}", n);
                                        _ = conn.shutdown().await;
                                        rx.close();
                                        {
                                            let mut _channel_mapcw = _channel_mapc.lock().await;
                                            _channel_mapcw.remove(&_meta_buffer);
                                        }
                                        log::error!("{}->close dst: {}", line!(), tcp_accept.dst);
                                        return;
                                    }
                                    _read_buf[13] = (n >> 8) as u8;
                                    _read_buf[14] = n as u8;
                                    if let Err(e) = mtx.send(_read_buf).await {
                                        _ = conn.shutdown().await;
                                        rx.close();
                                        {
                                            let mut _channel_mapcw = _channel_mapc.lock().await;
                                            _channel_mapcw.remove(&_meta_buffer);
                                        }
                                        log::error!("{}->close dst: {} {}", line!(), tcp_accept.dst, e);
                                        return;
                                    }
                                    _read_buf = {
                                        let mut _gvp = _global_vec_poolc.lock().await;
                                        match _gvp.pop_back() {
                                            Some(mut _vec) => {
                                                unsafe {
                                                    _vec.set_len(0);
                                                }
                                                if _vec.capacity() < _data_len {
                                                    _vec.reserve(_data_len);
                                                }
                                                _vec
                                            },
                                            None => {
                                                Vec::<u8>::with_capacity(_data_len)
                                            }
                                        }
                                    };
                                    _read_buf.push(0b1000_0100);
                                    _read_buf.extend_from_slice(&_meta_buffer);
                                    _read_buf.push(0);
                                    _read_buf.push(0);
                                } else {
                                    _ = conn.shutdown().await;
                                    rx.close();
                                    {
                                        let mut _channel_mapcw = _channel_mapc.lock().await;
                                        _channel_mapcw.remove(&_meta_buffer);
                                    }
                                    // 通知inside关闭连接
                                    let _data_len = 13;
                                    let mut _kill_buf = {
                                        let mut _gvp = _global_vec_poolc.lock().await;
                                        match _gvp.pop_back() {
                                            Some(mut _vec) => {
                                                unsafe {
                                                    _vec.set_len(0);
                                                }
                                                if _vec.capacity() < _data_len {
                                                    _vec.reserve(_data_len);
                                                }
                                                _vec
                                            },
                                            None => {
                                                Vec::<u8>::with_capacity(_data_len)
                                            }
                                        }
                                    };
                                    _kill_buf.push(0b1010_0100);
                                    _kill_buf.extend_from_slice(&_meta_buffer);
                                    _ = mtx.send(_kill_buf).await;
                                    log::error!("{}->close dst: {}", line!(), tcp_accept.dst);
                                    return;
                                }
                            }
                            Err(e) => {
                                _ = conn.shutdown().await;
                                rx.close();
                                {
                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                    _channel_mapcw.remove(&_meta_buffer);
                                }
                                // 通知inside关闭连接
                                let _data_len = 13;
                                let mut _kill_buf = {
                                    let mut _gvp = _global_vec_poolc.lock().await;
                                    match _gvp.pop_back() {
                                        Some(mut _vec) => {
                                            unsafe {
                                                _vec.set_len(0);
                                            }
                                            if _vec.capacity() < _data_len {
                                                _vec.reserve(_data_len);
                                            }
                                            _vec
                                        },
                                        None => {
                                            Vec::<u8>::with_capacity(_data_len)
                                        }
                                    }
                                };
                                _kill_buf.push(0b1010_0100);
                                _kill_buf.extend_from_slice(&_meta_buffer);
                                _ = mtx.send(_kill_buf).await;
                                log::error!("{}->close dst: {} {}", line!(), tcp_accept.dst, e);
                                return;
                            }
                        }
                    }
                }
            }
            

        });
    }
}

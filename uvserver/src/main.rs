use std::{collections::{HashMap, VecDeque}, fs::File, io::{BufReader, Cursor, Read}, net::{Ipv4Addr, SocketAddrV4}, sync::Arc};

use futures::{future, stream, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{io::{split, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, select, sync::{mpsc, Mutex, RwLock}, time};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Connection, ConnectionError, Mode};

pub async fn noop_server(c: impl Stream<Item = Result<yamux::Stream, yamux::ConnectionError>>) {
    c.for_each(|maybe_stream| {
        drop(maybe_stream);
        future::ready(())
    })
    .await;
}

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

const CMD_UDP: u8= 1;
const CMD_TCP: u8= 2;


#[derive(Clone)]
struct VecPool {
    vec_pool: Arc<Mutex<VecDeque<Vec<u8>>>>
}

impl VecPool {
    pub fn new(size: usize) -> Self {
        let mut _inner = VecDeque::<Vec<u8>>::with_capacity(size);
        for _ in 0..size {
            _inner.push_back(Vec::with_capacity(100));
        }
        VecPool {
            vec_pool: Arc::new(Mutex::new(_inner))
        }
    }
    pub async fn pop(&mut self, size: usize) -> Vec<u8> {
        let mut t = self.vec_pool.lock().await;
        let v = t.pop_back();
        match v {
            Some(mut d) => {
                log::info!("replace vec {}", t.len());
                d.resize(size, 0);
                return d;
            }
            None => {
                log::info!("new vec {}", t.len());
                let mut d = Vec::with_capacity(size);
                unsafe {
                    d.set_len(size);
                }
                return d;
            }
        }
    }
    pub async fn back(&mut self, mut data: Vec<u8>) {
        unsafe {
            data.set_len(0);
        }
        let mut t = self.vec_pool.lock().await;
        t.push_back(data);
        log::info!("back vec {}", t.len());
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
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
                    let mut ctrl_conn = match tlsacceptor.accept(income_conn).await {
                        Ok(x) => x,
                        Err(e) => {
                            log::error!("peer error {} {}", _addr, e);
                            return;
                        }
                    };
                    let _cmd = match ctrl_conn.read_u8().await {
                        Ok(_t) => _t,
                        Err(e) => {
                            log::info!("{} {}", line!(), e);
                            return;
                        }
                    };
                    match _cmd {
                        CMD_TCP => {
                            log::info!("TCP client income {}", _addr);
                            let mut mconn = Connection::new(
                                ctrl_conn.compat(),
                                yamux::Config::default(),
                                Mode::Server,
                            );
                            let mut server = stream::poll_fn(move |cx| mconn.poll_next_inbound(cx));
                            loop {
                                let mut _stream = match server.next().await.ok_or(ConnectionError::Closed).unwrap() {
                                    Ok(_cc) => _cc,
                                    Err(_) => {
                                        log::info!("client break {}", _addr);
                                        return;
                                    }
                                };
                                let mut _stream = _stream.compat();
                                tokio::spawn(async move {
                                    // let _buf = [0u8;2];
                                    let _len = match _stream.read_u16().await {
                                        Ok(i) => i as usize,
                                        Err(e) => {
                                            log::info!("{} {}", line!(), e);
                                            return;
                                        }
                                    };
                                    let mut _dst_data = vec![0u8; _len];
                                    if let Err(e) = _stream.read_exact(&mut _dst_data).await {
                                        log::info!("{} {}", line!(), e);
                                        return;
                                    }
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
                        }
                        CMD_UDP => {
                            log::info!("UDP client income {}", _addr);
                            let mut vec_pool = VecPool::new(50);
                            let (mut r, mut w) = split(ctrl_conn);
                            let mut key = [0u8;12];
                            let (main_sender, mut main_receiver) = mpsc::channel::<Vec<u8>>(100);
                            let dispatcher_map = Arc::new(RwLock::new(HashMap::<(SocketAddrV4, SocketAddrV4), mpsc::Sender<Vec<u8>>>::new()));
                            let mut vec_pool3 = vec_pool.clone();
                            tokio::spawn(async move {
                                loop {
                                    let recv = main_receiver.recv().await;
                                    match recv {
                                        Some(v) => {
                                            if let Err(e) = w.write_all(&v).await {
                                                log::info!("{} {}", line!(), e);
                                            }
                                            if let Err(e) = w.flush().await {
                                                log::info!("{} {}", line!(), e);
                                            }
                                            log::info!("back {}", line!());
                                            vec_pool3.back(v).await;
                                            log::info!("{}", line!());
                                        }
                                        None => {
                                            log::info!("{}", line!());
                                            return;
                                        }
                                    }
                                }
                            });
                            loop {
                                match r.read_exact(&mut key).await {
                                    Ok(_) => {
                                        let src = SocketAddrV4::new(Ipv4Addr::new(key[0], key[1], key[2], key[3]), u16::from_be_bytes([key[4], key[5]]));
                                        let dst = SocketAddrV4::new(Ipv4Addr::new(key[6], key[7], key[8], key[9]), u16::from_be_bytes([key[10], key[11]]));
                                        log::info!("{} src:{} dst: {}", line!(), src, dst);
                                        let _len = match r.read_u16().await {
                                            Ok(_t) => _t as usize,
                                            Err(e) => {
                                                log::info!("{} {}", line!(), e);
                                                return;
                                            }  
                                        };
                                        log::info!("pop {}", line!());
                                        let mut buf = vec_pool.pop(_len).await;
                                        if let Err(e) = r.read_exact(&mut buf[.._len]).await {
                                            log::info!("{} {}", line!(), e);
                                        }
                                        match dispatcher_map.read().await.get(&(src, dst)) {
                                            Some(_sender) => {
                                                log::info!("{}", line!());
                                                if let Err(e) =  _sender.send(buf).await {
                                                    log::info!("back {}", line!());
                                                    vec_pool.back(e.0).await;
                                                }
                                            }
                                            None => {
                                                log::info!("{}", line!());
                                                let dispatcher_map2 = dispatcher_map.clone();
                                                let mut vec_pool2 = vec_pool.clone();
                                                let main_sender2 = main_sender.clone();
                                                // 添加监听
                                                tokio::spawn(async move{
                                                    let usock = match UdpSocket::bind("0.0.0.0:0").await {
                                                        Ok(_sk) => _sk,
                                                        Err(e) => {
                                                            log::info!("{} {}", line!(), e);
                                                            return;
                                                        }
                                                    };
                                                    if let Err(e) = usock.connect(dst).await {
                                                        log::info!("{} {}", line!(), e);
                                                        return;
                                                    }
                                                    if let Err(e) = usock.send(&buf).await {
                                                        log::info!("{} {}", line!(), e);
                                                        return;
                                                    }
                                                    log::info!("back {}", line!());
                                                    vec_pool2.back(buf).await;
                                                    let (usock_sender, mut usock_receiver) = mpsc::channel::<Vec<u8>>(100);
                                                    // 5分钟不活动自动释放udp绑定端口
                                                    {
                                                        dispatcher_map2.write().await.insert((src, dst), usock_sender);
                                                    }
                                                    let mut interval = time::interval(time::Duration::from_secs(300));
                                                    interval.tick().await;
                                                    log::info!("{}", line!());
                                                    log::info!("pop {}", line!());
                                                    let mut buf = vec_pool2.pop(2046).await;
                                                    loop {
                                                        select! {
                                                            _ = interval.tick() => {
                                                                log::info!("{}", line!());
                                                                // 超时释放连接
                                                                {
                                                                    dispatcher_map2.write().await.remove(&(src, dst));
                                                                }
                                                                log::info!("back {}", line!());
                                                                vec_pool2.back(buf).await;
                                                                return;
                                                            }
                                                            _data = usock_receiver.recv() => {
                                                                log::info!("{}", line!());
                                                                match _data {
                                                                    Some(v) => {
                                                                        if let Err(e) = usock.send(&v).await {
                                                                            log::info!("{} {}", line!(), e);
                                                                            log::info!("back {}", line!());
                                                                            vec_pool2.back(buf).await;
                                                                            return;
                                                                        }
                                                                        log::info!("back {}", line!());
                                                                        vec_pool2.back(v).await;
                                                                        interval.reset();
                                                                    }
                                                                    None => {
                                                                        log::info!("back {}", line!());
                                                                        vec_pool2.back(buf).await;
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                            _len = usock.recv(&mut buf[14..]) => {
                                                                match _len {
                                                                    Ok(_size) => {
                                                                        log::info!("{} {}", line!(), _size);
                                                                        unsafe {
                                                                            buf.set_len(_size + 14);
                                                                        }
                                                                        buf[..4].copy_from_slice(&src.ip().octets());
                                                                        buf[4..6].copy_from_slice(&src.port().to_be_bytes());
                                                                        buf[6..10].copy_from_slice(&dst.ip().octets());
                                                                        buf[10..12].copy_from_slice(&dst.port().to_be_bytes());
                                                                        buf[12..14].copy_from_slice(&(_size as u16).to_be_bytes());
                                                                        if let Err(e) = main_sender2.send(buf).await {
                                                                            log::info!("back {}", line!());
                                                                            vec_pool2.back(e.0).await;
                                                                            return;
                                                                        }
                                                                        log::info!("pop {}", line!());
                                                                        buf = vec_pool2.pop(2046).await;
                                                                        interval.reset();
                                                                    }
                                                                    Err(_) => {
                                                                        log::info!("{}", line!());
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        log::info!("UDP client break");
                                        return;
                                    }
                                }
                                
                            }

                        }
                        _ => {
                            log::info!("{}", line!());
                        }
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

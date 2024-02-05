/// 次源码仅仅提供ip包转换为TCP/UDP的实现方式

use packet::{ip::Protocol, tcp::Flags, Packet, PacketMut};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    sync::{mpsc::channel, Arc, RwLock},
};

pub trait Layer3Device: Send + 'static {
    // 设备ip
    fn ip(&self) -> Ipv4Addr;
    // 处理读取到的包
    fn handle_packet(
        &mut self,
        buffer: &mut [u8],
        unreal_kernel_dst: Ipv4Addr,
        kernel_src_port: u16,
        unreal_context: Arc<RwLock<UnrealContext>>,
    ) -> bool {
        let ip = self.ip();
        match packet::ip::Packet::new(&mut buffer[..]) {
            Ok(packet::ip::Packet::V4(mut ipck)) => {
                // ipv4
                match ipck.protocol() {
                    packet::ip::Protocol::Udp => {}
                    packet::ip::Protocol::Tcp => {
                        let src_addr = ipck.source();
                        let dst_addr = ipck.destination();
                        let mut tcpck = packet::tcp::Packet::new(ipck.payload_mut()).unwrap();
                        let src_port = tcpck.source();
                        let dst_port = tcpck.destination();
                        // 凡是发给虚拟目标地址的都是协议栈返回的
                        if dst_addr == unreal_kernel_dst && src_addr == ip {
                            // 协议栈返回
                            let _real_peer = match unreal_context.read() {
                                Ok(m) => match m.unreal2real.get(&dst_port) {
                                    Some(_sock_peer) => Some(*_sock_peer),
                                    None => None,
                                },
                                Err(_) => None,
                            };
                            if let Some((src, dst)) = _real_peer {
                                let src_addr = src.ip();
                                let src_port = src.port();
                                let dst_addr = dst.ip();
                                let dst_port = dst.port();
                                tcpck
                                    .set_destination(src_port)
                                    .unwrap()
                                    .set_source(dst_port)
                                    .unwrap()
                                    .set_checksum(0)
                                    .unwrap();
                                let tcplen = tcpck.as_ref().len() as u16;
                                let ipck = ipck
                                    .set_destination(*src_addr)
                                    .unwrap()
                                    .set_source(*dst_addr)
                                    .unwrap()
                                    .set_checksum(0)
                                    .unwrap();
                                ipck.update_checksum().unwrap();
                                let mut prefix = [0u8; 12];
                                prefix[0..4].copy_from_slice(&ipck.source().octets());
                                prefix[4..8].copy_from_slice(&ipck.destination().octets());
                                prefix[9] = Protocol::Tcp.into();
                                prefix[10] = (tcplen >> 8) as u8;
                                prefix[11] = tcplen as u8;
                                let mut result = checksum(0, &prefix);
                                result = checksum(result, ipck.payload());
                                let tcp_checksum = (!result) as u16;
                                let mut tcpck =
                                    packet::tcp::Packet::new(ipck.payload_mut()).unwrap();
                                tcpck.set_checksum(tcp_checksum).unwrap();
                                return true;
                            }
                        } else {
                            let _real_peer = (
                                SocketAddrV4::new(src_addr, src_port),
                                SocketAddrV4::new(dst_addr, dst_port),
                            );
                            let unreal_src_port = if tcpck.flags() & Flags::SYN == Flags::SYN {
                                // 初始SYN请求建连
                                // 获取一个虚拟端口
                                match unreal_context.write() {
                                    Ok(mut a) => {
                                        if a.real2unreal.contains_key(&_real_peer) {
                                            None
                                        } else {
                                            Some(a.next(_real_peer))
                                        }
                                    }
                                    Err(_) => None,
                                }
                            } else {
                                match unreal_context.read() {
                                    Ok(a) => match a.real2unreal.get(&_real_peer) {
                                        Some(unreal_context) => Some(*unreal_context),
                                        None => None,
                                    },
                                    Err(_) => None,
                                }
                            };
                            match unreal_src_port {
                                Some(unreal_src_port) => {
                                    // 插入到虚拟
                                    tcpck
                                        .set_destination(kernel_src_port)
                                        .unwrap()
                                        .set_source(unreal_src_port)
                                        .unwrap()
                                        .set_checksum(0)
                                        .unwrap();
                                    let tcplen = tcpck.as_ref().len() as u16;

                                    let ipck = ipck
                                        .set_destination(ip)
                                        .unwrap()
                                        .set_checksum(0)
                                        .unwrap()
                                        .set_source(unreal_kernel_dst)
                                        .unwrap();

                                    ipck.update_checksum().unwrap();
                                    let mut prefix = [0u8; 12];
                                    prefix[0..4].copy_from_slice(&ipck.source().octets());
                                    prefix[4..8].copy_from_slice(&ipck.destination().octets());
                                    prefix[9] = Protocol::Tcp.into();
                                    prefix[10] = (tcplen >> 8) as u8;
                                    prefix[11] = tcplen as u8;
                                    let mut result = checksum(0, &prefix);
                                    result = checksum(result, ipck.payload());
                                    let tcp_checksum = (!result) as u16;
                                    let mut tcpck =
                                        packet::tcp::Packet::new(ipck.payload_mut()).unwrap();
                                    tcpck.set_checksum(tcp_checksum).unwrap();
                                    return true;
                                }
                                None => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(packet::ip::Packet::V6(_)) => {}
            _ => {}
        }
        false
    }
    // 运行tun设备
    fn server_forever(
        &mut self,
        unreal_kernel_dst: Ipv4Addr,
        kernel_src_port: u16,
        unreal_context: Arc<RwLock<UnrealContext>>,
    );
}

pub struct UnrealContext {
    unreal2real: HashMap<u16, (SocketAddrV4, SocketAddrV4)>,
    real2unreal: HashMap<(SocketAddrV4, SocketAddrV4), u16>,
    _min: u16,
    _max: u16,
    _current: u16,
}

impl UnrealContext {
    // _min<=x<_max
    fn new(_min: u16, _max: u16) -> Self {
        if _min == 0 || _max <= _min {
            panic!("Range error");
        }
        UnrealContext {
            unreal2real: HashMap::<u16, (SocketAddrV4, SocketAddrV4)>::new(),
            real2unreal: HashMap::<(SocketAddrV4, SocketAddrV4), u16>::new(),
            _min,
            _max,
            _current: _min,
        }
    }
    fn next(&mut self, peer: (SocketAddrV4, SocketAddrV4)) -> u16 {
        loop {
            if self.unreal2real.len() == (self._max - self._min) as usize {
                return 0;
            }
            self._current = self._current.wrapping_add(1);
            if self._current < self._min || self._current >= self._max {
                self._current = self._min
            }
            if self.unreal2real.contains_key(&self._current) {
                continue;
            }
            break;
        }
        self.unreal2real.insert(self._current, peer);
        self.real2unreal.insert(peer, self._current);
        log::info!("Insert: {}", self._current);
        self._current
    }
    fn release(&mut self, port: &u16) {
        log::info!("Remove: {}", port);
        let peer = self.unreal2real.remove(port);
        if let Some(peer) = peer {
            self.real2unreal.remove(&peer);
        }
    }
}

pub struct TcpAccept {
    pub src: SocketAddrV4,                // 真实源地址
    pub dst: SocketAddrV4,                // 真实目标地址
    _unreal_src_port: u16,                // 虚拟源端口
    _context: Arc<RwLock<UnrealContext>>, // context
    pub stream: TcpStream,
}

impl TcpAccept {
    fn new(
        src: SocketAddrV4,                    // 真实源地址
        dst: SocketAddrV4,                    // 真实目标地址
        _unreal_src_port: u16,                // 虚拟源端口
        _context: Arc<RwLock<UnrealContext>>, // context
        stream: TcpStream,
    ) -> Self {
        Self {
            src,
            dst,
            _unreal_src_port,
            _context,
            stream,
        }
    }
}

impl Drop for TcpAccept {
    fn drop(&mut self) {
        match self._context.write() {
            Ok(mut s) => {
                s.release(&self._unreal_src_port);
            }
            Err(_) => {}
        }
        let _ = self.stream;
    }
}

pub struct Layer3to4 {
    _listener: TcpListener,
    _unreal_context: Arc<RwLock<UnrealContext>>,
}

impl Layer3to4 {
    pub fn new<T: Layer3Device>(mut dev: T) -> Self {
        let ip = dev.ip();
        let (tx, rx) = channel::<u16>();
        let unreal_context = Arc::new(RwLock::new(UnrealContext::new(10000, 40000)));
        let unreal_contextw = unreal_context.clone();
        std::thread::spawn(move || {
            let ip = dev.ip();
            let u = ip.octets();
            let unreal_kernel_dst = Ipv4Addr::new(u[0], u[1], u[2], u[3] + 1);
            let kernel_src_port = rx.recv().unwrap();
            log::info!("Start tun.");
            dev.server_forever(unreal_kernel_dst, kernel_src_port, unreal_context);
        });
        let _listener = get_listener(ip);
        let sport = _listener.local_addr().unwrap().port();
        log::info!("Listen on: {}", sport);
        tx.send(sport).unwrap();
        Layer3to4 {
            _listener,
            _unreal_context: unreal_contextw,
        }
    }
    // 从ip包解析、接收新连接
    pub fn accept_tcp(&self) -> std::io::Result<TcpAccept> {
        match self._listener.accept() {
            Ok((conn, src)) => {
                let _unreal_src_port = src.port();
                let (src, dst) = match self._unreal_context.read() {
                    Ok(_context) => {
                        if let Some((a, b)) = _context.unreal2real.get(&src.port()) {
                            (*a, *b)
                        } else {
                            return Err(Error::new(ErrorKind::Other, "Not context"));
                        }
                    }
                    Err(e) => {
                        return Err(Error::new(ErrorKind::Other, e.to_string()));
                    }
                };
                return Ok(TcpAccept::new(
                    src,
                    dst,
                    _unreal_src_port,
                    self._unreal_context.clone(),
                    conn,
                ));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

#[inline]
fn checksum(mid: u32, buf: &[u8]) -> u32 {
    let mut i = 0usize;
    let mut result = mid;
    while i < buf.len() {
        let k = i + 1;
        if k >= buf.len() {
            result += (buf[i] as u32) << 8;
            while result > 0xffff {
                result = (result >> 16) + (result & 0xffff);
            }
            break;
        }
        result += ((buf[i] as u32) << 8) | (buf[k] as u32);
        while result > 0xffff {
            result = (result >> 16) + (result & 0xffff);
        }
        i += 2;
    }
    result
}

fn get_listener(ip: Ipv4Addr) -> TcpListener {
    loop {
        let listener = TcpListener::bind(SocketAddrV4::new(ip, 0));
        if let Ok(listener) = listener {
            return listener;
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

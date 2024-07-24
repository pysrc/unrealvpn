/// 此源码仅仅提供ip包转换为TCP/UDP的实现方式
use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    sync::{mpsc::channel, Arc, RwLock},
};

pub mod ip {
    use std::net::Ipv4Addr;

    use crate::checksum;

    pub enum Version {
        V4,
        V6,
        Others,
    }
    pub enum Protocol {
        Udp,
        Tcp,
        Others,
    }
    // 版本
    pub fn version(buf: &[u8]) -> Version {
        match buf[0] >> 4 {
            4 => Version::V4,
            6 => Version::V6,
            _ => Version::Others,
        }
    }
    pub fn protocol(buf: &[u8]) -> Protocol {
        match buf[9] {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Others,
        }
    }
    pub fn source4(buf: &[u8]) -> Ipv4Addr {
        Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])
    }
    pub fn copy_source4(buf: &[u8], dst: &mut [u8]) {
        dst[0..4].copy_from_slice(&buf[12..16]);
    }
    pub fn destination4(buf: &[u8]) -> Ipv4Addr {
        Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
    }
    pub fn copy_destination4(buf: &[u8], dst: &mut [u8]) {
        dst[0..4].copy_from_slice(&buf[16..20]);
    }
    pub fn header(buf: &[u8]) -> u8 {
        buf[0] & 0b1111
    }
    pub fn header_len(buf: &[u8]) -> usize {
        (header(&buf) as usize) << 2
    }
    pub fn payload(buf: &[u8]) -> &[u8] {
        let header_size = header_len(&buf);
        &buf[header_size..]
    }
    pub fn payload_mut(buf: &mut [u8]) -> &mut [u8] {
        let header_size = header_len(&buf);
        &mut buf[header_size..]
    }
    pub fn set_source4(buf: &mut [u8], value: Ipv4Addr) {
        buf[12..16].copy_from_slice(&value.octets());
    }
    pub fn set_destination4(buf: &mut [u8], value: Ipv4Addr) {
        buf[16..20].copy_from_slice(&value.octets());
    }
    pub fn get_checksum(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[10], buf[11]])
    }
    pub fn set_checksum(buf: &mut [u8], value: u16) {
        buf[10..12].copy_from_slice(&value.to_be_bytes());
    }
    pub fn update_checksum(buf: &mut [u8]) {
        let siz = header_len(&buf);
        set_checksum(buf, 0);
        let value = checksum(0, &buf[..siz]);
        set_checksum(buf, (!value) as u16);
    }
}

pub mod udp {
    pub fn source(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[0], buf[1]])
    }
    pub fn destination(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[2], buf[3]])
    }
    pub fn set_source(buf: &mut [u8], value: u16) {
        buf[..2].copy_from_slice(&value.to_be_bytes());
    }
    pub fn set_destination(buf: &mut [u8], value: u16) {
        buf[2..4].copy_from_slice(&value.to_be_bytes());
    }
    pub fn set_checksum(buf: &mut [u8], value: u16) {
        buf[6..8].copy_from_slice(&value.to_be_bytes());
    }
}

pub mod tcp {
    pub fn source(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[0], buf[1]])
    }
    pub fn destination(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[2], buf[3]])
    }
    pub fn set_source(buf: &mut [u8], value: u16) {
        buf[..2].copy_from_slice(&value.to_be_bytes());
    }
    pub fn set_destination(buf: &mut [u8], value: u16) {
        buf[2..4].copy_from_slice(&value.to_be_bytes());
    }
    pub fn set_checksum(buf: &mut [u8], value: u16) {
        buf[16..18].copy_from_slice(&value.to_be_bytes());
    }
}

pub trait Layer3Device: Send + 'static {
    // 设备ip
    fn ip(&self) -> Ipv4Addr;
    // 处理读取到的包
    fn handle_packet(
        &mut self,
        buffer: &mut [u8],
        unreal_kernel_dst: Ipv4Addr,
        tcp_kernel_src_port: u16,
        tcp_unreal_context: Arc<RwLock<UnrealContext>>,
        udp_kernel_src_port: u16,
        udp_unreal_context: Arc<RwLock<UnrealContext>>,
    ) -> bool {
        let ip = self.ip();
        match ip::version(&buffer) {
            ip::Version::V4 => {
                match ip::protocol(&buffer) {
                    ip::Protocol::Udp => {
                        let src_addr = ip::source4(&buffer);
                        let dst_addr = ip::destination4(&buffer);
                        // 拒绝组播、多播udp，仅支持单播
                        if (dst_addr.octets()[0] >= 224 && dst_addr.octets()[0] <= 239)
                            || dst_addr.octets()[3] == 255
                        {
                            return false;
                        }
                        let payload = ip::payload(&buffer);
                        let src_port = udp::source(&payload);
                        let dst_port = udp::destination(&payload);
                        if dst_addr == unreal_kernel_dst && src_addr == ip {
                            // 发送回内部的包
                            let _real_peer = match udp_unreal_context.read() {
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
                                {
                                    let buffer_mut = buffer.as_mut();
                                    let mut payload_mut = ip::payload_mut(buffer_mut);
                                    udp::set_destination(&mut payload_mut, src_port);
                                    udp::set_source(&mut payload_mut, dst_port);
                                    udp::set_checksum(&mut payload_mut, 0);
                                }
                                {
                                    let mut buffer_mut = buffer.as_mut();
                                    ip::set_source4(&mut buffer_mut, *dst_addr);
                                    ip::set_destination4(&mut buffer_mut, *src_addr);
                                    ip::update_checksum(&mut buffer_mut);
                                }
                                let mut prefix = [0u8; 12];
                                ip::copy_source4(&buffer, &mut prefix[0..4]);
                                ip::copy_destination4(&buffer, &mut prefix[4..8]);
                                prefix[9] = 17;
                                let payload = ip::payload(&buffer);
                                let payloadlen = payload.len();
                                prefix[10] = (payloadlen >> 8) as u8;
                                prefix[11] = payloadlen as u8;
                                let mut result = checksum(0, &prefix);
                                result = checksum(result, payload);
                                let payload_checksum = (!result) as u16;
                                let buffer_mut = buffer.as_mut();
                                let payload_mut = ip::payload_mut(buffer_mut);
                                udp::set_checksum(payload_mut, payload_checksum);
                                return true;
                            }
                        } else {
                            // 发送到外网的地址，转换成内部监听
                            let _real_peer = (
                                SocketAddrV4::new(src_addr, src_port),
                                SocketAddrV4::new(dst_addr, dst_port),
                            );
                            // 是否已经初始化
                            let unreal_src_port = match udp_unreal_context.write() {
                                Ok(mut a) => {
                                    if a.real2unreal.contains_key(&_real_peer) {
                                        match a.real2unreal.get(&_real_peer) {
                                            Some(unreal_context) => Some(*unreal_context),
                                            None => None,
                                        }
                                    } else {
                                        Some(a.next(_real_peer))
                                    }
                                }
                                Err(_) => None,
                            };
                            match unreal_src_port {
                                Some(unreal_src_port) => {
                                    // 插入到虚拟
                                    {
                                        let buffer_mut = buffer.as_mut();
                                        let mut payload_mut = ip::payload_mut(buffer_mut);
                                        udp::set_destination(&mut payload_mut, udp_kernel_src_port);
                                        udp::set_source(&mut payload_mut, unreal_src_port);
                                        udp::set_checksum(&mut payload_mut, 0);
                                    }
                                    {
                                        let mut buffer_mut = buffer.as_mut();
                                        ip::set_source4(&mut buffer_mut, unreal_kernel_dst);
                                        ip::set_destination4(&mut buffer_mut, ip);
                                        ip::update_checksum(&mut buffer_mut);
                                    }
                                    let mut prefix = [0u8; 12];
                                    ip::copy_source4(&buffer, &mut prefix[0..4]);
                                    ip::copy_destination4(&buffer, &mut prefix[4..8]);
                                    prefix[9] = 17;
                                    let payload = ip::payload(&buffer);
                                    let payloadlen = payload.len();
                                    prefix[10] = (payloadlen >> 8) as u8;
                                    prefix[11] = payloadlen as u8;
                                    let mut result = checksum(0, &prefix);
                                    result = checksum(result, payload);
                                    let payload_checksum = (!result) as u16;
                                    let buffer_mut = buffer.as_mut();
                                    let payload_mut = ip::payload_mut(buffer_mut);
                                    udp::set_checksum(payload_mut, payload_checksum);
                                    return true;
                                }
                                None => {}
                            }
                        }
                    }
                    ip::Protocol::Tcp => {
                        let src_addr = ip::source4(&buffer);
                        let dst_addr = ip::destination4(&buffer);
                        let payload = ip::payload(&buffer);
                        let src_port: u16 = tcp::source(&payload);
                        let dst_port = tcp::destination(&payload);
                        if dst_addr == unreal_kernel_dst && src_addr == ip {
                            // 发送回内部的包
                            let _real_peer = match tcp_unreal_context.read() {
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
                                {
                                    let buffer_mut = buffer.as_mut();
                                    let mut payload_mut = ip::payload_mut(buffer_mut);
                                    tcp::set_destination(&mut payload_mut, src_port);
                                    tcp::set_source(&mut payload_mut, dst_port);
                                    tcp::set_checksum(&mut payload_mut, 0);
                                }
                                {
                                    let mut buffer_mut = buffer.as_mut();
                                    ip::set_source4(&mut buffer_mut, *dst_addr);
                                    ip::set_destination4(&mut buffer_mut, *src_addr);
                                    ip::update_checksum(&mut buffer_mut);
                                }
                                let mut prefix = [0u8; 12];
                                ip::copy_source4(&buffer, &mut prefix[0..4]);
                                ip::copy_destination4(&buffer, &mut prefix[4..8]);
                                prefix[9] = 6;
                                let payload = ip::payload(&buffer);
                                let payloadlen = payload.len();
                                prefix[10] = (payloadlen >> 8) as u8;
                                prefix[11] = payloadlen as u8;
                                let mut result = checksum(0, &prefix);
                                result = checksum(result, payload);
                                let payload_checksum = (!result) as u16;
                                let buffer_mut = buffer.as_mut();
                                let payload_mut = ip::payload_mut(buffer_mut);
                                tcp::set_checksum(payload_mut, payload_checksum);
                                return true;
                            }
                        } else {
                            // 发送到外网的地址，转换成内部监听
                            let _real_peer = (
                                SocketAddrV4::new(src_addr, src_port),
                                SocketAddrV4::new(dst_addr, dst_port),
                            );
                            // 是否已经初始化
                            let unreal_src_port = match tcp_unreal_context.write() {
                                Ok(mut a) => {
                                    if a.real2unreal.contains_key(&_real_peer) {
                                        match a.real2unreal.get(&_real_peer) {
                                            Some(unreal_context) => Some(*unreal_context),
                                            None => None,
                                        }
                                    } else {
                                        Some(a.next(_real_peer))
                                    }
                                }
                                Err(_) => None,
                            };
                            match unreal_src_port {
                                Some(unreal_src_port) => {
                                    // 插入到虚拟
                                    {
                                        let buffer_mut = buffer.as_mut();
                                        let mut payload_mut = ip::payload_mut(buffer_mut);
                                        tcp::set_destination(&mut payload_mut, tcp_kernel_src_port);
                                        tcp::set_source(&mut payload_mut, unreal_src_port);
                                        tcp::set_checksum(&mut payload_mut, 0);
                                    }
                                    {
                                        let mut buffer_mut = buffer.as_mut();
                                        ip::set_source4(&mut buffer_mut, unreal_kernel_dst);
                                        ip::set_destination4(&mut buffer_mut, ip);
                                        ip::update_checksum(&mut buffer_mut);
                                    }
                                    let mut prefix = [0u8; 12];
                                    ip::copy_source4(&buffer, &mut prefix[0..4]);
                                    ip::copy_destination4(&buffer, &mut prefix[4..8]);
                                    prefix[9] = 6;
                                    let payload = ip::payload(&buffer);
                                    let payloadlen = payload.len();
                                    prefix[10] = (payloadlen >> 8) as u8;
                                    prefix[11] = payloadlen as u8;
                                    let mut result = checksum(0, &prefix);
                                    result = checksum(result, payload);
                                    let payload_checksum = (!result) as u16;
                                    let buffer_mut = buffer.as_mut();
                                    let payload_mut = ip::payload_mut(buffer_mut);
                                    tcp::set_checksum(payload_mut, payload_checksum);
                                    return true;
                                }
                                None => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        false
    }
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buffer: &[u8]) -> io::Result<()>;
    // 从tun设备收发数据包
    fn server_forever(
        &mut self,
        unreal_kernel_dst: Ipv4Addr,
        tcp_kernel_src_port: u16,
        tcp_unreal_context: Arc<RwLock<UnrealContext>>,
        udp_kernel_src_port: u16,
        udp_unreal_context: Arc<RwLock<UnrealContext>>,
    ) {
        let mut buffer = vec![0u8; 4096];
        loop {
            // 收到ip包数据
            let _len = match self.read(&mut buffer) {
                Ok(_len) => _len,
                Err(e) => {
                    log::error!("Tun dev read err: {}", e);
                    return;
                }
            };
            if _len == 0 {
                continue;
            }
            // 处理包
            let success = self.handle_packet(
                &mut buffer[.._len],
                unreal_kernel_dst,
                tcp_kernel_src_port,
                tcp_unreal_context.clone(),
                udp_kernel_src_port,
                udp_unreal_context.clone(),
            );
            // 发送包
            if success {
                self.write(&buffer[.._len]).unwrap();
            }
        }
    }
}

pub struct UnrealContext {
    unreal2real: HashMap<u16, (SocketAddrV4, SocketAddrV4)>,
    real2unreal: HashMap<(SocketAddrV4, SocketAddrV4), u16>,
    unreal_ip: Ipv4Addr,
    _min: u16,
    _max: u16,
    _current: u16,
}

impl UnrealContext {
    // _min<=x<_max
    fn new(_min: u16, _max: u16, unreal_ip: Ipv4Addr) -> Self {
        if _min == 0 || _max <= _min {
            panic!("Range error");
        }
        UnrealContext {
            unreal2real: HashMap::<u16, (SocketAddrV4, SocketAddrV4)>::new(),
            real2unreal: HashMap::<(SocketAddrV4, SocketAddrV4), u16>::new(),
            unreal_ip,
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

pub struct TcpWorker {
    _listener: TcpListener,
    _unreal_context: Arc<RwLock<UnrealContext>>,
}

impl TcpWorker {
    // 从ip包解析、接收新连接
    pub fn accept(&self) -> std::io::Result<TcpAccept> {
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

pub struct UdpWorker {
    _listener: UdpSocket,
    _unreal_context: Arc<RwLock<UnrealContext>>,
}

impl UdpWorker {
    // 收包
    pub fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(SocketAddrV4, SocketAddrV4, usize)> {
        loop {
            match self._listener.recv_from(buf) {
                Ok((size, src)) => {
                    match self._unreal_context.read() {
                        Ok(_context) => {
                            if let Some((a, b)) = _context.unreal2real.get(&src.port()) {
                                return Ok((*a, *b, size));
                            } else {
                                return Err(Error::new(ErrorKind::Other, "Not context"));
                            }
                        }
                        Err(e) => {
                            return Err(Error::new(ErrorKind::Other, e.to_string()));
                        }
                    };
                }
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }
        }
    }
    // 返包
    pub fn send_back(&self, buf: &[u8], src: SocketAddrV4, dst: SocketAddrV4) -> io::Result<usize> {
        match self._unreal_context.read() {
            Ok(_context) => {
                if let Some(port) = _context.real2unreal.get(&(src, dst)) {
                    return self
                        ._listener
                        .send_to(buf, SocketAddrV4::new(_context.unreal_ip, *port));
                } else {
                    return Err(Error::new(ErrorKind::Other, "Not context"));
                }
            }
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));
            }
        };
    }

    pub fn clone(&self) -> UdpWorker {
        UdpWorker {
            _listener: self._listener.try_clone().unwrap(),
            _unreal_context: self._unreal_context.clone(),
        }
    }
}

pub fn dev_run<T: Layer3Device>(mut dev: T) -> (TcpWorker, UdpWorker) {
    let ip = dev.ip();
    let u = ip.octets();
    let unreal_kernel_dst = Ipv4Addr::new(u[0], u[1], u[2], u[3] + 1);
    let (tx, rx) = channel::<u16>();
    let (utx, urx) = channel::<u16>();
    let tcp_unreal_context = Arc::new(RwLock::new(UnrealContext::new(
        10000,
        40000,
        unreal_kernel_dst,
    )));
    let tcp_unreal_contextw = tcp_unreal_context.clone();
    let udp_unreal_context = Arc::new(RwLock::new(UnrealContext::new(
        10000,
        40000,
        unreal_kernel_dst,
    )));
    let udp_unreal_contextw = udp_unreal_context.clone();
    std::thread::spawn(move || {
        let tcp_kernel_src_port = rx.recv().unwrap();
        let udp_kernel_src_port = urx.recv().unwrap();
        log::info!("Start tun.");
        dev.server_forever(
            unreal_kernel_dst,
            tcp_kernel_src_port,
            tcp_unreal_context,
            udp_kernel_src_port,
            udp_unreal_context,
        );
    });
    // tcp部分
    let _tcp_listener = get_tcp_listener(ip);
    let sport = _tcp_listener.local_addr().unwrap().port();
    log::info!("Tcp listen on: {}", sport);
    tx.send(sport).unwrap();
    // udp部分
    let _udp_listener = get_udp_listener(ip);
    let sport = _udp_listener.local_addr().unwrap().port();
    log::info!("Udp listen on: {}", sport);
    utx.send(sport).unwrap();
    (
        TcpWorker {
            _listener: _tcp_listener,
            _unreal_context: tcp_unreal_contextw,
        },
        UdpWorker {
            _listener: _udp_listener,
            _unreal_context: udp_unreal_contextw,
        },
    )
}

#[inline]
fn checksum(mut sum: u32, buffer: &[u8]) -> u32 {
    // Sum all 16-bit words
    for i in (0..buffer.len()).step_by(2) {
        let word = if i + 1 < buffer.len() {
            ((buffer[i] as u32) << 8) + (buffer[i + 1] as u32)
        } else {
            (buffer[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    // Add carry bits to the sum
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

fn get_tcp_listener(ip: Ipv4Addr) -> TcpListener {
    loop {
        let listener = TcpListener::bind(SocketAddrV4::new(ip, 0));
        if let Ok(listener) = listener {
            return listener;
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

fn get_udp_listener(ip: Ipv4Addr) -> UdpSocket {
    loop {
        let listener = UdpSocket::bind(SocketAddrV4::new(ip, 0));
        if let Ok(listener) = listener {
            return listener;
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

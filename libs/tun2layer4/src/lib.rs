pub use layer3to4::EN_TCP;
pub use layer3to4::EN_UDP;
pub use layer3to4::UdpWorker;
pub use layer3to4::TcpWorker;

fn binmatch(n: u8) -> Option<u8> {
    match n {
        0b0000_0000 => Some(0),
        0b1000_0000 => Some(1),
        0b1100_0000 => Some(2),
        0b1110_0000 => Some(3),
        0b1111_0000 => Some(4),
        0b1111_1000 => Some(5),
        0b1111_1100 => Some(6),
        0b1111_1110 => Some(7),
        0b1111_1111 => Some(8),
        _ => None,
    }
}

// 255.255.252.0 -> 22
fn mask2prefix(mask: &str) -> u8 {
    let sp: Vec<&str> = mask.split(".").collect();
    let a: u8 = sp[0].parse().unwrap();
    let b: u8 = sp[1].parse().unwrap();
    let c: u8 = sp[2].parse().unwrap();
    let d: u8 = sp[3].parse().unwrap();
    let mut res = 0;
    if let Some(k) = binmatch(a) {
        res += k;
    }
    if let Some(k) = binmatch(b) {
        res += k;
    }
    if let Some(k) = binmatch(c) {
        res += k;
    }
    if let Some(k) = binmatch(d) {
        res += k;
    }
    res
}

fn route_with_mask(route: String) -> String {
    let mut route = route;
    if !route.contains("/") {
        route = route + "/32";
    }
    let rm: Vec<&str> = route.split("/").collect();
    let mask = rm[1];
    if mask.contains(".") {
        // eg. 255.255.0.0
        let prefix = mask2prefix(mask);
        route = format!("{}/{}", rm[0], prefix);
    }
    return route;
}

#[cfg(target_os = "windows")]
pub mod os_tun {
    use layer3to4::{dev_run, Layer3Device, TcpWorker, UdpWorker};
    use std::{net::Ipv4Addr, sync::Arc};

    struct TransPacket {
        ipacket: wintun::Packet
    }
    impl TransPacket {
        fn new(ipacket: wintun::Packet) -> Self {
            TransPacket {
                ipacket
            }
        }
    }
    impl layer3to4::IPacket for TransPacket {
        fn bytes_mut(&mut self) -> &mut [u8] {
            self.ipacket.bytes_mut()
        }

        fn bytes(&self) -> &[u8] {
            self.ipacket.bytes()
        }
    }

    pub fn new(tun_name: String, opt: u8, ip: Ipv4Addr, mask: u8, routes: Option<Vec<String>>) -> (Option<TcpWorker>, Option<UdpWorker>) {
        let dev = TunDevice::new(tun_name, ip, mask, routes);
        dev_run(dev, opt)
    }

    pub struct TunDevice {
        ip: Ipv4Addr,
        session: Arc<wintun::Session>,
    }

    impl TunDevice {
        pub fn new(tun_name: String, ip: Ipv4Addr, mask: u8, routes: Option<Vec<String>>) -> Self {
            // 加载wintun
            let wintun =
                unsafe { wintun::load_from_path("wintun.dll") }.expect("Failed to load wintun dll");
            // 打开或创建一个虚拟网卡装置
            let adapter = match wintun::Adapter::open(&wintun, &tun_name) {
                Ok(a) => a,
                Err(_) => wintun::Adapter::create(&wintun, &tun_name, &tun_name, None)
                    .expect("Failed to create wintun adapter!"),
            };

            // 设置虚拟网卡信息
            let [a, b, c, d] = ip.octets();
            let index = adapter.get_adapter_index().unwrap();
            let set_metric = format!("netsh interface ip set interface {} metric=255", index);
            let set_gateway = format!(
                "netsh interface ip set address {} static {}.{}.{}.{}/{}",
                index, a, b, c, d, mask
            );
            // 打印输出
            log::info!("{}", set_metric);
            log::info!("{}", set_gateway);

            // 执行网卡初始化命令
            std::process::Command::new("cmd")
                .arg("/C")
                .arg(set_metric)
                .output()
                .unwrap();
            std::process::Command::new("cmd")
                .arg("/C")
                .arg(set_gateway)
                .output()
                .unwrap();

            // 设置其他路由
            if let Some(routes) = routes {
                for mut route in routes {
                    route = crate::route_with_mask(route);
                    let set_route = format!("netsh interface ip add route {} {}", route, index);
                    log::info!("{}", set_route);
                    std::process::Command::new("cmd")
                        .arg("/C")
                        .arg(set_route)
                        .output()
                        .unwrap();
                }
            }

            // 开启tun会话
            let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
            TunDevice { ip, session }
        }
    }

    impl Layer3Device for TunDevice {
        fn ip(&self) -> Ipv4Addr {
            self.ip.clone()
        }
        
        fn read(&mut self) -> Box<dyn layer3to4::IPacket> {
            loop {
                let pkt = match self.session.receive_blocking() {
                    Ok(pkt) => pkt,
                    Err(_) => {
                        continue;
                    }
                };
                return Box::new(TransPacket::new(pkt));
            }
        }
        
        fn write(&mut self, data: Box<dyn layer3to4::IPacket>) {
            let buffer = data.bytes();
            let mut write_pack = self
                .session
                .allocate_send_packet(buffer.len() as u16)
                .unwrap();
            let resp_pack = write_pack.bytes_mut();
            resp_pack.copy_from_slice(buffer);
            self.session.send_packet(write_pack);
        }
    }
}

#[cfg(target_os = "linux")]
pub mod os_tun {
    use layer3to4::{dev_run, Layer3Device, TcpWorker, UdpWorker};
    use std::{
        io::{Read, Write},
        net::Ipv4Addr,
    };
    use tun::platform::Device;

    struct TransPacket {
        ipacket: &'static mut [u8]
    }
    impl TransPacket {
        fn new(data: &'static mut [u8]) -> Self {
            TransPacket {
                ipacket: data
            }
        }
    }
    impl layer3to4::IPacket for TransPacket {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.ipacket
        }

        fn bytes(&self) -> &[u8] {
            &self.ipacket
        }
    }

    static mut BUFFER: Vec<u8> = Vec::new();

    fn nmatch(n: u8) -> Option<u8> {
        match n {
            0 => Some(0),
            1 => Some(0b1000_0000),
            2 => Some(0b1100_0000),
            3 => Some(0b1110_0000),
            4 => Some(0b1111_0000),
            5 => Some(0b1111_1000),
            6 => Some(0b1111_1100),
            7 => Some(0b1111_1110),
            8 => Some(0b1111_1111),
            _ => None,
        }
    }

    // 24 -> [255, 255, 255, 0]
    fn prefix_len_to_netmask(prefix: u8) -> [u8; 4] {
        let mut mask = [0u8, 0u8, 0u8, 0u8];
        let mut p = prefix;
        for i in 0..4 {
            if p >= 8 {
                mask[i] = 255;
                p -= 8;
            } else {
                match nmatch(p) {
                    Some(n) => mask[i] = n,
                    None => panic!("Error netmask prefix: {}", prefix),
                }
                break;
            }
        }
        return mask;
    }

    pub fn new(tun_name: String, opt: u8, ip: Ipv4Addr, mask: u8, routes: Option<Vec<String>>) -> (Option<TcpWorker>, Option<UdpWorker>) {
        let dev = TunDevice::new(tun_name, ip, mask, routes);
        dev_run(dev, opt)
    }

    pub struct TunDevice {
        ip: Ipv4Addr,
        dev: Device,
    }

    impl TunDevice {
        pub fn new(tun_name: String, ip: Ipv4Addr, mask: u8, routes: Option<Vec<String>>) -> Self {
            // 设置虚拟网卡信息
            let [a, b, c, d] = ip.octets();
            let mut config = tun::Configuration::default();
            let mask2 = prefix_len_to_netmask(mask);

            config
                .name(&tun_name)
                .address((a, b, c, d))
                .netmask((mask2[0], mask2[1], mask2[2], mask2[3]))
                .up();

            #[cfg(target_os = "linux")]
            config.platform(|config| {
                config.packet_information(false);
            });

            let dev = tun::create(&config).unwrap();

            // 设置其他路由
            if let Some(routes) = routes {
                for mut route in routes {
                    route = crate::route_with_mask(route);
                    let set_route = format!("ip route add {} dev {}", route, tun_name);
                    log::info!("{}", set_route);
                    std::process::Command::new("sh")
                        .arg("-c")
                        .arg(set_route)
                        .output()
                        .unwrap();
                }
            }
            unsafe {
                BUFFER.resize(4096, 0);
            }
            TunDevice { ip, dev}
        }
    }

    impl Layer3Device for TunDevice {
        fn ip(&self) -> Ipv4Addr {
            self.ip
        }

        // 读数据包
        fn read(&mut self) -> Box<dyn layer3to4::IPacket> {
            unsafe {
                loop {
                    // 收到ip包数据
                    BUFFER.set_len(BUFFER.capacity());
                    #[allow(static_mut_refs)]
                    let _len = match self.dev.read(&mut BUFFER) {
                        Ok(_len) => _len,
                        Err(e) => {
                            panic!("panic {}", e);
                        }
                    };
                    if _len == 0 {
                        continue;
                    }
                    BUFFER.set_len(_len);
                    #[allow(static_mut_refs)]
                    return Box::new(TransPacket::new(&mut BUFFER));
                }
            }
        }
        // 写数据包
        fn write(&mut self, data: Box<dyn layer3to4::IPacket>) {
            let buffer = data.bytes();
            self.dev.write_all(&buffer[..]).unwrap();
        }
    }
}
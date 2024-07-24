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

pub mod os_tun {
    use layer3to4::{dev_run, Layer3Device, TcpWorker, UdpWorker};
    use std::{
        io::{Read, Write}, net::Ipv4Addr
    };
    use tun::platform::Device;

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

    pub fn new(
        tun_name: String,
        ip: Ipv4Addr,
        mask: u8,
        routes: Option<Vec<String>>,
    ) -> (TcpWorker, UdpWorker) {
        let dev = TunDevice::new(tun_name, ip, mask, routes);
        dev_run(dev)
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

            let mut dev = tun::create(&config).unwrap();

            // 设置其他路由
            #[cfg(target_os = "linux")]
            {
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
            }
            #[cfg(target_os = "windows")]
            {
                use tun::Device;
                let index = dev.queue(0).unwrap().get_adapter_index().unwrap();
                // 获取index
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
            }
            TunDevice { ip, dev }
        }
    }

    impl Layer3Device for TunDevice {
        fn ip(&self) -> Ipv4Addr {
            self.ip
        }

        fn server_forever(
            &mut self,
            unreal_kernel_dst: Ipv4Addr,
            tcp_kernel_src_port: u16,
            tcp_unreal_context: std::sync::Arc<std::sync::RwLock<layer3to4::UnrealContext>>,
            udp_kernel_src_port: u16,
            udp_unreal_context: std::sync::Arc<std::sync::RwLock<layer3to4::UnrealContext>>,
        ) {
            let mut buffer = vec![0u8; 4096];
            loop {
                // 收到ip包数据
                let _len = match self.dev.read(&mut buffer) {
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
                    self.dev.write_all(&buffer[.._len]).unwrap();
                }
            }
        }
    }
}

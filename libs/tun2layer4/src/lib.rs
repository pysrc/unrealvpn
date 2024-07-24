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

// 24 -> [255, 255, 255, 0]
fn prefix_len_to_netmask(prefix: u8) -> [u8; 4] {
    let mut u64max = u64::MAX;
    u64max = u64max.wrapping_shl(32 - prefix as u32);
    (u64max as u32).to_be_bytes()
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
        io::{self, Read, Write},
        net::Ipv4Addr,
    };
    use tun::platform::Device;

    use crate::prefix_len_to_netmask;

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

        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            // 收到ip包数据
            self.dev.read(buffer)
        }

        fn write(&mut self, buffer: &[u8]) -> io::Result<()> {
            self.dev.write_all(buffer)
        }
    }
}

use std::{net::{Ipv4Addr, SocketAddrV4}, sync::{atomic::{AtomicBool, Ordering}, Arc}};

use tokio::{io::{split, AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{rustls::ServerName, TlsConnector};



const CMD_UDP: u8 = 1;

pub async fn worker(server: String, connector: TlsConnector, domain: ServerName, udp_worker: tun2layer4::UdpWorker) -> tun2layer4::UdpWorker {
    // udp
    let udp_ctrl_conn = match TcpStream::connect(server.clone()).await {
        Ok(_conn) => _conn,
        Err(_) => {
            return udp_worker;
        }
    };
    let mut udp_ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> = match connector.connect(domain.clone(), udp_ctrl_conn).await {
        Ok(_conn) => _conn,
        Err(_) => {
            return udp_worker;
        }
    };
    if let Err(_) = udp_ctrl_conn.write_u8(CMD_UDP).await {
        return udp_worker;
    }
    log::info!("Connection established.");
    let (mut r, mut w) = split(udp_ctrl_conn);
    let udp_worker2 = udp_worker.clone();
    let runing = Arc::new(AtomicBool::new(true));
    let runingr = runing.clone();
    tokio::spawn(async move {
        let mut key = [0u8; 12];
        let mut buf = vec![0u8; 2048];
        while runingr.load(Ordering::Relaxed) {
            if let Err(_) = r.read_exact(&mut key).await {
                runingr.store(false, Ordering::Relaxed);
                break;
            }
            let src = SocketAddrV4::new(
                Ipv4Addr::new(key[0], key[1], key[2], key[3]),
                u16::from_be_bytes([key[4], key[5]]),
            );
            let dst = SocketAddrV4::new(
                Ipv4Addr::new(key[6], key[7], key[8], key[9]),
                u16::from_be_bytes([key[10], key[11]]),
            );
            let _len = match r.read_u16().await {
                Ok(n) => n as usize,
                Err(_) => {
                    runingr.store(false, Ordering::Relaxed);
                    break;
                }
            };
            if let Err(_) = r.read_exact(&mut buf[.._len]).await {
                runingr.store(false, Ordering::Relaxed);
                break;
            }
            if let Err(_) = udp_worker2.send_back(&buf[.._len], src, dst) {
                runingr.store(false, Ordering::Relaxed);
                break;
            }
        }
    });
    let mut key = [0u8; 12];
    let mut buf = vec![0u8; 2048];
    // 阻塞操作提出去
    while runing.load(Ordering::Relaxed) {
        if let Ok((src, dst, size)) = udp_worker.recv_from(&mut buf) {
            key[..4].copy_from_slice(&src.ip().octets());
            key[4..6].copy_from_slice(&src.port().to_be_bytes());
            key[6..10].copy_from_slice(&dst.ip().octets());
            key[10..12].copy_from_slice(&dst.port().to_be_bytes());
            if let Err(_) = w.write_all(&key).await {
                return udp_worker;
            }
            if let Err(_) = w.write_u16(size as u16).await {
                return udp_worker;
            }
            if let Err(_) = w.write_all(&buf[..size]).await {
                return udp_worker;
            }
            if let Err(_) = w.flush().await {
                return udp_worker;
            }
        } else {
            return udp_worker;
        }
    }
    return udp_worker;
}
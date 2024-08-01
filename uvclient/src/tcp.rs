use std::{
    num::NonZeroU64,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{rustls::ServerName, TlsConnector};

const CMD_TCP: u8 = 2;

pub async fn worker(
    server: String,
    connector: TlsConnector,
    domain: ServerName,
    tcp_worker: tun2layer4::TcpWorker,
) -> tun2layer4::TcpWorker {
    let ctrl_conn = match TcpStream::connect(server.clone()).await {
        Ok(_conn) => _conn,
        Err(_) => {
            return tcp_worker;
        }
    };
    let mut ctrl_conn: tokio_rustls::client::TlsStream<TcpStream> =
        match connector.connect(domain.clone(), ctrl_conn).await {
            Ok(_conn) => _conn,
            Err(_) => {
                return tcp_worker;
            }
        };
    if let Err(_) = ctrl_conn.write_u8(CMD_TCP).await {
        return tcp_worker;
    }
    log::info!("Connection established.");
    let (mux_connector, _, mux_worker) = async_smux::MuxBuilder::client()
        .with_keep_alive_interval(NonZeroU64::new(30).unwrap())
        .with_connection(ctrl_conn)
        .build();
    tokio::spawn(mux_worker);
    let runing = Arc::new(AtomicBool::new(true));
    while runing.load(Ordering::Relaxed) {
        // 面向于inside端
        if let Ok(tcp_accept) = tcp_worker.accept() {
            log::info!("dst: {}", tcp_accept.dst);
            let mut _mux_stream = match mux_connector.connect() {
                Ok(cc) => cc,
                Err(e) => {
                    log::info!("{}->{}", line!(), e);
                    return tcp_worker;
                }
            };

            let runingr = runing.clone();
            tokio::spawn(async move {
                let conn = match tcp_accept.stream.try_clone() {
                    Ok(_conn) => _conn,
                    Err(_) => {
                        runingr.store(false, Ordering::Relaxed);
                        return;
                    }
                };
                if let Err(_) = conn.set_nonblocking(true) {
                    runingr.store(false, Ordering::Relaxed);
                    return;
                }
                let mut src_stream = match tokio::net::TcpStream::from_std(conn) {
                    Ok(_conn) => _conn,
                    Err(_) => {
                        runingr.store(false, Ordering::Relaxed);
                        return;
                    }
                };
                let target = format!(
                    "{}:{}",
                    tcp_accept.dst.ip().to_string(),
                    tcp_accept.dst.port()
                );
                if let Err(_) = _mux_stream.write_u16(target.len() as u16).await {
                    runingr.store(false, Ordering::Relaxed);
                    return;
                }
                if let Err(_) = _mux_stream.write_all(target.as_bytes()).await {
                    runingr.store(false, Ordering::Relaxed);
                    return;
                }
                if let Err(_) = _mux_stream.flush().await {
                    runingr.store(false, Ordering::Relaxed);
                    return;
                }
                _ = tokio::io::copy_bidirectional(&mut _mux_stream, &mut src_stream).await;
                _ = _mux_stream.shutdown().await;
            });
        } else {
            return tcp_worker;
        }
    }
    return tcp_worker;
}

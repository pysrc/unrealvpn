use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
    sync::{mpsc, Mutex},
};
use tokio_rustls::TlsStream;

pub async fn start_mux(ctrl_conn: TlsStream<TcpStream>) {
    let (mut _ctrl_recv, mut _ctrl_send) = split(ctrl_conn);

    // 主连接channel
    let (mtx, mut mrx) = mpsc::unbounded_channel::<Vec<u8>>();
    // 发送channel
    let mut _channel_map = Arc::new(Mutex::new(HashMap::<[u8; 8], mpsc::Sender<Vec<u8>>>::new()));
    // 全局数组池
    let _global_vec_pool = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));

    let _global_vec_poolc = _global_vec_pool.clone();
    loop {
        select! {
            // 发数据
            _wait_send = mrx.recv() => {

                match _wait_send {
                    Some(data) => {

                        if let Err(e) = _ctrl_send.write_all(&data).await {

                            {
                                let mut _gvp = _global_vec_poolc.lock().await;
                                _gvp.push_back(data);
                            }
                            _ = _ctrl_send.shutdown().await;
                            log::error!("{}->{}", line!(), e);
                            return;
                        } else {

                            let mut _gvp = _global_vec_poolc.lock().await;
                            _gvp.push_back(data);
                        }

                    }
                    None => {
                        log::error!("{}->mrx close", line!());
                    }
                }
            }
            cmd = _ctrl_recv.read_u8() => match cmd {
                Ok(cmd) => {
                    match cmd {
                        0b1000_0100 => {

                            // tcp packet outside
                            // 正常转发tcp包
                            let mut _meta_buffer = [0u8;8];
                            if let Err(e) = _ctrl_recv.read_exact(&mut _meta_buffer).await {
                                log::error!("{}->{}", line!(), e);
                                return;
                            }

                            let _data_len = _ctrl_recv.read_u16().await.unwrap() as usize;

                            // 数据包数组
                            let mut _buffer = {
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
                                _buffer.set_len(_data_len);
                            }
                            if let Err(e) = _ctrl_recv.read_exact(&mut _buffer).await {
                                log::error!("{}->{}", line!(), e);
                                return;
                            }

                            let mut _channel_mapw = _channel_map.lock().await;

                            match _channel_mapw.get_mut(&_meta_buffer) {
                                Some(s)=>{

                                    if let Err(e) = s.send(_buffer).await {

                                        _channel_mapw.remove(&_meta_buffer);
                                        log::error!("{}->{}", line!(), e);
                                        return;
                                    }
                                }
                                None => {
                                    log::info!("i->{} {:?}", line!(), _meta_buffer);
                                }
                            }

                        }
                        0b1100_0100 => {
                            // tcp open outside
                            // 开始新连接
                            log::info!("{}-> open outside", line!());
                            let _channel_mapc = _channel_map.clone();
                            let mut _meta_buffer = [0u8;8];
                            match _ctrl_recv.read_exact(&mut _meta_buffer).await {
                                Ok(_) => {
                                    let port = match  _ctrl_recv.read_u16().await {
                                        Ok(_port) => _port,
                                        Err(e) => {
                                            log::error!("{}->{}", line!(), e);
                                            return;
                                        }
                                    };
                                    let dlen = match _ctrl_recv.read_u8().await {
                                        Ok(_dlen) => _dlen,
                                        Err(e) => {
                                            log::error!("{}->{}", line!(), e);
                                            return;
                                        }
                                    };
                                    let mut domain = vec![0u8; dlen as usize];
                                    match _ctrl_recv.read_exact(&mut domain).await {
                                        Ok(_) => {},
                                        Err(e) => {
                                            log::error!("{}->{}", line!(), e);
                                            return;
                                        }
                                    };

                                    let mtx = mtx.clone();
                                    let _global_vec_poolc = _global_vec_poolc.clone();
                                    tokio::spawn(async move {
                                        let target_addr = format!("{}:{}", String::from_utf8_lossy(&domain), port);
                                        log::info!("dst: {}", target_addr);
                                        let _data_len = 11;
                                        let mut _auth_buf = {
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
                                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
                                        let mut _conn = match TcpStream::connect(&target_addr).await {
                                            Ok(_stream) => {
                                                // 响应客户端成功
                                                log::info!("{}->dst success: {}", line!(), target_addr);
                                                {
                                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                                    _channel_mapcw.insert(_meta_buffer, tx);
                                                }
                                                _auth_buf.push(0b1000_1010);
                                                _auth_buf.extend_from_slice(&_meta_buffer);
                                                _auth_buf.push(0);
                                                _auth_buf.push(0);
                                                mtx.send(_auth_buf).unwrap();
                                                _stream
                                            },
                                            Err(e) => {
                                                // 响应客户端失败
                                                rx.close();
                                                log::error!("{}->dst fail: {} {}", line!(), target_addr, e);
                                                _auth_buf.push(0b1000_1001);
                                                _auth_buf.extend_from_slice(&_meta_buffer);
                                                _auth_buf.push(0);
                                                _auth_buf.push(0);
                                                mtx.send(_auth_buf).unwrap();
                                                return;
                                            }
                                        };
                                        let (mut crx, mut ctx) = _conn.split();
                                        let _data_len = 1600;
                                        log::info!("{}", line!());
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
                                        log::info!("{}", line!());
                                        _read_buf.push(0b1000_1000);
                                        _read_buf.extend_from_slice(&_meta_buffer);
                                        _read_buf.push(0);
                                        _read_buf.push(0);
                                        loop {
                                            select! {
                                                _data = rx.recv() => {
                                                    match _data {
                                                        Some(_data) => {

                                                            if let Err(e) = ctx.write_all(&_data).await {

                                                                {
                                                                    let mut _gvp = _global_vec_poolc.lock().await;
                                                                    _gvp.push_back(_data);
                                                                }
                                                                _ = ctx.shutdown().await;
                                                                rx.close();
                                                                {
                                                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                    _channel_mapcw.remove(&_meta_buffer);
                                                                }
                                                                log::error!("{}->close dst:{} {}", line!(), target_addr, e);
                                                                return;
                                                            } else {
                                                                let mut _gvp = _global_vec_poolc.lock().await;
                                                                _gvp.push_back(_data);

                                                            }
                                                        }
                                                        None => {
                                                            log::info!("{}", line!());
                                                            _ = ctx.shutdown().await;
                                                            rx.close();
                                                            {
                                                                let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                _channel_mapcw.remove(&_meta_buffer);
                                                            }
                                                            log::error!("{}->close dst:{}", line!(), target_addr);
                                                            return;
                                                        }
                                                    }
                                                },
                                                _rn = crx.read_buf(&mut _read_buf) => {

                                                    match _rn {
                                                        Ok(n) => {
                                                            if n > 0 {
                                                                if n > 0xffff {
                                                                    log::error!("buffer over 0xffff {}", n);
                                                                    _ = ctx.shutdown().await;
                                                                    rx.close();
                                                                    {
                                                                        let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                        _channel_mapcw.remove(&_meta_buffer);
                                                                    }
                                                                    // 通知inside关闭连接
                                                                    let _data_len = 9;
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
                                                                    _kill_buf.push(0b1010_1000);
                                                                    _kill_buf.extend_from_slice(&_meta_buffer);
                                                                    _ = mtx.send(_kill_buf);
                                                                    log::error!("{}->close dst:{}", line!(), target_addr);
                                                                    return;
                                                                }

                                                                _read_buf[9] = (n >> 8) as u8;
                                                                _read_buf[10] = n as u8;

                                                                if let Err(e) = mtx.send(_read_buf) {

                                                                    _ = ctx.shutdown().await;
                                                                    rx.close();
                                                                    {
                                                                        let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                        _channel_mapcw.remove(&_meta_buffer);
                                                                    }
                                                                    // 通知inside关闭连接
                                                                    let _data_len = 9;
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
                                                                    _kill_buf.push(0b1010_1000);
                                                                    _kill_buf.extend_from_slice(&_meta_buffer);
                                                                    _ = mtx.send(_kill_buf);
                                                                    log::error!("{}->close dst:{} {}", line!(), target_addr, e);
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
                                                                _read_buf.push(0b1000_1000);
                                                                _read_buf.extend_from_slice(&_meta_buffer);
                                                                _read_buf.push(0);
                                                                _read_buf.push(0);
                                                            } else {

                                                                _ = ctx.flush().await;
                                                                _ = ctx.shutdown().await;

                                                                rx.close();

                                                                {
                                                                    let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                    _channel_mapcw.remove(&_meta_buffer);
                                                                }

                                                                // 通知inside关闭连接
                                                                let _data_len = 9;
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
                                                                _kill_buf.push(0b1010_1000);
                                                                _kill_buf.extend_from_slice(&_meta_buffer);
                                                                _ = mtx.send(_kill_buf);
                                                                log::error!("{}->close dst:{}", line!(), target_addr);
                                                                return;
                                                            }

                                                        }
                                                        Err(e) => {

                                                            _ = ctx.shutdown().await;
                                                            rx.close();
                                                            {
                                                                let mut _channel_mapcw = _channel_mapc.lock().await;
                                                                _channel_mapcw.remove(&_meta_buffer);
                                                            }
                                                            // 通知inside关闭连接
                                                            let _data_len = 8;
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
                                                            _kill_buf.push(0b1010_1000);
                                                            _kill_buf.extend_from_slice(&_meta_buffer);
                                                            _ = mtx.send(_kill_buf);
                                                            log::error!("{}->close dst:{} {}", line!(), target_addr, e);
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    {
                                        let mut _channel_mapcw = _channel_mapc.lock().await;
                                        _channel_mapcw.remove(&_meta_buffer);
                                    }
                                    log::error!("{}->{}", line!(), e);
                                    return;
                                }
                            }

                        }
                        0b1010_0100 => {
                            // tcp close outside
                            // 关闭连接

                            let mut _meta_buffer = [0u8;8];
                            match _ctrl_recv.read_exact(&mut _meta_buffer).await {
                                Ok(_) => {
                                    log::info!("i->{} close {:?}", line!(), _meta_buffer);
                                    let mut _channel_mapw = _channel_map.lock().await;
                                    _channel_mapw.remove(&_meta_buffer);
                                }
                                Err(e) => {
                                    log::error!("{}->{}", line!(), e);
                                }
                            }

                        }
                        _ => {
                            log::info!("{}->{}", line!(), cmd);
                        }
                    }
                }
                Err(e) => {
                    _ = _ctrl_send.shutdown().await;
                    log::error!("{}->{}", line!(), e);
                    return;
                }
            }
        }
    }
}

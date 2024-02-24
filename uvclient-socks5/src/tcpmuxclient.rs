use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
    sync::{
        mpsc::{self, UnboundedSender},
        Mutex,
    },
};
use tokio_rustls::TlsStream;

pub struct StreamMuxClient {
    master_tx: UnboundedSender<Vec<u8>>,
    channel_map: Arc<Mutex<HashMap<[u8; 8], UnboundedSender<Vec<u8>>>>>,
    vec_pool: Arc<Mutex<VecDeque<Vec<u8>>>>,
    global_id: Arc<AtomicU64>,
}

impl Clone for StreamMuxClient {
    fn clone(&self) -> Self {
        Self {
            master_tx: self.master_tx.clone(),
            channel_map: self.channel_map.clone(),
            vec_pool: self.vec_pool.clone(),
            global_id: self.global_id.clone(),
        }
    }
}

impl StreamMuxClient {
    pub async fn init(mut ctrl_conn: TlsStream<TcpStream>) -> Self {
        // 主连接channel
        let (mtx, mut mrx) = mpsc::unbounded_channel::<Vec<u8>>();
        // 发送channel
        let mut _channel_map = Arc::new(Mutex::new(HashMap::<
            [u8; 8],
            mpsc::UnboundedSender<Vec<u8>>,
        >::new()));
        // 全局数组池
        let _global_vec_pool = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let _channel_mapmw = _channel_map.clone();
        let _global_vec_poolc = _global_vec_pool.clone();
        let mmtx = mtx.clone();
        let _global_id = Arc::new(AtomicU64::new(0));

        tokio::spawn(async move {
            let mut _meta_buffer = [0u8; 8];
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
                                                    _ = tx.send(_read_buf);
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
                                                    _ = tx.send(_read_buf);
                                                }
                                                None => {
                                                    // todo 远端成功，我方超时关闭连接，通知远端关闭连接
                                                    log::error!("{}->inside success and outside close", line!());
                                                    let mut _gvp = _global_vec_poolc.lock().await;
                                                    _gvp.push_back(_read_buf);
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
                                                    _kill_buf.push(0b1010_0100);
                                                    _kill_buf.extend_from_slice(&_meta_buffer);
                                                    _ = mmtx.send(_kill_buf);
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
                                        let mut _meta_buffer = [0u8;8];
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

        Self {
            master_tx: mtx,
            channel_map: _channel_map,
            vec_pool: _global_vec_pool,
            global_id: _global_id,
        }
    }

    pub async fn add(&self, mut src_stream: TcpStream, dst_addr: String, dst_port: u16) {
        // 生成全局id
        let uid = self.global_id.fetch_add(1, Ordering::Relaxed);
        let _meta_buffer = uid.to_be_bytes();
        // 1 + 8 + 2 + 1
        let _data_len = 12 + dst_addr.len();
        let mut sv = {
            let mut _gvp = self.vec_pool.lock().await;
            match _gvp.pop_back() {
                Some(mut _vec) => {
                    unsafe {
                        _vec.set_len(0);
                    }
                    if _vec.capacity() < _data_len {
                        _vec.reserve(_data_len);
                    }
                    _vec
                }
                None => Vec::<u8>::with_capacity(_data_len),
            }
        };
        sv.push(0b1100_0100);
        sv.extend_from_slice(&_meta_buffer);
        sv.extend(dst_port.to_be_bytes());
        sv.push(dst_addr.len() as u8);
        sv.extend(dst_addr.as_bytes());
        if let Err(_) = self.master_tx.send(sv) {
            log::error!("main channel stop");
            return;
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        {
            let mut _channel_mapcw = self.channel_map.lock().await;
            _channel_mapcw.insert(_meta_buffer, tx);
        }
        // 等待inside确认目标端口已经连接上
        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                // 如果60秒还没连接上目标端口，直接按超时处理
                src_stream.shutdown().await.unwrap();
                {
                    let mut _channel_mapcw = self.channel_map.lock().await;
                    _ = _channel_mapcw.remove(&_meta_buffer);
                }
                log::error!("{}->dst error overtime: {}:{}", line!(), dst_addr, dst_port);
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
                            let mut _gvp = self.vec_pool.lock().await;
                            _gvp.push_back(_data);
                        }
                        if !success {
                            log::error!("{}->dst error: {}:{}", line!(), dst_addr, dst_port);
                            // 目标端口拒绝
                            {
                                let mut _channel_mapcw = self.channel_map.lock().await;
                                _ = _channel_mapcw.remove(&_meta_buffer);
                            }
                            src_stream.shutdown().await.unwrap();
                            return;
                        }
                        log::info!("{}->dst success: {}:{}", line!(), dst_addr, dst_port);
                    }
                    None => {
                        log::error!("{}->dst error: {}:{}", line!(), dst_addr, dst_port);
                        // 目标端口拒绝
                        {
                            let mut _channel_mapcw = self.channel_map.lock().await;
                            _ = _channel_mapcw.remove(&_meta_buffer);
                        }
                        src_stream.shutdown().await.unwrap();
                        return;
                    }
                }
            }
        }
        let mut conn = src_stream;
        let _data_len = 1600;
        let mut _read_buf = {
            let mut _gvp = self.vec_pool.lock().await;
            match _gvp.pop_back() {
                Some(mut _vec) => {
                    unsafe {
                        _vec.set_len(0);
                    }
                    if _vec.capacity() < _data_len {
                        _vec.reserve(_data_len);
                    }
                    _vec
                }
                None => Vec::<u8>::with_capacity(_data_len),
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
                                    let mut _gvp = self.vec_pool.lock().await;
                                    _gvp.push_back(_data);
                                }
                                _ = conn.shutdown().await;
                                rx.close();
                                {
                                    let mut _channel_mapcw = self.channel_map.lock().await;
                                    _channel_mapcw.remove(&_meta_buffer);
                                }
                                log::error!("{}->close dst: {}:{} {}", line!(), dst_addr, dst_port, e);
                                return;
                            } else {
                                let mut _gvp = self.vec_pool.lock().await;
                                _gvp.push_back(_data);
                            }
                        }
                        None => {
                            _ = conn.shutdown().await;
                            rx.close();
                            {
                                let mut _channel_mapcw = self.channel_map.lock().await;
                                _channel_mapcw.remove(&_meta_buffer);
                            }
                            log::error!("{}->close dst: {}:{}", line!(), dst_addr, dst_port);
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
                                        let mut _channel_mapcw = self.channel_map.lock().await;
                                        _channel_mapcw.remove(&_meta_buffer);
                                    }
                                    log::error!("{}->close dst: {}:{}", line!(), dst_addr, dst_port);
                                    return;
                                }
                                _read_buf[9] = (n >> 8) as u8;
                                _read_buf[10] = n as u8;
                                if let Err(e) = self.master_tx.send(_read_buf) {
                                    _ = conn.shutdown().await;
                                    rx.close();
                                    {
                                        let mut _channel_mapcw = self.channel_map.lock().await;
                                        _channel_mapcw.remove(&_meta_buffer);
                                    }
                                    log::error!("{}->close dst: {}:{} {}", line!(), dst_addr, dst_port, e);
                                    return;
                                }
                                _read_buf = {
                                    let mut _gvp = self.vec_pool.lock().await;
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
                                    let mut _channel_mapcw = self.channel_map.lock().await;
                                    _channel_mapcw.remove(&_meta_buffer);
                                }
                                // 通知inside关闭连接
                                let _data_len = 9;
                                let mut _kill_buf = {
                                    let mut _gvp = self.vec_pool.lock().await;
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
                                _ = self.master_tx.send(_kill_buf);
                                log::error!("{}->close dst: {}:{}", line!(), dst_addr, dst_port);
                                return;
                            }
                        }
                        Err(e) => {
                            _ = conn.shutdown().await;
                            rx.close();
                            {
                                let mut _channel_mapcw = self.channel_map.lock().await;
                                _channel_mapcw.remove(&_meta_buffer);
                            }
                            // 通知inside关闭连接
                            let _data_len = 9;
                            let mut _kill_buf = {
                                let mut _gvp = self.vec_pool.lock().await;
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
                            _ = self.master_tx.send(_kill_buf);
                            log::error!("{}->close dst: {}:{} {}", line!(), dst_addr, dst_port, e);
                            return;
                        }
                    }
                }
            }
        }
    }
}

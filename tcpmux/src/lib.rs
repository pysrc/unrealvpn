use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, select, sync::mpsc::{UnboundedReceiver, UnboundedSender}};




pub mod server;
pub mod client;

pub mod pool;

pub mod cmd {
    // 心跳
    pub const HART: u8 = 0;
    // 新通道
    pub const NEWBI: u8 = 1;
    // 数据包
    pub const PKG: u8 = 3;
    // 通道断开
    pub const BREAK: u8 = 4;
}


// 双向复制
pub async fn bicopy<IO>(
    id: u64,
    mut recv: UnboundedReceiver<Vec<u8>>,
    send: UnboundedSender<(u8, u64, Vec<u8>)>,
    mut stream: IO,
    mut vec_pool: pool::VecPool,
)
where IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + AsyncRead + AsyncWrite + 'static
{
    let mut _data = vec_pool.get().await;
    loop {
        select! {
            _len_op = stream.read_buf(&mut _data) => match _len_op {
                Ok(_len) => {
                    if _len == 0 {
                        // 关闭连接
                        break;
                    }
                    unsafe {
                        _data.set_len(_len);
                    }
                    if let Err(e) = send.send((cmd::PKG, id, _data)) {
                        log::error!("{} -> {}", line!(), e);
                        break;
                    }
                    _data = vec_pool.get().await;
                }
                Err(e) => {
                    log::error!("{} read error {}", line!(), e);
                    break;
                }

            },
            peer_data = recv.recv() => match peer_data {
                Some(_peer_data) => {
                    if let Err(e) = stream.write_all(&_peer_data).await {
                        log::error!("{} -> {}", line!(), e);
                        vec_pool.push(_peer_data).await;
                        break;
                    }
                    vec_pool.push(_peer_data).await;
                }
                None => {
                    log::error!("{} -> None", line!());
                    break;
                }
            }
            
        }
    }
    _ = stream.flush().await;
    _ = stream.shutdown().await;
    let data = vec_pool.get().await;
    _ = send.send((cmd::BREAK, id, data));
}
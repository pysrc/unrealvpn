use std::{collections::HashMap, marker::PhantomData, sync::{atomic::{AtomicU64, Ordering}, Arc}};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, select, sync::{mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender}, Mutex}, time};


use crate::{cmd, pool::VecPool};

type UReceiver = UnboundedReceiver<Vec<u8>>;
type MainSender = UnboundedSender<(u8, u64, Option<Vec<u8>>)>;

pub trait MuxClient<IO> {
    // 初始化
    fn init(stream: IO) -> Self;
    // 开启新通道
    fn new_channel(&mut self) -> impl std::future::Future<Output = (u64, UReceiver, MainSender, VecPool)> + Send;
}

pub struct StreamMuxClient<IO> {
    phantom: PhantomData<IO>,
    vec_pool: VecPool,
    work_sender_map: Arc<Mutex<HashMap<u64, UnboundedSender<Vec<u8>>>>>,
    main_sender: MainSender,
    id_generator: AtomicU64
}

impl<IO> MuxClient<IO> for StreamMuxClient<IO>
    where IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static
{
    fn init(mut stream: IO) -> Self {
        let vec_pool = VecPool::new();
        let id_generator = AtomicU64::new(0);
        let mut use_pool = vec_pool.clone();
        // 
        let work_sender_map = Arc::new(Mutex::new(HashMap::<u64, UnboundedSender<Vec<u8>>>::new()));
        // 接收发送到主连接的数据
        let (main_sender, mut main_receiver) = unbounded_channel::<(u8, u64, Option<Vec<u8>>)>();

        let work_sender_mapc = work_sender_map.clone();
        let main_senderc = main_sender.clone();
        tokio::spawn(async move {
            let mut main_recv_data = use_pool.get().await;
            let mut timer = time::interval(time::Duration::from_secs(30));
            loop {
                select!{
                    _command_op = stream.read_u8() => {
                        match _command_op {
                            Ok(main_recv_cmd) => {
                                let main_recv_id = stream.read_u64().await.unwrap();
                                let lens = stream.read_u32().await.unwrap() as usize;
                                if lens != 0 {
                                    unsafe {
                                        main_recv_data.set_len(0);
                                        main_recv_data.reserve(lens);
                                        main_recv_data.set_len(lens);
                                    }
                                    stream.read_exact(&mut main_recv_data).await.unwrap();
                                }
                                match main_recv_cmd {
                                    cmd::HART => {
                                        log::info!("{} hart from server", line!());
                                        continue;
                                    }
                                    // 收到数据包
                                    cmd::PKG => {
                                        let mut work_sender_map_unlock = work_sender_mapc.lock().await;
                                        match work_sender_map_unlock.get_mut(&main_recv_id) {
                                            Some(work_sender) => {
                                                if let Err(e) = work_sender.send(main_recv_data) {
                                                    // work通道关闭
                                                    log::info!("{} work channel close {}", line!(), e);
                                                    work_sender_map_unlock.remove(&main_recv_id);
                                                    // 发送断开连接信号
                                                    stream.write_u8(cmd::BREAK).await.unwrap();
                                                    stream.write_u64(main_recv_id).await.unwrap();
                                                    stream.write_u32(0).await.unwrap();
                                                }
                                                main_recv_data = use_pool.get().await;
                                            }
                                            None => {
                                                // 未知ID
                                                log::info!("{} undefine id {}", line!(), main_recv_id);
                                            }
                                        }
                                        
                                    }
                                    // 通道断开
                                    cmd::BREAK => {
                                        let mut work_sender_map_unlock = work_sender_mapc.lock().await;
                                        match work_sender_map_unlock.remove(&main_recv_id) {
                                            Some(ch) => {
                                                drop(ch);
                                                log::info!("{} channel close from server {}", line!(), main_recv_id);
                                            }
                                            None => {
                                                log::info!("{} channel is none {}", line!(), main_recv_id);
                                            }
                                        }
                                    }
                                    _ => {
                                        log::info!("{} undefine command {}", line!(), main_recv_cmd);
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("{} -> {}", line!(), e);
                                return;
                            }
                        }
                    },
                    recv = main_receiver.recv() => match recv {
                        Some((_cmd, _id, _data)) => {
                            stream.write_u8(_cmd).await.unwrap();
                            stream.write_u64(_id).await.unwrap();
                            match _data {
                                Some(_data) => {
                                    stream.write_u32(_data.len() as u32).await.unwrap();
                                    stream.write_all(&_data).await.unwrap();
                                    use_pool.push(_data).await;
                                }
                                None => {
                                    stream.write_u32(0).await.unwrap();
                                }
                            }
                            if _cmd == cmd::BREAK {
                                // 关闭本地channel
                                let local_channel_op = work_sender_mapc.lock().await.remove(&_id);
                                match local_channel_op {
                                    Some(local_channel) => {
                                        drop(local_channel);
                                        log::info!("{} channel close {}", line!(), _id);
                                    }
                                    None => {
                                        log::info!("{} channel breaked {}", line!(), _id);
                                    }
                                }
                            }
                        }
                        None => {
                            // 主通道关闭
                            log::info!("{} master channel close.", line!());
                            return;
                        }
                    },
                    // 发送心跳包
                    _ = timer.tick() => {
                        main_senderc.send((cmd::HART, 0, None)).unwrap();
                    }
                }
            }
        });
        Self {
            phantom: PhantomData,
            vec_pool,
            work_sender_map,
            main_sender,
            id_generator
        }
    }

    async fn new_channel(&mut self) -> (u64, UReceiver, MainSender, VecPool) {
        let main_sender = self.main_sender.clone();
        let id = self.id_generator.fetch_add(1, Ordering::Relaxed);
        let (work_sender, work_receiver) = unbounded_channel::<Vec<u8>>();
        self.work_sender_map.lock().await.insert(id, work_sender);
        main_sender.send((cmd::NEWBI, id, None)).unwrap();
        log::info!("{} new channel {}", line!(), id);
        return (id, work_receiver, main_sender, self.vec_pool.clone());
    }
}
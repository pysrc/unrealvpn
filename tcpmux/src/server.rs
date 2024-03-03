use std::{collections::HashMap, marker::PhantomData};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, select, sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender}};


use crate::{pool::VecPool, cmd};

type UReceiver = UnboundedReceiver<Vec<u8>>;
type MainSender = UnboundedSender<(u8, u64, Option<Vec<u8>>)>;

pub trait MuxServer<IO> {
    // 初始化
    fn init(stream: IO) -> Self;
    // 接收新通道
    fn accept_channel(&mut self) -> impl std::future::Future<Output = Option<(u64, UReceiver, MainSender, VecPool)>> + Send;
}

pub struct StreamMuxServer<IO> {
    phantom: PhantomData<IO>,
    vec_pool: VecPool,
    receiver: UnboundedReceiver<(u64, UReceiver, MainSender)>,
}

impl<IO> MuxServer<IO> for StreamMuxServer<IO>
    where IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static
{
    fn init(mut stream: IO) -> Self {
        let (sender, receiver) = unbounded_channel();
        let vec_pool = VecPool::new();
        let mut use_pool = vec_pool.clone();
        // 接收发送到主连接的数据
        let (main_sender, mut main_receiver) = unbounded_channel::<(u8, u64, Option<Vec<u8>>)>();
        tokio::spawn(async move {
            let mut work_sender_map = HashMap::new();
            let mut main_recv_data = use_pool.get().await;
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
                                    // 心跳
                                    cmd::HART => {
                                        log::info!("{} hart from client", line!());
                                        continue;
                                    }
                                    // 开启新通道
                                    cmd::NEWBI => {
                                        // 接收发送到工作通道的数据
                                        let (work_sender, work_receiver) = unbounded_channel::<Vec<u8>>();
                                        sender.send((main_recv_id, work_receiver, main_sender.clone())).unwrap();
                                        work_sender_map.insert(main_recv_id, work_sender);
                                        log::info!("{} new channel {}", line!(), main_recv_id);
                                    }
                                    // 收到数据包
                                    cmd::PKG => {
                                        match work_sender_map.get_mut(&main_recv_id) {
                                            Some(work_sender) => {
                                                if let Err(_) = work_sender.send(main_recv_data) {
                                                    // work通道关闭
                                                    log::info!("{} work channel close.", line!());
                                                    work_sender_map.remove(&main_recv_id);
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
                                        match work_sender_map.remove(&main_recv_id) {
                                            Some(ch) => {
                                                drop(ch);
                                                log::info!("{} channel close from client {}", line!(), main_recv_id);
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
                                let local_channel_op = work_sender_map.remove(&_id);
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
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        main_sender.send((cmd::HART, 0, None)).unwrap();
                    }
                }
            }
        });
        Self {
            phantom: PhantomData,
            vec_pool,
            receiver,
        }
    }
    
    async fn accept_channel(&mut self) -> Option<(u64, UReceiver, MainSender, VecPool)> {
        if let Some((a, b, c)) = self.receiver.recv().await {
            Some((a, b, c, self.vec_pool.clone()))
        } else {
            None
        }
        
    }
}
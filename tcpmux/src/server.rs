use std::{collections::HashMap, marker::PhantomData};

use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, select, sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender}};


use crate::{pool::VecPool, cmd};

type UReceiver = UnboundedReceiver<Vec<u8>>;
type MainSender = UnboundedSender<(u8, u64, Vec<u8>)>;

pub trait MuxServer<IO> {
    // 初始化
    fn init(stream: IO) -> Self;
    // 接收新通道
    fn accept_channel(&mut self) -> impl std::future::Future<Output = Option<(u64, UReceiver, MainSender, VecPool)>> + Send;
    // 从数据池获取
    fn get_vec(&mut self) -> impl std::future::Future<Output = Vec<u8>> + Send;
    // 将数据返回数组池
    fn back_vec(&mut self, data: Vec<u8>) -> impl std::future::Future<Output = ()> + Send;
    // 关闭通道
    fn break_channel(&mut self, id: u64) -> impl std::future::Future<Output = ()> + Send;
}

pub struct StreamMuxServer<IO> {
    phantom: PhantomData<IO>,
    vec_pool: VecPool,
    receiver: UnboundedReceiver<(u64, UReceiver, MainSender)>,
    main_sender: MainSender,
}

impl<IO> MuxServer<IO> for StreamMuxServer<IO>
    where IO: AsyncReadExt + AsyncWriteExt + Unpin + Send + AsyncRead + AsyncWrite + 'static
{
    fn init(mut stream: IO) -> Self {
        let (sender, receiver) = unbounded_channel();
        let vec_pool = VecPool::new();
        let mut use_pool = vec_pool.clone();
        // 接收发送到主连接的数据
        let (main_sender, mut main_receiver) = unbounded_channel::<(u8, u64, Vec<u8>)>();
        let main_senderc = main_sender.clone();
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
                                        continue;
                                    }
                                    // 开启新通道
                                    cmd::NEWBI => {
                                        // 接收发送到工作通道的数据
                                        let (work_sender, work_receiver) = unbounded_channel::<Vec<u8>>();
                                        sender.send((main_recv_id, work_receiver, main_senderc.clone())).unwrap();
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
                                                // todo 删除
                                                return;
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
                            if _data.len() == 0 {
                                stream.write_u32(0).await.unwrap();
                            } else {
                                stream.write_u32(_data.len() as u32).await.unwrap();
                                stream.write_all(&_data).await.unwrap();
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
                    }
                }
            }
        });
        Self {
            phantom: PhantomData,
            vec_pool,
            receiver,
            main_sender,
        }
    }
    
    async fn accept_channel(&mut self) -> Option<(u64, UReceiver, MainSender, VecPool)> {
        if let Some((a, b, c)) = self.receiver.recv().await {
            Some((a, b, c, self.vec_pool.clone()))
        } else {
            None
        }
        
    }
    
    async fn get_vec(&mut self) -> Vec<u8> {
        self.vec_pool.get().await
    }
    
    async fn back_vec(&mut self, data: Vec<u8>) {
        self.vec_pool.push(data).await;
    }
    
    async fn break_channel(&mut self, id: u64) {
        let data = self.get_vec().await;
        // 发信给客户端断开channel
        self.main_sender.send((cmd::BREAK, id, data)).unwrap();
    }
}
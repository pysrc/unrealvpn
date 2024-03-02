use std::{collections::VecDeque, sync::Arc};

use tokio::sync::Mutex;

pub struct VecPool {
    pool: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl VecPool {
    pub fn new() -> Self {
        Self {
            pool: Arc::new(Mutex::new(VecDeque::new()))
        }
    }
    pub async fn get(&mut self) -> Vec<u8> {
        let v = {
            self.pool.lock().await.pop_back()
        };
        let mut v = if v == None {
            Vec::new()
        } else {
            v.unwrap()
        };
        unsafe {
            v.set_len(0);
        }
        v
    }

    pub async fn push(&mut self, data: Vec<u8>) {
        self.pool.lock().await.push_back(data);
    }
}

impl Clone for VecPool {
    fn clone(&self) -> Self {
        Self { pool: self.pool.clone() }
    }
}

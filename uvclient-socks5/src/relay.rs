use std::cell::Cell;

pub struct Delay {
    last_time: Cell<tokio::time::Instant>,
    step: Cell<u64>,
}

impl Delay {
    pub fn new() -> Self {
        Delay {
            last_time: Cell::new(tokio::time::Instant::now()),
            step: Cell::new(1),
        }
    }

    pub async fn delay(&self) {
        let mut step = self.step.get();
        let last_time = self.last_time.get();
        let split_time = last_time.elapsed().as_secs();
        if split_time > 60 {
            // 1 min 重置
            step = 1;
        }
        log::info!("waite for {} secs.", step);
        tokio::time::sleep(tokio::time::Duration::from_secs(step)).await;
        // 指数退让
        step <<= 1;
        self.last_time.set(tokio::time::Instant::now());
        self.step.set(step);
    }
}

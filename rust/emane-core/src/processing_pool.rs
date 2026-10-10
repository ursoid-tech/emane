//! Persistent PHY workers. A layer joins every batch before processing its
//! next message; work within each receive antenna stays ordered.
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
type Job = Box<dyn FnOnce() + Send>;
pub struct ProcessingPool {
    sender: Option<mpsc::Sender<Job>>,
    workers: Vec<JoinHandle<()>>,
}
impl ProcessingPool {
    pub fn new(size: u16) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut pool = Self {
            sender: Some(sender),
            workers: Vec::new(),
        };
        for i in 0..size {
            let receiver = receiver.clone();
            pool.workers.push(
                std::thread::Builder::new()
                    .name(format!("emane-phy-{i}"))
                    .spawn(move || loop {
                        let job = receiver.lock().unwrap().recv();
                        match job {
                            Ok(job) => job(),
                            Err(_) => break,
                        }
                    })?,
            );
        }
        Ok(pool)
    }
    pub fn run<T: Send + 'static>(
        &self,
        jobs: Vec<Box<dyn FnOnce() -> T + Send>>,
    ) -> Result<Vec<T>, String> {
        let mut results = Vec::new();
        for job in jobs {
            let (send, receive) = mpsc::sync_channel(1);
            self.sender
                .as_ref()
                .ok_or("stopped PHY pool")?
                .send(Box::new(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                    let _ = send.send(result.map_err(|_| "PHY worker panicked".to_string()));
                }))
                .map_err(|_| "stopped PHY pool")?;
            results.push(receive);
        }
        // Drain every result even if one worker fails, preserving message barriers.
        let mut output = Vec::new();
        let mut error = None;
        for result in results {
            match result
                .recv()
                .map_err(|_| "PHY worker disconnected".to_string())
                .and_then(|r| r)
            {
                Ok(v) => output.push(v),
                Err(e) => error = Some(e),
            }
        }
        if let Some(error) = error {
            Err(error)
        } else {
            Ok(output)
        }
    }
}
impl Drop for ProcessingPool {
    fn drop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workers_overlap_but_results_preserve_order_and_shutdown_joins() {
        let pool = ProcessingPool::new(3).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let jobs = (0..3)
            .map(|i| {
                let barrier = barrier.clone();
                Box::new(move || {
                    barrier.wait();
                    (i, std::thread::current().id())
                }) as Box<dyn FnOnce() -> (i32, std::thread::ThreadId) + Send>
            })
            .collect();
        let results = pool.run(jobs).unwrap();
        assert_eq!(
            results.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_ne!(results[0].1, results[1].1);
        assert_ne!(results[1].1, results[2].1);
        drop(pool);
    }
}

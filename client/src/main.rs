mod data_link_layer;
mod network_layer;
use std::sync::{Arc,Mutex};
use lazy_static::*;
use std::thread;
use crate::tools::send_queue::SendQueue;
pub mod tools;


lazy_static!{
    ///懒分配的静态变量--发送队列
    static ref SEND_QUEUE:Arc<Mutex<SendQueue>> = Arc::new(Mutex::new(SendQueue::new()));
}
fn main() {
    network_layer::ip::send(Arc::clone(&SEND_QUEUE));

    let handle = thread::spawn(move || {
        data_link_layer::ethernet_v2::send(Arc::clone(&SEND_QUEUE));
    });
    
    handle.join().unwrap();
}

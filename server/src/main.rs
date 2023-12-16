use crate::tools::receive_queue::ReceiveQueue;
use std::sync::{Arc,Mutex};
use lazy_static::lazy_static;
use std::thread;

mod data_link_layer;
mod network_layer;
pub mod tools;
lazy_static!{
    ///懒分配的静态变量--发送队列
    static ref REVEIVE_QUEUE:Arc<Mutex<ReceiveQueue>> = Arc::new(Mutex::new(ReceiveQueue::new()));
}
fn main() {

    let handle = thread::spawn(move || {
        data_link_layer::ethernet_v2::receive(Arc::clone(&REVEIVE_QUEUE));
    });
    network_layer::ip::receive(Arc::clone(&REVEIVE_QUEUE));
    handle.join().unwrap();
}

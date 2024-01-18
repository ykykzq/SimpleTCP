use std::collections::VecDeque;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;

use lazy_static::*;

use super::cache_table::{ArpCacheEntry, ArpCacheTable};
lazy_static!{
    ///静态变量--ARP的发送队列
    pub static ref ARP_RECEIVE_QUEUE:Arc<Mutex<ArpReceiveQueue>> = Arc::new(Mutex::new(ArpReceiveQueue::new()));
}

///ARP的接收队列
pub struct ArpReceiveQueue(
    VecDeque<[u8;28]>
);

impl ArpReceiveQueue{
    ///生成接收队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        ArpReceiveQueue(new_send_queue)
    }
    /// datalink向其中写入数据。
    /// datalink层的数据长度应在46与1500之间，这一点暂未实现。
    pub fn add_data(&mut self,buffer: [u8;28]) -> bool{
        //if buffer.len()>1500 || buffer.len()<46{
        //    return false;
        //}
        self.0.push_back(buffer.clone());
        true
    }
    /// 获取队列数据
    pub fn get_data(&mut self)-> Option<[u8;28]>{
        self.0.pop_front()
    }

    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}

///### 功能
/// 考虑到为client端，这里只考虑对收到的arp应答报文的处理。arp请求报文处理在server端。
pub fn receive(shared_arp_cache_table:Arc<Mutex<ArpCacheTable>>,shared_arp_receive_queue:Arc<Mutex<ArpReceiveQueue>>){
    loop{
        let mut receive_queue=shared_arp_receive_queue.lock().unwrap();
        if receive_queue.is_empty(){
            yield_now();
            continue;
        }

        let arp_frame=receive_queue.get_data().unwrap();

        //我们只处理arp应答报文，不是则直接丢弃
        if arp_frame[6..8]!=[0x00,0x02]{
            continue;
        }

        let arp_cache_entry=ArpCacheEntry::new(
            arp_frame[14..18].try_into().unwrap(),
            arp_frame[8..14].try_into().unwrap(),
            // 1:静态 2:动态 3: log
            2
        );

        if shared_arp_cache_table.lock().unwrap().is_existed_ip(arp_frame[14..18].try_into().unwrap()){
            //如果存在则更新
            shared_arp_cache_table.lock().unwrap().update_entry(arp_cache_entry);
        }
        else{
            //否则插入
            shared_arp_cache_table.lock().unwrap().insert_entry(arp_cache_entry);
        }
        

    }
}
use std::collections::VecDeque;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use lazy_static::*;

use crate::network_layer::arp::send::ARP_SEND_REPLY_QUEUE;
use crate::tools::global_variables::*;

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
/// 考虑到为server端，这里只考虑对收到的arp请求报文的处理。arp应答报文处理在client端。
pub fn receive(shared_arp_receive_queue:Arc<Mutex<ArpReceiveQueue>>){
    loop{
        let mut receive_queue=shared_arp_receive_queue.lock().unwrap();
        if receive_queue.is_empty(){
            yield_now();
            continue;
        }

        let arp_frame=receive_queue.get_data().unwrap();

        //我们只处理arp请求报文，不是则直接丢弃
        if arp_frame[6..8]!=[0x00,0x01]{
            continue;
        }

        //个人主机，只处理关于自己的请求报文
        if arp_frame[24..28]!=LOCAL_IP{
            continue;
        }


        let dest_mac:[u8;6]=arp_frame[8..14].try_into().unwrap();
        let dest_ip:[u8;4]=arp_frame[14..18].try_into().unwrap();
        //封装为帧
        let mut reply_frame:[u8;28]=[0;28];
        //硬件类型
        reply_frame[0..2].copy_from_slice(&[0x00,0x01]);
        //协议类型
        reply_frame[2..4].copy_from_slice(&[0x08,0x00]);
        //硬件地址长度
        reply_frame[4]=6;
        //协议地址长度
        reply_frame[5]=4;
        //操作字段。op=2代表为ARP应答
        reply_frame[6..8].copy_from_slice(&[0x00,0x02]);
        //发送端mac地址
        reply_frame[8..14].copy_from_slice(&LOCAL_MAC);
        //发送端ip地址
        reply_frame[14..18].copy_from_slice(&LOCAL_IP);
        //目的mac地址。
        reply_frame[18..24].copy_from_slice(&dest_mac);
        //目的ip地址
        reply_frame[24..28].copy_from_slice(&dest_ip);

        ARP_SEND_REPLY_QUEUE.lock().unwrap().add_data(reply_frame);
    }
}
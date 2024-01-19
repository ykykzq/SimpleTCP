use std::collections::VecDeque;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use lazy_static::*;
use crate::tools::global_variables::*;

use crate::data_link_layer::ethernet_v2::send::Eth2SendQueue;

use super::cache_table::ArpCacheTable;
lazy_static!{
    ///静态变量--ARP应答报文的发送队列
    pub static ref ARP_SEND_REPLY_QUEUE:Arc<Mutex<ArpSendReplyQueue>> = Arc::new(Mutex::new(ArpSendReplyQueue::new()));
    ///静态变量--ARP请求报文的发送队列
    pub static ref ARP_SEND_REQUEST_QUEUE:Arc<Mutex<ArpSendRequestQueue>> = Arc::new(Mutex::new(ArpSendRequestQueue::new()));
}

///ARP应答报文的发送队列
pub struct ArpSendReplyQueue(
    VecDeque<[u8;28]>
);

impl ArpSendReplyQueue{
    /// 生成应答报文发送队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        ArpSendReplyQueue(new_send_queue)
    }
    /// 由receive控制，向其中加入封装好的arp应答帧
    pub fn add_data(&mut self,arp_frame: [u8;28]) -> bool{
        self.0.push_back(arp_frame.clone());
        true
    }
    /// 获取应答报文队列数据
    pub fn get_data(&mut self)-> Option<[u8;28]>{
        self.0.pop_front()
    }

    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}

///ARP请求报文的发送队列
pub struct ArpSendRequestQueue(
    VecDeque<[u8;4]>
);

impl ArpSendRequestQueue{
    ///生成请求报文发送队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        ArpSendRequestQueue(new_send_queue)
    }
    /// 由ip控制，向其中加入ipv4地址
    pub fn add_data(&mut self,ip: [u8;4]) -> bool{
        self.0.push_back(ip.clone());
        true
    }
    /// 获取队列数据
    pub fn get_data(&mut self)-> Option<[u8;4]>{
        self.0.pop_front()
    }

    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}
///### 功能
/// 考虑到为server端，目前仅支持发送arp应答报文。arp请求报文发送在client端。
pub fn send(
    shared_ethernet_v2_send_queue:Arc<Mutex<Eth2SendQueue>>,
    shared_arp_send_reply_queue:Arc<Mutex<ArpSendReplyQueue>>,
    shared_arp_send_request_queue:Arc<Mutex<ArpSendRequestQueue>>,
    shared_arp_cache_table:Arc<Mutex<ArpCacheTable>>
) {
    loop{
        if !shared_arp_send_reply_queue.lock().unwrap().is_empty(){
            let mut sendqueue=shared_arp_send_reply_queue.lock().unwrap();
            //如果为空，直接continue;
            if sendqueue.is_empty(){
                continue;
            }
            //队列不为空，则封装为帧，并发送
            let arp_frame=sendqueue.get_data().unwrap();
            
            let dest_mac:[u8;6]=arp_frame[18..24].try_into().unwrap();

            //发送--写入到Ethernet-v2的发送队列里
            let mut ethernet_v2_send_queue=shared_ethernet_v2_send_queue.lock().unwrap();
            ethernet_v2_send_queue.add_data(dest_mac,0x0806,&Vec::from(arp_frame));
        }
        else if !shared_arp_send_request_queue.lock().unwrap().is_empty(){
            let mut sendqueue=shared_arp_send_request_queue.lock().unwrap();
            //队列不为空，则封装为帧，并发送
            let mut dest_ip=sendqueue.get_data().unwrap();

            //为了防止重复发送
            if shared_arp_cache_table.lock().unwrap().is_existed_ip(dest_ip){
                continue;
            }
            
            //如果为同一子网，为目的ip
            dest_ip= if (u32::from_be_bytes(dest_ip) & u32::from_be_bytes(NETMASK))==(u32::from_be_bytes(LOCAL_IP) & u32::from_be_bytes(NETMASK)){
                dest_ip
            }
            else{
                //否则为网关的ip
                GATEWAY_IP
            };
            

            //封装为帧
            let mut arp_frame:[u8;28]=[0;28];
            //硬件类型
            arp_frame[0..2].copy_from_slice(&[0x00,0x01]);
            //协议类型
            arp_frame[2..4].copy_from_slice(&[0x08,0x00]);
            //硬件地址长度
            arp_frame[4]=6;
            //协议地址长度
            arp_frame[5]=4;
            //操作字段。op=1代表为ARP请求
            arp_frame[6..8].copy_from_slice(&[0x00,0x01]);
            //发送端mac地址
            arp_frame[8..14].copy_from_slice(&LOCAL_MAC);
            //发送端ip地址
            arp_frame[14..18].copy_from_slice(&LOCAL_IP);
            //目的mac地址。全0
            arp_frame[18..24].copy_from_slice(&[0;6]);
            //目的ip地址
            arp_frame[24..28].copy_from_slice(&dest_ip);

            //发送--写入到Ethernet-v2的发送队列里
            shared_ethernet_v2_send_queue.lock().unwrap().add_data(BROADCAST_MAC,0x0806,&Vec::from(arp_frame));
        }
    }
}

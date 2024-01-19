use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use lazy_static::*;

use crate::network_layer::ip::send::IPSendQueue;
use crate::network_layer::icmp::receive::*;
use crate::network_layer::ip::send::*;

lazy_static!{
    ///静态变量--ARP的发送队列
    pub static ref ICMP_SEND_QUEUE:Arc<Mutex<IcmpSendQueue>> = Arc::new(Mutex::new(IcmpSendQueue::new()));
}

///ARP的接收队列
pub struct IcmpSendQueue(
    VecDeque<Vec<u8>>
);

impl IcmpSendQueue{
        /// 生成应答报文发送队列
        pub fn new() -> Self{
            let new_send_queue=VecDeque::new();
            IcmpSendQueue(new_send_queue)
        }
        /// 由ipv4协议写入
        pub fn add_data(&mut self,data: Vec<u8>) -> bool{
            self.0.push_back(data.clone());
            true
        }
        /// 获取队列数据
        pub fn get_data(&mut self)-> Option<Vec<u8>>{
            self.0.pop_front()
        }
    
        /// 队列是否为空
        pub fn is_empty(&self)->bool{
            self.0.is_empty()
        }
}

pub fn send(
    shared_ip_send_queue:Arc<Mutex<IPSendQueue>>,
    shared_icmp_send_queue:Arc<Mutex<IcmpSendQueue>>)
{
    let mut sendqueue=shared_icmp_send_queue.lock().unwrap();
    loop {
        if sendqueue.is_empty(){
            yield_now();
            continue;
        }
        else{
            let data=sendqueue.get_data().unwrap();
            //加载头部
            let hdr=IcmpHeader::from_vec_u8(data.clone());
            let mut buffer:Vec<u8>=Vec::new();
            for i in hdr.into_u16_array(){
                buffer.push(((i>>8)&0x00_ff )as u8);
                buffer.push((i&0x00_ff )as u8);
            }
            //加载数据
            buffer.append(&mut data[8..data.len()].to_vec());
    
            shared_ip_send_queue.lock().unwrap().add_data(buffer.into(),ICMPV4_PROTOCOL);
        }
    }
}


fn test_ip_send_queue(shared_ip_send_queue:Arc<Mutex<IPSendQueue>>)  {
    let file_path=String::from("data.txt");
    let mut tmp=Vec::new();
    match File::open(file_path) {
        Ok(mut file)=>{
            //读到tmp里
            let size_of_data;
            size_of_data=file.read_to_end( &mut tmp).unwrap()as i32;
        }
        Err(err)=> {
            println!("读取文件失败！");
        }
    } 
    shared_ip_send_queue.lock().unwrap().add_data(tmp,UDP_PROTOCOL);
}

pub fn test_icmp(shared_icmp_send_queue:Arc<Mutex<IcmpSendQueue>>){
    let mut data:Vec<u8>=Vec::new();
    let hdr=IcmpHeader::new(11, 0, 0);
    for i in hdr.into_u16_array(){
        data.push(((i>>8)&0x00_ff )as u8);
        data.push((i&0x00_ff )as u8);
    }
    data.append(&mut [0;68].to_vec());
    shared_icmp_send_queue.lock().unwrap().add_data(data);
}
use std::{sync::{Arc, Mutex}, thread::yield_now};
use pcap::*;
use std::collections::VecDeque;
use lazy_static::*;

use crate::tools::crc32::calculate_crc32;
use crate::tools::global_variables::*;


lazy_static!{
    ///静态变量--ethernet_v2的发送队列
    pub static ref ETHERNET_V2_SEND_QUEUE:Arc<Mutex<Eth2SendQueue>> = Arc::new(Mutex::new(Eth2SendQueue::new()));
}


///帧头
pub struct EthernetHeader{
    ///目的MAC地址
    dest_mac_addr   :[u8;6],
    ///源MAC地址
    src_mac_addr    :[u8;6],
    ///类型
    ethernet_type   :u16,   
}
/// Ethernet v2的发送队列的元素
pub struct Eth2QueueElement{
    ///目的MAC地址
    dest_mac_addr   :[u8;6],
    ///类型
    ethernet_type   :u16, 
    ///数据
    data:Vec<u8>
}
pub struct Eth2SendQueue(
    VecDeque<Eth2QueueElement>
);

impl Eth2SendQueue{
    ///生成发送队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        Eth2SendQueue(new_send_queue)
    }
    /// netwrok向其中写入数据。
    /// 注意分片的工作由network层负责。
    /// newwork层保证数据长度在46与1500之间，该函数中不再检查。
    pub fn add_data(&mut self,dest_mac:[u8;6],ethernet_v2_type:u16,buffer: &Vec<u8>) -> bool{
        // if buffer.len()>1500 || buffer.len()<46{
        //     return false;
        // }
        self.0.push_back(
            Eth2QueueElement{
                dest_mac_addr   :dest_mac,
                ethernet_type   :ethernet_v2_type, 
                data:buffer.clone()
            }
        );
        true
    }
    /// 获取队列数据
    pub fn get_data(&mut self)-> Option<Eth2QueueElement>{
        self.0.pop_front()
    }

    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}


///加载帧头
pub fn load_ethernet_header( buffer: &mut Vec<u8>,element:&Eth2QueueElement){
    let ethernet_header:EthernetHeader=EthernetHeader{
        dest_mac_addr:element.dest_mac_addr,
        src_mac_addr:LOCAL_MAC,
        ethernet_type:element.ethernet_type,
    };
    buffer.extend_from_slice(&ethernet_header.dest_mac_addr);
    buffer.extend_from_slice(&ethernet_header.src_mac_addr);
    buffer.extend_from_slice(&ethernet_header.ethernet_type.to_be_bytes())
    
}

///# 功能
///从SEND_QUEUE中加载MAC的数据部分
///# 返回值
///元组(是否成功打开文件并加载,帧长)
pub fn load_ethernet_data_from_network_layer(buffer: &mut Vec<u8>,element:&Eth2QueueElement) -> (bool,usize){
    let data=&element.data;
    //计算CRC32校验码
    let crc32:u32=calculate_crc32(&data, data.len() as i32);

    //拼接帧,注意要在帧头（14B）之后
    buffer.extend_from_slice(&data);
    for i in 14..data.len() as i32+14{
        buffer[i as usize]=data[i as usize-14];
    }
    buffer.extend_from_slice(&crc32.to_be_bytes());

    //返回值
    (true,14+data.len() as usize+crc32.to_be_bytes().len())
}

pub fn send(shared_ethernet_v2_send_queue:Arc<Mutex<Eth2SendQueue>>) {

    //获取并打印所有网络适配器
    let devices=Device::list().unwrap();
    if devices.is_empty(){
        panic!("本机无网络适配器！");
    }
    // for (i,device) in devices.iter().enumerate(){
    //     println!("第{}个设备：{}",i+1,device.name);
    //     match device.desc.clone(){
    //         Some(sm)=>{
    //             println!("  设备描述:{}",sm);
    //         }
    //         None=>{
    //             println!("  设备描述:该设备没有描述");
    //         }
    //     };
    // }

    // //由用户选择使用的网络适配器
    // println!("选择发送端使用的网络适配器：1-{}",devices.len());
    // io::stdout().flush().unwrap();//确保所有数据写入终端,此行可以删除
    //     //读取用户输入
    // let mut user_input = String::new();
    // io::stdin().read_line(&mut user_input).unwrap();
    // let used_device_number:usize=user_input.trim().parse().unwrap();
    // if used_device_number < 1 || used_device_number >devices.len(){
    //     panic!("不存在该设备！");
    // }
    let used_device_number=1;
    //打开网络适配器
    let mut cap=Capture::from_device(devices[used_device_number-1].clone()).unwrap()
        .promisc(true)
        .open()
        .unwrap();

    println!();
    // println!("您选择的网络适配器的datalink信息：");
    // println!("  {},{}",cap.get_datalink().get_name().unwrap(),cap.get_datalink().get_description().unwrap());
    if cap.get_datalink().get_description().unwrap() != "Ethernet"{
        panic!("您选择的设备不支持以太网");
    }
    
    //轮询发送队列，队列为空则直接continue
    loop{
        if shared_ethernet_v2_send_queue.lock().unwrap().is_empty(){
            yield_now();
            continue;
        }
        else {
            let element=shared_ethernet_v2_send_queue.lock().unwrap().get_data().unwrap();

            //本次发送中的数据帧
            let mut buffer:Vec<u8>=Vec::new();

            //加载帧头
            load_ethernet_header(&mut buffer,&element);
        
            //从网络层加载数据;
            let(load_success,size_of_frame)=load_ethernet_data_from_network_layer(&mut buffer,&element);
            if load_success{
                println!("封装为帧成功，帧长: {} ,数据长度: {} ",size_of_frame,size_of_frame-18);
            }
            else{
                continue;
            }
            
            //发送数据
            cap.sendpacket(buffer.clone()).unwrap();
            yield_now();
        }
    }
}

use std::sync::{Arc, Mutex};
use pcap::*;
use std::io::{self, Write};
use crate::tools::crc32::calculate_crc32;
use crate::tools::send_queue::SendQueue;
///帧头
pub struct EthernetHeader{
    ///目的MAC地址
    dest_mac_addr   :[u8;6],
    ///源MAC地址
    src_mac_addr    :[u8;6],
    ///类型
    ethernet_type   :u16,   
}


///加载帧头
pub fn load_ethernet_header( buffer: &mut Vec<u8>){
    let ethernet_header:EthernetHeader=EthernetHeader{
        dest_mac_addr:[0x14,0x5A,0xFC,0x15,0x1A,0x8D],
        src_mac_addr:[0x14,0x5A,0xFC,0x15,0x1A,0x8D],
        ethernet_type:0x0800,
    };
    buffer.extend_from_slice(&ethernet_header.dest_mac_addr);
    buffer.extend_from_slice(&ethernet_header.src_mac_addr);
    buffer.extend_from_slice(&ethernet_header.ethernet_type.to_be_bytes())
    
}

// ///# 功能
// ///根据文件路径加载MAC的数据部分
// ///# 返回值
// ///元组(是否成功打开文件并加载,帧长)
// pub fn load_ethernet_data(buffer: &mut Vec<u8>,file_path:&String) -> (bool,usize){
//     let size_of_data:i32 ;
//     let mut tmp:Vec<u8>=Vec::new();

//     match File::open(file_path) {
//         Ok(mut file)=>{
//             //读到tmp里
//             size_of_data=file.read_to_end(&mut tmp).unwrap()as i32;

//             //判断数据长度
//             if size_of_data <46 {
//                 println!("文件数据长度为{},小于最小帧长！",size_of_data);
//                 return (false,0);
//             }
//             if  size_of_data>1500{
//                 println!("文件数据长度为{},超过最大帧长！",size_of_data);
//                 return (false,0);
//             }

//             //计算CRC32校验码
//             let crc32:u32=calculate_crc32(&tmp, size_of_data as i32);

//             //拼接帧,注意要在帧头（14B）之后
//             buffer.extend_from_slice(&tmp);
//             // for i in 14..size_of_data+14{
//             //     buffer[i as usize]=tmp[i as usize-14];
//             // }
//             buffer.extend_from_slice(&crc32.to_be_bytes());
//             (true,14+size_of_data as usize+crc32.to_be_bytes().len())
//         }
//         Err(err)=> {
//             println!("读取文件失败！{file_path}:{err}");
//             (false,0)
//         }
//     }
// }

///# 功能
///从SEND_QUEUE中加载MAC的数据部分
///# 返回值
///元组(是否成功打开文件并加载,帧长)
pub fn load_ethernet_data_from_network_layer(buffer: &mut Vec<u8>,send_queue:Arc<Mutex<SendQueue>>) -> (bool,usize){
    let mut send_queue=send_queue.lock().unwrap();
    if send_queue.is_empty(){
        return (false,0);
    }
    let data=match send_queue.get_data() {
        Some(value)=>{
            value
        }
        None=>{
            //发送队列为空则加载失败
            return (false,0);
        }
    };
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

pub fn send(shared_send_queue:Arc<Mutex<SendQueue>>) {

    //获取并打印所有网络适配器
    let devices=Device::list().unwrap();
    if devices.is_empty(){
        panic!("本机无网络适配器！");
    }
    for (i,device) in devices.iter().enumerate(){
        println!("第{}个设备：{}",i+1,device.name);
        match device.desc.clone(){
            Some(sm)=>{
                println!("  设备描述:{}",sm);
            }
            None=>{
                println!("  设备描述:该设备没有描述");
            }
        };
    }

    //由用户选择使用的网络适配器
    println!("选择发送端使用的网络适配器：1-{}",devices.len());
    io::stdout().flush().unwrap();//确保所有数据写入终端,此行可以删除
        //读取用户输入
    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).unwrap();
    let used_device_number:usize=user_input.trim().parse().unwrap();
    if used_device_number < 1 || used_device_number >devices.len(){
        panic!("不存在该设备！");
    }

    //打开网络适配器
    let mut cap=Capture::from_device(devices[used_device_number-1].clone()).unwrap()
        .promisc(true)
        .open()
        .unwrap();

    println!();
    println!("您选择的网络适配器的datalink信息：");
    println!("  {},{}",cap.get_datalink().get_name().unwrap(),cap.get_datalink().get_description().unwrap());
    if cap.get_datalink().get_description().unwrap() != "Ethernet"{
        panic!("您选择的设备不支持以太网");
    }
    
    //轮询发送队列，队列为空则直接continue
    loop{

        //本次发送中的数据帧
        let mut buffer:Vec<u8>=Vec::new();

        //加载帧头
        load_ethernet_header(&mut buffer);
    
        //从网络层加载数据;
        let(load_success,size_of_frame)=load_ethernet_data_from_network_layer(&mut buffer,shared_send_queue.clone());
        if load_success{
            println!("封装为帧成功，帧长: {} ,数据长度: {} ",size_of_frame,size_of_frame-18);
        }
        else{
            continue;
        }
        
        
        
        //发送数据
        cap.sendpacket(buffer.clone()).unwrap();

    }
    
    
}

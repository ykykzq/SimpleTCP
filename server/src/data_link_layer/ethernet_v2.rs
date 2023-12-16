use crate::ReceiveQueue;
use std::sync::{Arc, Mutex};
use pcap::*;
use std::io::{ self, Write};
use crate::tools::crc32::*;

pub fn receive(shared_reveive_queue:Arc<Mutex<ReceiveQueue>>){

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
    println!("选择接收端使用的网络适配器：1-{}",devices.len());
    io::stdout().flush().unwrap();//确保所有数据写入终端,此行可以删除
        //读取用户输入
    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).unwrap();
    let used_device_number:usize=user_input.trim().parse().unwrap();
    if used_device_number < 1 || used_device_number >devices.len(){
        panic!("不存在该设备！");
    }
    let mut cap=Capture::from_device(devices[used_device_number-1].clone()).unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // 过滤掉所有源或目标地址不为 127.0.0.1 的数据包。
    //cap.filter("host 127.0.0.1", true).unwrap();


    while let Ok(packet)=cap.next_packet(){

        println!("收到的帧的长度：{}",packet.header.caplen);
        println!("目的MAC：");
        for i in 0..6{
            print!("{:#X} ",packet.data[i]);
        }
        println!();
        println!("源MAC：");
        for i in 6..12{
            print!("{:#X} ",packet.data[i]);
        }
        println!();
        println!("类型：");
        for i in 12..14{
            print!("{:#X} ",packet.data[i]);
        }
        println!();
        println!("数据内容：");
        for i in 14..packet.header.caplen-4{
             print!("{}",packet.data[i as usize] as char);
        }
        println!();
        println!("CRC32:");
        let crc_byte:[u8;4]=packet.data[packet.header.caplen as usize-4 .. packet.header.caplen as usize].try_into().unwrap();
        let crc32_code=u32::from_be_bytes(crc_byte);
        print!("{:#X}",crc32_code);

        println!();
        //校验数据
        if crc32_code==calculate_crc32(&packet.data[14..packet.header.caplen as usize-4].to_vec(), packet.header.caplen as i32-18 ){ 
            println!("CRC32校验通过！");
            if packet.header.len-18>(46) && packet.header.caplen-18<1500{
                println!("数据长度检验通过！");
                if (packet.data[6..12]==vec![0x14,0x5a,0xfc,0x15,0x1a,0x8d]) | (packet.data[6..12]==vec![0xff,0xff,0xff,0xff,0xff,0xff]){
                    println!("MAC检验通过!");

                    //通过一系列校验之后，再写入到接收队列里
                    //写入队列
                    shared_reveive_queue.lock()
                    .unwrap()
                    .add_data(
                &packet.data[14..packet.header.len as usize-4].to_vec()
                    );

                }
                else {
                    println!("MAC检验未通过！");
                }
            }
            else {
                println!("数据长度检验未通过！")
            }
        }
        else{
            println!("CRC32校验失败！应为{:#X}！",calculate_crc32(&packet.data[14..packet.header.caplen as usize-4].to_vec(), packet.header.caplen as i32-18 ));
        }
        
        
        

        
    }
    
}

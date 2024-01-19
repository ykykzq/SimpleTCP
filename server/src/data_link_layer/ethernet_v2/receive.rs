use std::sync::Arc;
use std::sync::Mutex;
use pcap::*;
use crate::tools::crc32::*;
use crate::network_layer::arp::receive::ArpReceiveQueue;
use crate::network_layer::ip::receive::IpReceiveQueue;
use crate::tools::global_variables::*;
pub fn receive(shared_arp_receive_queue:Arc<Mutex<ArpReceiveQueue>>,shared_ip_receive_queue:Arc<Mutex<IpReceiveQueue>>){

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
    // println!("选择接收端使用的网络适配器：1-{}",devices.len());
    // io::stdout().flush().unwrap();//确保所有数据写入终端,此行可以删除
    //     //读取用户输入
    // let mut user_input = String::new();
    // io::stdin().read_line(&mut user_input).unwrap();
    // let used_device_number:usize=user_input.trim().parse().unwrap();
    // if used_device_number < 1 || used_device_number >devices.len(){
    //     panic!("不存在该设备！");
    // }
    let used_device_number=1;
    let mut cap=Capture::from_device(devices[used_device_number-1].clone()).unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // 过滤掉所有源或目标地址不为 127.0.0.1 的数据包。
    //cap.filter("host 127.0.0.1", true).unwrap();


    while let Ok(packet)=cap.next_packet(){

        let len=packet.header.caplen;
        println!("收到的帧的长度：{}",len);
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
        
        let crc_byte:[u8;4]=packet.data[packet.header.caplen as usize-4 .. packet.header.caplen as usize].try_into().unwrap();
        let crc32_code=u32::from_be_bytes(crc_byte);


        println!();
        //校验数据
        if crc32_code==calculate_crc32(&packet.data[14..packet.header.caplen as usize-4].to_vec(), packet.header.caplen as i32-18 ){ 
            println!("CRC32校验通过！");
            //if packet.header.len-18>(46) && packet.header.caplen-18<1500{
            //    println!("数据长度检验通过！");
                if (packet.data[0..6]==LOCAL_MAC) | (packet.data[0..6]==BROADCAST_MAC){
                    println!("MAC检验通过!");

                    //通过一系列校验之后，再写入到接收队列里
                    //写入队列
                    if packet.data[12]==0x08 && packet.data[13]==0x00{
                        //ipv4协议
                        shared_ip_receive_queue.lock().unwrap().add_data(
                            &packet.data[14..packet.header.len as usize-4].to_vec()
                        );
                    }
                    else if packet.data[12]==0x08 && packet.data[13]==0x06{
                        //arp协议
                        //帧长一定为28
                        let mut data:[u8;28]=[0;28];
                        data.copy_from_slice(&packet.data[14..42]);
                        shared_arp_receive_queue.lock().unwrap().add_data(data);
                    }

                }
                else {
                    println!("MAC检验未通过！");
                }
            //}
            //else {
            //    println!("数据长度检验未通过！")
            //}
        }
        else{
            println!("CRC32校验失败！应为{:#X}！",calculate_crc32(&packet.data[14..packet.header.caplen as usize-4].to_vec(), packet.header.caplen as i32-18 ));
        }  
        println!();
    }
    
    
}

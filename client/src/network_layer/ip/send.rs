use std::collections::VecDeque;
use lazy_static::*;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use crate::data_link_layer::ethernet_v2::send::Eth2SendQueue;
use crate::network_layer::arp::cache_table::ArpCacheTable;
use crate::tools::global_variables::*;

lazy_static!{
    //静态变量--IP发送队列
    pub static ref IP_SEND_QUEUE:Arc<Mutex<IPSendQueue>> = Arc::new(Mutex::new(IPSendQueue::new()));
}


///最大分片长度
pub const DATA_SLICE_LENTH:usize=1400;
/// 上层协议字段-TCP
pub const TCP_PROTOCOL:u8 = 6;
/// 上层协议字段-UDP
pub const UDP_PROTOCOL :u8= 17;
/// 上层协议字段-ICMPV4
pub const ICMPV4_PROTOCOL:u8=1;
/// 上层协议字段-IGMPV4
pub const IGMPV4_PROTOCOL:u8=2;

///ARP应答报文的发送队列
pub struct IPSendQueue(
    VecDeque<IPSendQueueElement>
);

pub struct IPSendQueueElement{
    protocol_type:u8,
    data:Vec<u8>
}

impl IPSendQueue{
    /// 生成应答报文发送队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        IPSendQueue(new_send_queue)
    }
    /// 由上层协议写入
    pub fn add_data(&mut self,data: Vec<u8>,protocol_type:u8) -> bool{
        let element=IPSendQueueElement{
            protocol_type,
            data
        };
        self.0.push_back(element);
        true
    }
    /// 获取应答报文队列数据
    pub fn get_data(&mut self)-> Option<IPSendQueueElement>{
        self.0.pop_front()
    }

    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}

struct IpHeader{
    /// 默认IP版本：IPV4，头部长度：单位为4字节，最长60字节
    version_and_hdrlen:u8,
    /// 服务类型
	type_of_service:u8,
    /// 总长度
	total_length:u16,
    /// 标识，表明不同分片属于同一数据报
	id:u16,			
    /// 标志与片偏移
	flags_and_fragment_offset:u16,
    /// 生存时间
	time_to_live:u8,
    /// （上层）协议（TCP = 6,UDP = 17，ICMPV4=1, IGMPV4=2）
	upper_protocol_type:u8,
    /// 首部检验和
	check_sum:u16,
    /// 源IP地址
	source_ip:[u8;4],   
    /// 目的IP地址
    destination_ip:[u8;4],
    /// 40字节的可选部分
	optional:[u8;40],
}

impl IpHeader {
    /// ### 功能
    /// 计算首部校验和时使用，把首部转化为2字节的数组（30*2）
    pub fn into_u16_array(&self) -> Vec<u16> {
        let mut result:Vec<u16>=Vec::new();
        result.push((self.version_and_hdrlen as u16) << 8 | self.type_of_service as u16);
        result.push(self.total_length);
        result.push(self.id);
        result.push(self.flags_and_fragment_offset);
        result.push((self.time_to_live as u16) << 8 | self.upper_protocol_type as u16);
        result.push(self.check_sum);
        result.push((self.source_ip[3] as u16)<<8|(self.source_ip[2] as u16));
        result.push((self.source_ip[1] as u16)<<8|(self.source_ip[0] as u16));
        result.push((self.destination_ip[3] as u16)<<8|(self.destination_ip[2] as u16));
        result.push((self.destination_ip[1] as u16)<<8|(self.destination_ip[0] as u16));
        for i in 0..20{
            result.push((self.optional[2*i] as u16) << 8 | self.optional[2*i+1] as u16);
        }
        result
    }
    /// ### 功能
    /// 根据所给值生成头部，并自动计算首部校验和
    /// ### 返回值
    /// 计算过首部校验和的头部
    pub fn new (
        in_version_and_hdrlen:u8,
        in_type_of_service:u8,
        in_total_length:u16,
        in_id:u16,			
        in_flags_and_fragment_offset:u16,
        in_time_to_live:u8,
        in_upper_protocol_type:u8,
        in_source_ip:[u8;4],   
        in_destination_ip:[u8;4],
        in_optional:[u8;40],
    )-> IpHeader{
        let mut hdr=IpHeader{
            version_and_hdrlen:in_version_and_hdrlen,
            type_of_service:in_type_of_service,
            total_length:in_total_length,
            id:in_id,			
            flags_and_fragment_offset:in_flags_and_fragment_offset,
            time_to_live:in_time_to_live,
            upper_protocol_type:in_upper_protocol_type,
            check_sum:0x0000,
            source_ip:in_source_ip,   
            destination_ip:in_destination_ip,
            optional:in_optional,
        };
        hdr.check_sum=calculate_check_sum(&hdr);
        hdr
    }
}

/// ### 功能
/// 计算首部校验和
/// ### 返回值 
/// 16bit的校验和
fn calculate_check_sum(ip_hdr:&IpHeader)-> u16{
    let mut sum:u32=0;
    let len:usize=(ip_hdr.version_and_hdrlen&0x000f)as usize;
	let hdr=ip_hdr.into_u16_array();

	for i in 0..hdr.len()-1{
        sum=sum+hdr[i] as u32;
    }

    //如果最后剩了一字节
    if len%2==1{
        //那么只需要加最后一个[u16]的高8位即可
        sum=sum+ ( (hdr[hdr.len()-1]>>8) & 0x00ff )as u32;
    }
    else{
        sum=sum+hdr[hdr.len()-1]as u32;
    }
	
	//压缩32位到16位
	while sum>>16 >0
	{
		sum=(sum & 0xffff)+(sum>>16);
	}

    (sum & 0xffff) as u16
}


/// ### 功能
/// 将Vec<u16>转换为Vec<u8>
pub fn u8_from_u16 (u16_array:& Vec<u16>)-> Vec<u8>{
    let mut u8_array:Vec<u8>=Vec::new();
    for i in u16_array{
        u8_array.push(((i & 0xff00)>>8)as u8);
        u8_array.push((i & 0x00ff)as u8);
    }
    u8_array
}


pub fn send(
    shared_arp_cache_table:Arc<Mutex<ArpCacheTable>>,
    shared_ethernet_v2_send_queue:Arc<Mutex<Eth2SendQueue>>,
    shared_ip_send_queue:Arc<Mutex<IPSendQueue>>
) {
    loop{
        //分片数
        let mut sendqueue=shared_ip_send_queue.lock().unwrap();
        if sendqueue.is_empty(){
            yield_now();
            continue;
        }
        let element=sendqueue.get_data().unwrap();
        let len_of_data=element.data.len();


        let number_of_slice=(len_of_data as usize /DATA_SLICE_LENTH)+1;

        //如果不需要分片
        if number_of_slice==1{
            let mut buffer:Vec<u8>=Vec::new();
            let hdr:IpHeader=IpHeader::new (
                0x4f,//60
                0xfe,
                60+len_of_data as u16,
                2023,			
                0b0100_0000_0000_0000,//DF=1,offset=0
                64,
                element.protocol_type,
                LOCAL_IP,   
                DEST_IP,
                [0;40],
            );

            buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
            buffer.extend(element.data);
            
            loop{
                let dest_mac=shared_arp_cache_table.lock().unwrap().find_mac_from_ip(DEST_IP);
                if dest_mac.is_some(){
                    let mut sendqueue=shared_ethernet_v2_send_queue.lock().unwrap();
                    sendqueue.add_data(dest_mac.unwrap(),0x0800,&buffer);
                    break;
                }
                else {
                    yield_now()
                }
            }
        }
        else{
            //如果需要分片
            //对于每一个分片
            //首先取出数据
            //然后计算头部并加载
            //之后加载数据并把整个片添加到发送队列里
            for i in 0..number_of_slice{
                if i==number_of_slice-1 {//最后一个分片
                    let mut buffer:Vec<u8>=Vec::new();
                    let len_of_data=element.data.len()-i*DATA_SLICE_LENTH;
                    let hdr:IpHeader=IpHeader::new (
                        0x4f,
                        0xfe,
                        60+len_of_data as u16,
                        2023,			
                        (i* DATA_SLICE_LENTH / 8)as u16,//DF=0,MF=0
                        64,
                        element.protocol_type,
                        LOCAL_IP,   
                        DEST_IP,
                        [0;40],
                    );
                    buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
                    buffer.extend(element.data[i*DATA_SLICE_LENTH..element.data.len()].to_vec());
                    loop{
                        let dest_mac=shared_arp_cache_table.lock().unwrap().find_mac_from_ip(DEST_IP);
                        if dest_mac.is_some(){
                            let mut sendqueue=shared_ethernet_v2_send_queue.lock().unwrap();
                            sendqueue.add_data(dest_mac.unwrap(),0x0800,&buffer);
                            break;
                        }
                        else {
                            yield_now()
                        }
                    }
                }
                else{
                    let mut buffer:Vec<u8>=Vec::new();
                    let len_of_data=DATA_SLICE_LENTH;
                    let hdr:IpHeader=IpHeader::new (
                        0x4f,
                        0xfe,
                        60+len_of_data as u16,
                        2023,			
                        1<<13 as u16/*MF*/ | (i* DATA_SLICE_LENTH/8)as u16,//MF=1,DF=0
                        64,
                        element.protocol_type,
                        LOCAL_IP,   
                        DEST_IP,
                        [0;40],
                    );
                    buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
                    buffer.extend(element.data[i*DATA_SLICE_LENTH..(i+1)*DATA_SLICE_LENTH].to_vec());
                    
                    loop{
                        let dest_mac=shared_arp_cache_table.lock().unwrap().find_mac_from_ip(DEST_IP);
                        if dest_mac.is_some(){
                            let mut sendqueue=shared_ethernet_v2_send_queue.lock().unwrap();
                            sendqueue.add_data(dest_mac.unwrap(),0x0800,&buffer);
                            break;
                        }
                        else {
                            yield_now();
                        }
                    }
                }
            }//end for
        }
    }
}
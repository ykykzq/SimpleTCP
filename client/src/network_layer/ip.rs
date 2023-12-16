use std::fs::File;
use std::io::Read;
use std::sync::{Arc,Mutex};

use crate::tools::send_queue::SendQueue;


///最大分片长度
const DATA_SLICE_LENTH:usize=1400;
/// 上层协议字段-TCP
const TCP_PROTOCOL:u8 = 6;
/// 上层协议字段-UDP
const UDP_PROTOCOL :u8= 17;
/// 上层协议字段-ICMPV4
const ICMPV4_PROTOCOL:u8=1;
/// 上层协议字段-IGMPV4
const IGMPV4_PROTOCOL:u8=2;

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
	source_ip:u32,   
    /// 目的IP地址
    destination_ip:u32,
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
        result.push((self.source_ip>>8)as u16);
        result.push((self.source_ip & 0x0000_ffff)as u16);
        result.push((self.destination_ip>>8)as u16);
        result.push((self.destination_ip & 0x0000_ffff)as u16);
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
        in_source_ip:u32,   
        in_destination_ip:u32,
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
/// 读取文件，将文件内容装入tmp中，并确定总长度与分片数
/// ### 返回值
/// 总长度，usize，需要分的片数，usize
fn read_file_and_into_slice(file_path:&String,tmp:&mut Vec<u8>) ->(usize,usize) {
    match File::open(file_path) {
        Ok(mut file)=>{
            //读到tmp里
            let size_of_data;
            size_of_data=file.read_to_end( tmp).unwrap()as i32;

            (tmp.len(),(size_of_data as usize /DATA_SLICE_LENTH)+1)
            
        }
        Err(err)=> {
            println!("读取文件失败！{file_path}:{err}");
            (0,0)
        }
    } 
}

/// ### 功能
/// 将四个u8转换为ip地址
pub fn ip_from_u8(a:u8,b:u8,c:u8,d:u8)->u32{
    (a as u32) << 24 |
    (b as u32) << 16 |
    (c as u32) << 8  |
    (d as u32)
    
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

/// ### 功能
/// 将filepath对应的文件分片，并塞入发送队列里
/// ### 返回值
/// 
pub fn load_ip_data(file_path:&String,send_queue:Arc<Mutex<SendQueue>>) -> bool{
    let mut data:Vec<u8>=Vec::new();
    //分片数
    let (len_of_data,number_of_slice)=read_file_and_into_slice(file_path,&mut data);

    //如果不需要分片
    if number_of_slice==1{
        let mut buffer:Vec<u8>=Vec::new();
        let hdr:IpHeader=IpHeader::new (
            0x4f,
            0xfe,
            60+len_of_data as u16,
            2023,			
            0b0100_0000_0000_0000,//DF=1,offset=0
            64,
            UDP_PROTOCOL,
            ip_from_u8(192, 168, 31, 1),   
            ip_from_u8(192, 168, 31, 1),
            [0;40],
        );

        buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
        buffer.extend(data);

        let mut sendqueue=send_queue.lock().unwrap();
        sendqueue.add_data(&buffer);

        return true;
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
                let len_of_data=data.len()-i*DATA_SLICE_LENTH;
                let hdr:IpHeader=IpHeader::new (
                    0x4f,
                    0xfe,
                    60+len_of_data as u16,
                    2023,			
                    (i* DATA_SLICE_LENTH / 8)as u16,//DF=0,MF=0
                    64,
                    UDP_PROTOCOL,
                    ip_from_u8(192, 168, 31, 1),   
                    ip_from_u8(192, 168, 31, 1),
                    [0;40],
                );
                buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
                buffer.extend(data[i*DATA_SLICE_LENTH..data.len()].to_vec());
                let mut sendqueue=send_queue.lock().unwrap();
                sendqueue.add_data(&buffer);
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
                    UDP_PROTOCOL,
                    ip_from_u8(192, 168, 31, 1),   
                    ip_from_u8(192, 168, 31, 1),
                    [0;40],
                );
                buffer.extend(u8_from_u16(&(hdr.into_u16_array())));
                buffer.extend(data[i*DATA_SLICE_LENTH..(i+1)*DATA_SLICE_LENTH].to_vec());
                let mut sendqueue=send_queue.lock().unwrap();
                sendqueue.add_data(&buffer);
            }
        }//end for
        return true;
    }
}


pub fn send(shared_send_queue:Arc<Mutex<SendQueue>>) {
    let file_path=String::from("data.txt");
    load_ip_data(&file_path,shared_send_queue);
}
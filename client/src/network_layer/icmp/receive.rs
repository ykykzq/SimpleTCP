use std::collections::VecDeque;
use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use lazy_static::*;


lazy_static!{
    ///静态变量--ARP的发送队列
    pub static ref ICMP_RECEIVE_QUEUE:Arc<Mutex<IcmpReceiveQueue>> = Arc::new(Mutex::new(IcmpReceiveQueue::new()));
}

///ARP的接收队列
pub struct IcmpReceiveQueue(
    VecDeque<Vec<u8>>
);

impl IcmpReceiveQueue{
        /// 生成应答报文发送队列
        pub fn new() -> Self{
            let new_send_queue=VecDeque::new();
            IcmpReceiveQueue(new_send_queue)
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

pub struct IcmpHeader{
    icmp_type:[u8;1],
    code:[u8;1],
    check_sum:[u8;2],
    other:[u8;4]
}

impl IcmpHeader {
    /// ### 功能
    /// 计算首部校验和时使用，把首部转化为2字节的数组（30*2）
    pub fn into_u16_array(&self) -> Vec<u16> {
        let mut result:Vec<u16>=Vec::new();
        result.push((self.icmp_type[0] as u16) << 8 | self.code[0] as u16);
        result.push((self.check_sum[0] as u16) << 8 | self.check_sum[1] as u16);
        result.push((self.other[0] as u16)<<8|(self.other[1] as u16));
        result.push((self.other[2] as u16)<<8|(self.other[3] as u16));
        result
    }
    /// ### 功能
    /// 根据所给值生成头部，并自动计算首部校验和
    /// ### 返回值
    /// 计算过首部校验和的头部
    pub fn new (
        icmp_type:u8,
        code:u8,
        other:u32
    )-> IcmpHeader{
        let mut hdr=IcmpHeader{
            icmp_type:[0;1],
            code:[0;1],
            check_sum:[0;2],
            other:[0;4]
        };
        hdr.icmp_type[0]=icmp_type;
        hdr.code[0]=code;
        hdr.other=other.to_be_bytes();
        hdr.check_sum=hdr.calculate_check_sum().to_be_bytes();
        hdr
    }

    pub fn from_vec_u8(v:Vec<u8>)->IcmpHeader{
        let mut hdr=IcmpHeader{
            icmp_type:[0;1],
            code:[0;1],
            check_sum:[0;2],
            other:[0;4]
        };
        hdr.icmp_type[0]=v[0];
        hdr.code[0]=v[1];
        hdr.check_sum=v[2..4].try_into().unwrap();
        hdr.other=v[5..9].try_into().unwrap();
        hdr
    }

    ///###功能
    /// 计算首部校验和
    pub fn calculate_check_sum(&self)-> u16{
        let mut sum:u32=0;
        let len:usize=8;
        let hdr=self.into_u16_array();
    
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
}


pub fn receive(shared_icmp_receive_queue:Arc<Mutex<IcmpReceiveQueue>>){
    loop{
        let mut receive_queue=shared_icmp_receive_queue.lock().unwrap();
        if receive_queue.is_empty(){
            yield_now();
            continue;
        }

        let data=receive_queue.get_data().unwrap();

        let hdr=IcmpHeader::from_vec_u8(data);

        if hdr.icmp_type[0]==11{
            println!("接收到ICMP超时报文！");
        }
        else if hdr.icmp_type[0]==8{
            println!("接收到ICMP回送请求报文！");
        }
        else if  hdr.icmp_type[0]==0 {
            println!("接收到ICMP回送回答报文！");
        }
        
    }
}
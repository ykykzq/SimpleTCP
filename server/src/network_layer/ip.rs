use std::sync::{Arc,Mutex};
use std::thread::yield_now;
use std::io::Write;
use std::fs::File;
use std::collections::VecDeque;
use lazy_static::*;

lazy_static!{
    ///静态变量--IP的接收队列
    pub static ref IP_RECEIVE_QUEUE:Arc<Mutex<IpReceiveQueue>> = Arc::new(Mutex::new(IpReceiveQueue::new()));
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
	source_ip:u32,   
    /// 目的IP地址
    destination_ip:u32,
    /// 40字节的可选部分
	optional:[u8;40],
}

impl IpHeader{
    /// ### 功能
    /// 从一个Vec<u8>的前几位构造一个ip头
    pub fn from_u8(buffer:& Vec<u8>)->Self{
        let result:IpHeader=IpHeader{
            version_and_hdrlen:buffer[0],
            type_of_service:buffer[1],
            total_length:(buffer[2]as u16)<<8| buffer[3] as u16,
            id:(buffer[4]as u16)<<8| buffer[5] as u16,			
            flags_and_fragment_offset:(buffer[6]as u16)<<8| buffer[7] as u16,
            time_to_live:buffer[8],
            upper_protocol_type:buffer[9],
            check_sum:(buffer[10] as u16)<<8| buffer[11] as u16,
            source_ip:(buffer[12] as u32)<<24| (buffer[13] as u32)<<16|(buffer[14] as u32)<<8 | buffer[15] as u32,  
            destination_ip:(buffer[16] as u32)<<24| (buffer[17] as u32)<<16|(buffer[18] as u32)<<8 | buffer[19] as u32,
            optional:buffer[20..60].to_vec().clone().try_into().unwrap(),
        };
        result
    }
}

///接收队列，下层协议交付时写入此结构
pub struct IpReceiveQueue(
    VecDeque<Vec<u8>>
);

impl IpReceiveQueue{
    ///生成接收队列
    pub fn new() -> Self{
        let new_receive_queue=VecDeque::new();
        IpReceiveQueue(new_receive_queue)
    }

    /// ### 功能
    /// data_link层向其中写入数据。
    /// 交付的数据应该在一定长度之间，该函数会检查。
    pub fn add_data(&mut self,buffer: &Vec<u8>) -> bool{
        if buffer.len()>1500 || buffer.len()<46{
            return false;
        }
        self.0.push_back(buffer.clone());
        true
    }
    /// ### 功能
    /// 获取第一个数据
    pub fn get_data(&mut self)-> Option<Vec<u8>>{
        self.0.pop_front()
    }
    
    /// ### 功能
    /// 队列是否为空
    pub fn is_empty(&self)->bool{
        self.0.is_empty()
    }
}


/// 一个队列，其中的元素是id对应的各数据报的缓冲区
/// ### 数据结构
/// 每一个元素包括四部分：数据报id，数据队列，一个用于指示已经接收多少字节的的指针，一个(分片起始位置，分片长度)队列，数据应有的总长度
struct ReceiveDataQueue(
    Vec<(u16,[u8;65536],u32,Vec<(u32,u32)>,u32)>
);
impl ReceiveDataQueue {
    /// ### 功能
    /// 根据id找到对应的缓冲区
    pub fn find(&mut self,id:u16)->Option<&mut (u16,[u8;65536],u32,Vec<(u32,u32)>,u32)>{
        for i in &mut self.0{
            if i.0==id{
                return Some(i);
            }
        }
        return None;
    }
    /// ###功能
    /// 根据id，找到对应的该id的缓冲区，并插入数据到指定位置
    /// ### 返回值
    /// 是否完成一个数据报
    pub fn insert_data(&mut self,id:u16,data:Vec<u8>,offset:u16,len:u16,MF:bool,DF:bool)->bool{
        let element=self.find(id).unwrap();

        //单位换算为字节
        let offset=offset*8;
        //插入数据
        element.1[offset as usize..(offset+len) as usize].copy_from_slice(data.as_slice());

        //插入下标组
        let mut flag=false;
        for i in &element.3{
            //检查是否存在该分片
            if i.0==offset as u32{
                flag=true;
                break;
            }
        }
        if flag==false{
            //不存在该分片
            element.3.push((offset.into(),len.into()));
        }
        //维护指针，每次都重新计算
        while find_receive_data_queue_len(&element.3,element.2).is_some() {
            element.2+=find_receive_data_queue_len(&element.3,element.2).unwrap();
        }
        //维护该数据报应有的数据长度
        if (DF==true)|(DF==false&&MF==false){
            element.4=(offset+len).into();
        }
        element.2==element.4
    }
    /// ###功能
    /// 创建一个与id对应的缓冲区，用于接收IP分组
    /// ### 返回值
    /// 是否完成一个数据报
    pub fn create_new(&mut self,id:u16,data:Vec<u8>,offset:u16,len:u16,MF:bool,DF:bool)->bool{
        let mut element:  (u16, [u8; 65536], u32, Vec<(u32, u32)>,u32)=(
            0,
            [0;65536],
            0,
            Vec::new(),
            65535
        );
        element.0=id;
        //插入数据
        element.1[offset as usize..(offset+len) as usize].copy_from_slice(data.as_slice());

        //插入下标组
        //一定不存在该分片
        element.3.push((offset.into(),len.into()));
        
        //维护指针
        while find_receive_data_queue_len(&element.3,element.2).is_some() {
            element.2+=find_receive_data_queue_len(&element.3,element.2).unwrap();
        }
        //维护该数据报应有的数据长度
        if (DF==true)|(DF==false&&MF==false){
            element.4=(offset+len).into();
        }
        let flag=element.2==element.4;//返回值。如果当前长度等于总长度，则代表数据报已经接收完整。
        self.0.push(element);
        flag
    }

    /// ###功能
    /// 删除一个与id对应的缓冲区
    /// ### 返回值
    /// 是否删除成功
    pub fn delete_element(&mut self,id:u16)-> bool{
        let mut index=0;
        for i in &mut self.0{
            if i.0==id{
                self.0.remove(index);
                return true;
            }
            index=index+1;
        }
        false
    }
}

/// ###功能
/// 从(分片起始位置，分片长度)队列中找到起始位置对应的分片长度
pub fn find_receive_data_queue_len(vec:&Vec<(u32,u32)>,current_ptr:u32)->Option<u32>{
    for i in vec{
        if i.0==current_ptr{
            return Some(i.1);
        }
    }
    None
}

pub fn receive(shared_ip_receive_queue:Arc<Mutex<IpReceiveQueue>>) {
    let mut receive_data_queue:ReceiveDataQueue=ReceiveDataQueue(Vec::new());
    loop{
        // 队列为空则直接跳过
        if shared_ip_receive_queue.lock().unwrap().is_empty(){
            yield_now();
            //因为下面代码在else块里，所以无需continue;
        }
        else {
        // 对于每一个分组，根据id判断其所属的数据报。
        // 如果为新的，则新建一个缓冲区存放
        // 如果为旧的，跟已有的拼接，如果拼接为完整，则写入。
            // 获取并解析
            let data_from_data_link_layer=shared_ip_receive_queue.lock().unwrap().get_data().unwrap();
            if data_from_data_link_layer.len()<60{
                //小于60，肯定不是一个IP数据分组
                yield_now();
                continue;
            }
            let hdr=IpHeader::from_u8( & data_from_data_link_layer);

            //查询是否在接收这个id
            let flag_exists:bool=receive_data_queue.find(hdr.id).is_some();
            

            let complete_flag;
            if flag_exists{
                //如果是已经接收过这个分组
                complete_flag=receive_data_queue.insert_data(
                    hdr.id,
                    data_from_data_link_layer[60..data_from_data_link_layer.len()].to_vec(), 
                    hdr.flags_and_fragment_offset & 0b0001_1111_1111_1111, 
                    hdr.total_length-60,
                    (hdr.flags_and_fragment_offset&(1<<13))==(1<<13),
                    (hdr.flags_and_fragment_offset&(1<<14))==(1<<14)
                );
            }
            else {
                //如果是新的分组
                complete_flag=receive_data_queue.create_new(
                    hdr.id,
                    data_from_data_link_layer[60..data_from_data_link_layer.len()].to_vec(), 
                    hdr.flags_and_fragment_offset & 0b0001_1111_1111_1111, 
                    hdr.total_length-60,
                    (hdr.flags_and_fragment_offset&(1<<13))==(1<<13),
                    (hdr.flags_and_fragment_offset&(1<<14))==(1<<14)
                );
                //如果是新分组，那么肯定是没有间隙的数据
                
            }
            if complete_flag{//如果接收完该分组后数据报完整，则写入到文件中
                let id;
                {//大括号是为了通过编译......不得不如此
                    //打开文件
                    let file_path=String::from("receive.data");
                    let mut file=File::create(file_path).unwrap();
                    //写入文件
                    let element=receive_data_queue.find(hdr.id).unwrap();
                    let data=&element.1[0..element.4 as usize];
                    file.write_all(data).unwrap();

                    id=element.0;
                }
                
                {//......不然无法绕开rust的所有权机制的限制
                    //将已经完成的缓冲区从receive_data_queue中删除
                    receive_data_queue.delete_element(id);
                }
                
            }
        }
    }
}


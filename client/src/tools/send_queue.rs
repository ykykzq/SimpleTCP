use std::collections::VecDeque;
pub struct SendQueue(
    VecDeque<Vec<u8>>
);

impl SendQueue{
    ///生成发送队列
    pub fn new() -> Self{
        let new_send_queue=VecDeque::new();
        SendQueue(new_send_queue)
    }
    /// netwrok向其中写入数据。
    /// 注意分片的工作由network层负责。
    /// newwork层保证数据长度在46与1500之间，该函数中会检查。
    pub fn add_data(&mut self,buffer: &Vec<u8>) -> bool{
        if buffer.len()>1500 || buffer.len()<46{
            return false;
        }
        self.0.push_back(buffer.clone());
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

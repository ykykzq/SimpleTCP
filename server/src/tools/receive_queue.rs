use std::collections::VecDeque;
pub struct ReceiveQueue(
    VecDeque<Vec<u8>>
);

impl ReceiveQueue{
    ///生成接收队列
    pub fn new() -> Self{
        let new_receive_queue=VecDeque::new();
        ReceiveQueue(new_receive_queue)
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

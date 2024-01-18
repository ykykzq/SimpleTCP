use lazy_static::*;
use std::sync::{Arc,Mutex};

use super::send::ARP_SEND_REQUEST_QUEUE;

lazy_static!{
    //静态变量--ARP缓存表
    pub static ref ARP_CACHE_TABLE:Arc<Mutex<ArpCacheTable>> = Arc::new(Mutex::new(ArpCacheTable::new()));
}

/// ARP缓存表的表项
pub struct ArpCacheEntry{
    ip:[u8;4],
    mac:[u8;6],
    /// 1:静态 2:动态 3: log
    state:u8
}
impl ArpCacheEntry{
    /// ### 功能
    /// 新建一个缓存表项
    pub fn new(in_ip:[u8;4],in_mac:[u8;6],in_state:u8)->ArpCacheEntry{
        ArpCacheEntry{
            ip:in_ip,
            mac:in_mac,
            state:in_state
        }
    }
}

/// ##ARP表
/// ###容量
/// 可变
pub struct  ArpCacheTable{
    inner:Vec<ArpCacheEntry>
}

impl ArpCacheTable{
    /// ### 功能
    /// 新建一个缓存表
    pub fn new()->ArpCacheTable{
        let v:Vec<ArpCacheEntry>=Vec::new();
        ArpCacheTable{
            inner:v
        }
    }
    /// ### 功能
    /// 插入一个表项，必须保证不存在该ip地址对应表项
    /// ### 返回值
    /// 是否插入成功
    /// ### 备注
    /// 如果已经存在该ip地址对应表项，请使用update函数
    pub fn insert_entry(&mut self,element:ArpCacheEntry)-> bool{
        //如果已经存在此项，则不插入，而是更新已有节点
        if self.is_existed_ip(element.ip) {
            return false;
        }
        //不存在此项则插入
        self.inner.push(element);
        true
    }
    /// ### 功能
    /// 删除某一个表项
    /// ### 返回值
    /// 是否删除成功
    pub fn delete_entry(&mut self,element:ArpCacheEntry)-> bool{
        let mut index=0;
        for old in &mut self.inner{
            if old.ip==element.ip && old.mac==element.mac{
                self.inner.remove(index);
                return true;
            }
            index+=1;
        }
        false
    }
    /// ### 功能
    /// 缓存表中是否存在此IP地址
    /// ### 返回值
    /// 是否存在
    pub fn is_existed_ip(&self,ip:[u8;4])->bool{
        for old in  &self.inner{
            if old.ip==ip{
                return true;
            }
        }
        false
    }
    /// ### 功能
    /// 更新某个IP地址对应表项的MAC地址与状态
    /// ### 返回值
    /// 是否更新成功（不存在则无法更新）
    pub fn update_entry(&mut self,element:ArpCacheEntry)->bool{
        for old in &mut self.inner{
            if old.ip==element.ip{
                old.mac=element.mac;
                old.state=element.state;
                return true;
            }
        }
        false
    }
    /// ### 功能
    /// 根据IP寻找MAC地址
    /// ### 返回值
    /// Option，成功找到则返回mac地址
    pub fn find_mac_from_ip(&self,ip:[u8;4])->Option<[u8;6]>{
        for element in  &self.inner{
            if element.ip==ip{
                return Some(element.mac);
            }
        }

        //如果没找到，则应当向arp发送队列中写入数据，以获取对应的mac
        ARP_SEND_REQUEST_QUEUE.lock().unwrap().add_data(ip);
        None
    }
}
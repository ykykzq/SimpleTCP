mod data_link_layer;
mod network_layer;
mod tools;

use std::sync::Arc;
use std::thread;


use network_layer::arp::send::{ARP_SEND_REPLY_QUEUE, ARP_SEND_REQUEST_QUEUE};

use crate::data_link_layer::ethernet_v2::send::ETHERNET_V2_SEND_QUEUE;

use crate::network_layer::arp::cache_table::ARP_CACHE_TABLE;
use crate::network_layer::arp::receive::ARP_RECEIVE_QUEUE;



fn main() {
    //运行数据链路层-EthernetV2
    let eth2_send_handle = thread::spawn(move || {
        //EthernetV2协议-发送
        data_link_layer::ethernet_v2::send::send(
            Arc::clone(&ETHERNET_V2_SEND_QUEUE)
        );
    });

    let eth2_receive_handle = thread::spawn(move || {
        //EthernetV2协议-接收
        data_link_layer::ethernet_v2::receive::receive(
            Arc::clone(&ARP_RECEIVE_QUEUE));
    });

    //运行网络层
    let ip_send_handle = thread::spawn(move || {
        //ip协议-发送
        network_layer::ip::send(
            Arc::clone(&ARP_CACHE_TABLE),
            Arc::clone(&ETHERNET_V2_SEND_QUEUE));
    });

    let arp_send_handle = thread::spawn(move || {
        //arp协议-发送
        network_layer::arp::send::send(
            Arc::clone(&ETHERNET_V2_SEND_QUEUE),
            Arc::clone(&ARP_SEND_REPLY_QUEUE),
            Arc::clone(&ARP_SEND_REQUEST_QUEUE));
    });
    let arp_receive_handle = thread::spawn(move || {
        //arp协议-接收
        network_layer::arp::receive::receive(
            Arc::clone(&ARP_CACHE_TABLE),
            Arc::clone(&ARP_RECEIVE_QUEUE));
    });

    eth2_send_handle.join().unwrap();
    eth2_receive_handle.join().unwrap();
    ip_send_handle.join().unwrap();
    arp_send_handle.join().unwrap();
    arp_receive_handle.join().unwrap();
}

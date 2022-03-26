/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** 定义常量数据  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
//定义ARP报文头
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t  send_MAC_Addr;//发送方mac地址
    ip4Addr_t  send_IP_Addr;//发送方ip地址
    macAddr_t  receive_MAC_Addr;//接收方mac地址
    ip4Addr_t  receive_IP_Addr;//接收方ip地址
}

struct metadata {
    ip4Addr_t  dst_ipv4;//元数据：接收方IP地址
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition Parser_E;
    }
    
    state Parser_E{
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: Parser_IPV4;
            TYPE_ARP : Parser_arp;//如果为arp则需要再提取arp报文头
            default: accept;
        }
}

    state Parser_IPV4{
    packet.extract(hdr.ipv4);
    transition accept;
        }
    //提取arp包头
    state Parser_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.receive_IP_Addr;
        transition accept;
    }     
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

action send_arp_reply(macAddr_t macAddr, ip4Addr_t IPAddr) {
        hdr.ethernet.dstAddr = hdr.arp.send_MAC_Addr;
        hdr.ethernet.srcAddr = macAddr;
        hdr.arp.oper         = ARP_OPER_REPLY;// 设置ARP报文类型为回应类型
        // 设置ARP返回内容
        hdr.arp.receive_MAC_Addr  = hdr.arp.send_MAC_Addr;
        hdr.arp.receive_IP_Addr  = hdr.arp.send_IP_Addr;
        hdr.arp.send_MAC_Addr    = macAddr;
        hdr.arp.send_IP_Addr    = IPAddr;
        // 从入端口转发出去
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    table arp_ternary {
        key = {
            hdr.arp.oper : exact;
            hdr.arp.receive_IP_Addr : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4)
        ipv4_lpm.apply();
    //增加arp响应
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_ternary.apply();
    }
}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);//发送ip数据包头   
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

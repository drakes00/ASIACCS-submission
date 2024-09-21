#SCENARIO: here we are in the normal function of SDNsec with PVF verification

import struct
import hmac
import hashlib
import scapy
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from scapy.all import Packet, Ether, sendp
from scapy.fields import ByteField, BitField, ShortField, IntField, LongField, StrFixedLenField, X3BytesField
from ryu.lib.packet.packet_base import PacketBase
from ryu.lib.packet import packet_utils


def compute_hmac_pvf(data, key):
    data=data.encode('utf_8')
    hmac_result = hmac.new(key,data,hashlib.sha256).digest() 
    return hmac_result[:8]

def compute_hmac_fe(data, key):
    data=data.encode('utf_8')
    hmac_result = hmac.new(key,data,hashlib.sha256).digest() 
    return hmac_result[:7]
    
    
class CustomHeader(PacketBase):
    _PACK_STR = '!BBI3sH3sQB7sB7s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    _TYPE = 0x88B6

    def __init__(self, pkt_type, fe_ptr, exp_time, flow_id, egress_switch_id, seq_no, pvf, egress_s1, hmac_s1, egress_s2, hmac_s2):
        self.pkt_type = pkt_type
        self.fe_ptr = fe_ptr
        self.exp_time = exp_time
        self.flow_id = flow_id if isinstance(flow_id, bytes) else flow_id.to_bytes(3, 'big')
        self.egress_switch_id = egress_switch_id
        self.seq_no = seq_no if isinstance(seq_no, bytes) else seq_no.to_bytes(3, 'big')
        self.pvf = pvf if isinstance(pvf, bytes) else pvf.to_bytes(8, 'big')
        self.egress_s1 = egress_s1
        self.hmac_s1 = hmac_s1 if isinstance(hmac_s1, bytes) else bytes(hmac_s1)
        self.egress_s2 = egress_s2
        self.hmac_s2 = hmac_s2 if isinstance(hmac_s2, bytes) else bytes(hmac_s2)

    def pack(self):
        return struct.pack(self._PACK_STR, self.pkt_type, self.fe_ptr, self.exp_time, self.flow_id, self.egress_switch_id,
                           self.seq_no, self.pvf, self.egress_s1, self.hmac_s1, self.egress_s2, self.hmac_s2)

    @classmethod
    def parser(cls, buf):
        if len(buf) < cls._MIN_LEN:
            return None, None
        unpacked_data = struct.unpack_from(cls._PACK_STR, buf)
        return cls(*unpacked_data), buf[cls._MIN_LEN:]
        
    def update_seq_no(self,new_seq_no):
        self.seq_no=new_seq_no.to_bytes(3,byteorder='big')
    
    def update_pvf(self,new_pvf):
        self.pvf=new_pvf




class SimpleController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SimpleController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.keys = {
            1: b'key_s0',
            2: b'key_s1',
            3: b'key_s2'}
        self.expected_pvf = {1: 8019800615180990830, 2: 17452890129398687322, 3: 5966870284584239409}
        self.calculated_pvf = {}       

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        custom_header = pkt.get_protocol(CustomHeader)
        data = msg.data
        dpid = dp.id
        # Ethernet header extraction
        dst_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[0:6]))
        src_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[6:12]))
        ethertype = struct.unpack('!H', data[12:14])[0]
        if ethertype == 0x88B6 :
            if dpid == 1: #s0
                print("\033[92m********PACKET RECEIVED BY S0**********\033[0m")
                print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                print(f"\033[94mSource MAC:\033[0m {src_mac}")
                print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                
                custom_pack_str = '!BBI3sH3sQB7sB7s'
                custom_header_data = data[14:52]
                payload = data[52:]
                
                # Unpack the custom header data
                custom_header = struct.unpack(custom_pack_str, custom_header_data)

                pkt_type = custom_header[0]
                fe_ptr = custom_header[1]
                exp_time = custom_header[2]
                flow_id = int.from_bytes(custom_header[3], byteorder='big')
                egress_switch_id = custom_header[4]
                seq_no = int.from_bytes(custom_header[5], byteorder='big')
                pvf = custom_header[6]
                egress_s1 = custom_header[7]
                hmac_s1 = custom_header[8]
                egress_s2 = custom_header[9]
                hmac_s2 = custom_header[10]

                print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                print(f"\033[94mFlow ID:\033[0m {flow_id}")
                print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                print(f"\033[94mSequence Number:\033[0m {seq_no}")
                print(f"\033[94mPVF_initial:\033[0m {pvf}")
                print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                print(f"\033[94mpayload:\033[0m {payload}")
                
                
                custom_header=CustomHeader.parser(custom_header_data)[0]
                custom_header.update_seq_no(1)
                FE_s0 =str(custom_header.flow_id)+str(custom_header.exp_time)
                c =str(custom_header.flow_id)+str(custom_header.seq_no)
                pvf_s0=compute_hmac_pvf(c,self.keys[dpid])
                self.calculated_pvf[dpid]=int.from_bytes(pvf_s0,'big')
                custom_header.update_pvf(pvf_s0) 
                     
                updated_header_bytes = struct.pack(
                    '!BBI3sH3sQB7sB7s',
                    int(custom_header.pkt_type),
                    int(custom_header.fe_ptr),
                    int(custom_header.exp_time),
                    custom_header.flow_id,  
                    int(custom_header.egress_switch_id),
                    custom_header.seq_no,  
                    int(custom_header.pvf) if isinstance(custom_header.pvf, int) else int.from_bytes(custom_header.pvf, 'big'),  
                    int(custom_header.egress_s1),
                    custom_header.hmac_s1 if isinstance(custom_header.hmac_s1, bytes) else bytes.fromhex(custom_header.hmac_s1),
                    int(custom_header.egress_s2),
                    custom_header.hmac_s2 if isinstance(custom_header.hmac_s2, bytes) else bytes.fromhex(custom_header.hmac_s2)
                    )                
                eth_header = struct.pack('!6s6sH', bytes.fromhex(eth_pkt.dst.replace(':','')), bytes.fromhex(eth_pkt.src.replace(':','')),eth_pkt.ethertype)
                new_packet_data = eth_header + updated_header_bytes + payload
                egress_s0=2
               

                # Forward the updated packet
                self.forward_packet(dp, msg, new_packet_data, egress_s0)
                print("\033[92m********PACKET SENT BY S0**********\033[0m")
                print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                print(f"\033[94mSource MAC:\033[0m {src_mac}")
                print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                
                custom_pack_str = '!BBI3sH3sQB7sB7s'
                custom_header_data = new_packet_data[14:52]
                payload = new_packet_data[52:]
                

                # Unpack the custom header data
                custom_header = struct.unpack(custom_pack_str, custom_header_data)

                pkt_type = custom_header[0]
                fe_ptr = custom_header[1]
                exp_time = custom_header[2]
                flow_id = int.from_bytes(custom_header[3], byteorder='big')
                egress_switch_id = custom_header[4]
                seq_no = int.from_bytes(custom_header[5], byteorder='big')
                pvf_s0 = custom_header[6]
                egress_s1 = custom_header[7]
                hmac_s1 = custom_header[8]
                egress_s2 = custom_header[9]
                hmac_s2 = custom_header[10]

                print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                print(f"\033[94mFlow ID:\033[0m {flow_id}")
                print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                print(f"\033[94mSequence Number:\033[0m {seq_no}")
                print(f"\033[94mPVF_s1:\033[0m {pvf_s0}")
                print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                print(f"\033[94mpayload:\033[0m {payload}")
          
            elif dpid==2:
                msg = ev.msg
                dp = msg.datapath
                pkt = packet.Packet(msg.data)
                eth_pkt = pkt.get_protocol(ethernet.ethernet)
                custom_header = pkt.get_protocol(CustomHeader)
                data = msg.data
                dpid = dp.id
                # Ethernet header extraction
                dst_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[0:6]))
                src_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[6:12]))
                ethertype = struct.unpack('!H', data[12:14])[0]
                if ethertype == 0x88B6 :
                    print("\033[92m********PACKET RECEIVED BY S1**********\033[0m")
                    print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                    print(f"\033[94mSource MAC:\033[0m {src_mac}")
                    print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                    
                    custom_pack_str = '!BBI3sH3sQB7sB7s'
                    custom_header_data = data[14:52]
                    payload = data[52:]
                

                    # Unpack the custom header data
                    custom_header = struct.unpack(custom_pack_str, custom_header_data)

                    pkt_type = custom_header[0]
                    fe_ptr = custom_header[1]
                    exp_time = custom_header[2]
                    flow_id = int.from_bytes(custom_header[3], byteorder='big')
                    egress_switch_id = custom_header[4]
                    seq_no = int.from_bytes(custom_header[5], byteorder='big')
                    pvf_s0 = custom_header[6]
                    egress_s1 = custom_header[7]
                    hmac_s1 = custom_header[8]
                    egress_s2 = custom_header[9]
                    hmac_s2 = custom_header[10]

                    print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                    print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                    print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                    print(f"\033[94mFlow ID:\033[0m {flow_id}")
                    print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                    print(f"\033[94mSequence Number:\033[0m {seq_no}")
                    print(f"\033[94mPVF_s0:\033[0m {pvf_s0}")
                    print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                    print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                    print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                    print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                    print(f"\033[94mpayload:\033[0m {payload}")
                    
                    custom_header=CustomHeader.parser(custom_header_data)[0]    
                    FE_s0 =str(custom_header.flow_id)+str(custom_header.exp_time)
                    c =str(custom_header.flow_id)+str(custom_header.seq_no)
                    FE_s1=str(egress_s1)+str(hmac_s1)
                    x = str(egress_s1)+FE_s0+str(custom_header.flow_id)+str(custom_header.exp_time)
                    hmac_s1_calculated_by_s1=compute_hmac_fe(x,self.keys[dpid])
                    if hmac_s1 == hmac_s1_calculated_by_s1 :
                        y = str(pvf_s0)+c
                        pvf_s1=compute_hmac_pvf(y,self.keys[dpid])
                        self.calculated_pvf[dpid]=int.from_bytes(pvf_s1,'big')
                        custom_header.update_pvf(pvf_s1)
                        custom_header.update_seq_no(2) 
                             
                        updated_header_bytes = struct.pack(
                            '!BBI3sH3sQB7sB7s',
                            int(custom_header.pkt_type),
                            int(custom_header.fe_ptr),
                            int(custom_header.exp_time),
                            custom_header.flow_id,  
                            int(custom_header.egress_switch_id),
                            custom_header.seq_no,  
                            int(custom_header.pvf) if isinstance(custom_header.pvf, int) else int.from_bytes(custom_header.pvf, 'big'),  
                            int(custom_header.egress_s1),
                            custom_header.hmac_s1 if isinstance(custom_header.hmac_s1, bytes) else bytes.fromhex(custom_header.hmac_s1),
                            int(custom_header.egress_s2),
                            custom_header.hmac_s2 if isinstance(custom_header.hmac_s2, bytes) else bytes.fromhex(custom_header.hmac_s2)
                            )                
                        eth_header = struct.pack('!6s6sH', bytes.fromhex(eth_pkt.dst.replace(':','')), bytes.fromhex(eth_pkt.src.replace(':','')),eth_pkt.ethertype)
                        new_packet_data = eth_header + updated_header_bytes + payload
                       

                        # Forward the updated packet
                        self.forward_packet(dp, msg, new_packet_data, egress_s1)

                        print("\033[92m********PACKET SENT BY S1**********\033[0m")
                        print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                        print(f"\033[94mSource MAC:\033[0m {src_mac}")
                        print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                        
                        custom_pack_str = '!BBI3sH3sQB7sB7s'
                        custom_header_data = new_packet_data[14:52]
                        payload = new_packet_data[52:]
                        

                        # Unpack the custom header data
                        custom_header = struct.unpack(custom_pack_str, custom_header_data)

                        pkt_type = custom_header[0]
                        fe_ptr = custom_header[1]
                        exp_time = custom_header[2]
                        flow_id = int.from_bytes(custom_header[3], byteorder='big')
                        egress_switch_id = custom_header[4]
                        seq_no = int.from_bytes(custom_header[5], byteorder='big')
                        pvf_s0 = custom_header[6]
                        egress_s1 = custom_header[7]
                        hmac_s1 = custom_header[8]
                        egress_s2 = custom_header[9]
                        hmac_s2 = custom_header[10]

                        print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                        print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                        print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                        print(f"\033[94mFlow ID:\033[0m {flow_id}")
                        print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                        print(f"\033[94mSequence Number:\033[0m {seq_no}")
                        print(f"\033[94mPVF_s1:\033[0m {pvf_s0}")
                        print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                        print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                        print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                        print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                        print(f"\033[94mpayload:\033[0m {payload}")
                    else:
                        print("HEY CONTROLLER, HMAC INVALID !!")
            elif dpid==3:
                msg = ev.msg
                dp = msg.datapath
                pkt = packet.Packet(msg.data)
                eth_pkt = pkt.get_protocol(ethernet.ethernet)
                custom_header = pkt.get_protocol(CustomHeader)
                data = msg.data
                dpid = dp.id
                # Ethernet header extraction
                dst_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[0:6]))
                src_mac = ':'.join(format(x, '02x') for x in struct.unpack('!6B', data[6:12]))
                ethertype = struct.unpack('!H', data[12:14])[0]
                if ethertype == 0x88B6 :
                    print("\033[92m********PACKET RECEIVED BY S2**********\033[0m")
                    print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                    print(f"\033[94mSource MAC:\033[0m {src_mac}")
                    print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                    
                    custom_pack_str = '!BBI3sH3sQB7sB7s'
                    custom_header_data = data[14:52]
                    payload = data[52:]
                    

                    # Unpack the custom header data
                    custom_header = struct.unpack(custom_pack_str, custom_header_data)

                    pkt_type = custom_header[0]
                    fe_ptr = custom_header[1]
                    exp_time = custom_header[2]
                    flow_id = int.from_bytes(custom_header[3], byteorder='big')
                    egress_switch_id = custom_header[4]
                    seq_no = int.from_bytes(custom_header[5], byteorder='big')
                    pvf_s1 = custom_header[6]
                    egress_s1 = custom_header[7]
                    hmac_s1 = custom_header[8]
                    egress_s2 = custom_header[9]
                    hmac_s2 = custom_header[10]

                    print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                    print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                    print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                    print(f"\033[94mFlow ID:\033[0m {flow_id}")
                    print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                    print(f"\033[94mSequence Number:\033[0m {seq_no}")
                    print(f"\033[94mPVF_s1:\033[0m {pvf_s1}")
                    print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                    print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                    print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                    print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                    print(f"\033[94mpayload:\033[0m {payload}")
                    custom_header=CustomHeader.parser(custom_header_data)[0]    
                    FE_s0 =str(custom_header.flow_id)+str(custom_header.exp_time)
                    c =str(custom_header.flow_id)+str(custom_header.seq_no)
                    FE_s1=str(egress_s1)+str(hmac_s1)
                    x = str(egress_s2)+FE_s1+str(custom_header.flow_id)+str(custom_header.exp_time)
                    hmac_s2_calculated_by_s2=compute_hmac_fe(x,self.keys[dpid])
                    
                    if hmac_s2 == hmac_s2_calculated_by_s2 :
                        y = str(pvf_s1)+c
                        pvf_s2=compute_hmac_pvf(y,self.keys[dpid])
                        self.calculated_pvf[dpid]= int.from_bytes(pvf_s2,'big')
                        custom_header.update_pvf(pvf_s2)
                        custom_header.update_seq_no(3) 
                             
                        updated_header_bytes = struct.pack(
                            '!BBI3sH3sQB7sB7s',
                            int(custom_header.pkt_type),
                            int(custom_header.fe_ptr),
                            int(custom_header.exp_time),
                            custom_header.flow_id,  
                            int(custom_header.egress_switch_id),
                            custom_header.seq_no,  
                            int(custom_header.pvf) if isinstance(custom_header.pvf, int) else int.from_bytes(custom_header.pvf, 'big'),  
                            int(custom_header.egress_s1),
                            custom_header.hmac_s1 if isinstance(custom_header.hmac_s1, bytes) else bytes.fromhex(custom_header.hmac_s1),
                            int(custom_header.egress_s2),
                            custom_header.hmac_s2 if isinstance(custom_header.hmac_s2, bytes) else bytes.fromhex(custom_header.hmac_s2)
                            )                
                        eth_header = struct.pack('!6s6sH', bytes.fromhex(eth_pkt.dst.replace(':','')), bytes.fromhex(eth_pkt.src.replace(':','')),eth_pkt.ethertype)
                        new_packet_data = eth_header + updated_header_bytes + payload
                        self.forward_packet(dp, msg, new_packet_data, egress_s2)
                        
                        print("\033[92m********PACKET SENT BY S2**********\033[0m")
                        print(f"\033[94mDestination MAC:\033[0m {dst_mac}")
                        print(f"\033[94mSource MAC:\033[0m {src_mac}")
                        print(f"\033[94mEthertype:\033[0m {hex(ethertype)}")

                        
                        custom_pack_str = '!BBI3sH3sQB7sB7s'
                        custom_header_data = new_packet_data[14:52]
                        payload = data[52:]
            

                        # Unpack the custom header data
                        custom_header = struct.unpack(custom_pack_str, custom_header_data)

                        pkt_type = custom_header[0]
                        fe_ptr = custom_header[1]
                        exp_time = custom_header[2]
                        flow_id = int.from_bytes(custom_header[3], byteorder='big')
                        egress_switch_id = custom_header[4]
                        seq_no = int.from_bytes(custom_header[5], byteorder='big')
                        pvf_s2 = custom_header[6]
                        egress_s1 = custom_header[7]
                        hmac_s1 = custom_header[8]
                        egress_s2 = custom_header[9]
                        hmac_s2 = custom_header[10]

                        print(f"\033[94mPacket Type:\033[0m {pkt_type}")
                        print(f"\033[94mFE Pointer:\033[0m {fe_ptr}")
                        print(f"\033[94mExpiration Time:\033[0m {exp_time}")
                        print(f"\033[94mFlow ID:\033[0m {flow_id}")
                        print(f"\033[94mEgress Switch ID:\033[0m {egress_switch_id}")
                        print(f"\033[94mSequence Number:\033[0m {seq_no}")
                        print(f"\033[94mPVF_s2:\033[0m {pvf_s2}")
                        print(f"\033[94mEgress S1:\033[0m {egress_s1}")
                        print(f"\033[94mHMAC S1:\033[0m {hmac_s1}")
                        print(f"\033[94mEgress S2:\033[0m {egress_s2}")
                        print(f"\033[94mHMAC S2:\033[0m {hmac_s2}")
                        print(f"\033[94mpayload:\033[0m {payload}")
                        self.compare_pvf(dpid)
                    
                    else:    
                        print("HEY CONTROLLER, HMAC INVALID !!")
                                   
            else:
                print("dpid not known")  
                          
        
        
    def forward_packet(self, datapath, msg, new_packet_data, out_port):
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match['in_port'],
            actions=actions, data=new_packet_data if msg.buffer_id == ofproto_v1_3.OFP_NO_BUFFER else None)
        datapath.send_msg(out)
        return 
    
    def compare_pvf(self,dpid):
        expected_pvf=self.expected_pvf.get(dpid)
        calculated_pvf=self.calculated_pvf.get(dpid)
        print("\033[95m**********PVF VERIFICATION***********\033[0m")
        if dpid == 3:
            if expected_pvf == calculated_pvf :
                print("\033[95mExpected PVFs\033[0m",self.expected_pvf)
                print("\033[95mReceived PVFs\033[0m",self.calculated_pvf)
                print("\033[92mAll PVF values are VALID ✓\033[0m")
            else:
                print("\033[31mWARNING !! The PVF values do not match")
                if self.expected_pvf.get(1) != self.calculated_pvf.get(1):
                    print("\033[95mExpected PVFs\033[0m",self.expected_pvf)
                    print("\033[95mReceived PVFs\033[0m",self.calculated_pvf)
                    print("\033[31mThe switch with datapath ID = 1 (S0) is suspicious!\033[0m")
                elif (self.expected_pvf.get(1) == self.calculated_pvf.get(1)) and (self.expected_pvf.get(2) != self.calculated_pvf.get(2)):
                    print("\033[95mExpected PVFs\033[0m",self.expected_pvf)
                    print("\033[95mReceived  PVFs\033[0m",self.calculated_pvf)
                    print("\033[31mThe switch with datapath ID = 2 (S1) is suspicious!\033[0m")
                elif (self.expected_pvf.get(1) == self.calculated_pvf.get(1)) and (self.expected_pvf.get(2) == self.calculated_pvf.get(2)) and (self.expected_pvf.get(3) != self.calculated_pvf.get(3)):
                    print("\033[95mExpected PVFs\033[0m",self.expected_pvf)
                    print("\033[95mReceived  PVFs\033[0m",self.calculated_pvf)
                    print("\033[31mThe switch with datapath ID = 3 (S2) is suspicious!\033[0m")    
        else:
            print("datapath ID not known")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dp = ev.msg.datapath
        dpid=dp.id
        self.mac_to_port.setdefault(datapath.id, {})

        # Add flow for custom EtherType packets.
        match = parser.OFPMatch(eth_type=0x88B6)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 100, match, actions)
        
        #if dpid == 1 or dpid == 2:
         #   actions = [parser.OFPActionOutput(2)]
         #   self.add_flow(datapath, 200, match, actions)
        #elif dpid == 3:
         #   actions = [parser.OFPActionOutput(3)]
          #  self.add_flow(datapath, 100, match, actions)
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
     

        

#The initial packet sent to the ingress switch S0

from scapy.all import Ether, sendp, Packet
from scapy.fields import ByteField, X3BytesField, ShortField, IntField, LongField, StrFixedLenField

class CustomHeader(Packet):
    name = "CustomHeader"
    fields_desc = [
        ByteField("pkt_type", 0),
        ByteField("fe_ptr", 0),
        IntField("exp_time", 0),
        X3BytesField("flow_id", 0),
        ShortField("egress_switch_id", 0),
        X3BytesField("seq_no", 0),
        LongField("pvf", 0),
        ByteField("egress_s1", 0),
        StrFixedLenField("hmac_s1", b'\x00' * 7, 7),
        ByteField("egress_s2", 0),
        StrFixedLenField("hmac_s2", b'\x00' * 7, 7)
    ]

def make_custom_packet(src_mac, dst_mac, ether_type=0x88B6):
    custom_header = CustomHeader(
        pkt_type=1,
        fe_ptr=0,
        exp_time=15,
        flow_id=0x001,
        egress_switch_id=1,
        seq_no=0x0,
        pvf=0x00,
        egress_s1=2,
        hmac_s1=b'\x1f\x13\x1f\xb1\x9a\x89Q',
        egress_s2=2,
        hmac_s2=b'\x7f\xc2\xaf\xfc\xce\n\x8d'

    )
    ether = Ether(src=src_mac, dst=dst_mac, type=ether_type)
    payload = (b'L3 Data' * 99)[:798]  #the average of packet size is 850 bytes in data centers based on the paper.
    return ether / custom_header / payload

# Construct and send the packet
custom_packet = make_custom_packet("00:00:00:00:00:01", "00:00:00:00:00:02")
sendp(custom_packet, iface='h1-eth0')

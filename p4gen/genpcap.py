import logging
import random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet, bind_layers
from scapy.utils import wrpcap
from p4gen.ptp_base import *

#bind_layers(UDP, PTP, dport=319)
#bind_layers(Ether, PTP, type=0x88F7)

bind_layers(UDP, PTP,                dport=319)
bind_layers(UDP, Sync,               dport=319)
bind_layers(UDP, DelayReq,           dport=319)
bind_layers(UDP, PdelayReq,          dport=319)
bind_layers(UDP, PdelayResp,         dport=319)
bind_layers(UDP, FollowUp,           dport=319)
bind_layers(UDP, DelayResp,          dport=319)
bind_layers(UDP, PdelayRespFollowUp, dport=319)

#bind_layers(Ether, PTP,                type=0x88F7)
#bind_layers(Ether, Sync,               type=0x88F7)
#bind_layers(Ether, DelayReq,           type=0x88F7)
#bind_layers(Ether, PdelayReq,          type=0x88F7)
#bind_layers(Ether, PdelayResp,         type=0x88F7)
#bind_layers(Ether, FollowUp,           type=0x88F7)
#bind_layers(Ether, DelayResp,          type=0x88F7)
#bind_layers(Ether, PdelayRespFollowUp, type=0x88F7)
#def set_ptp_message_tpye(etherType=0x88F7, messageType=0x0):
#    if(etherType == 0x88F7):
#        ptp_msg = {
#            0x0 : bind_layers(Ether, Sync,               type=0x88F7),
#            0x1 : bind_layers(Ether, DelayReq,           type=0x88F7),
#            0x2 : bind_layers(Ether, PdelayReq,          type=0x88F7),
#            0x3 : bind_layers(Ether, PdelayResp,         type=0x88F7),
#            0x8 : bind_layers(Ether, FollowUp,           type=0x88F7),
#            0x9 : bind_layers(Ether, DelayResp,          type=0x88F7),
#            0xA : bind_layers(Ether, PdelayRespFollowUp, type=0x88F7),
#        }
#        return ptp_msg.get(messageType)
#    elif(etherType == 0x0800):
#        ptp_msg = {
#            0x0 : bind_layers(UDP, Sync,               dport=319),
#            0x1 : bind_layers(UDP, DelayReq,           dport=319),
#            0x2 : bind_layers(UDP, PdelayReq,          dport=319),
#            0x3 : bind_layers(UDP, PdelayResp,         dport=319),
#            0x8 : bind_layers(UDP, FollowUp,           dport=319),
#            0x9 : bind_layers(UDP, DelayResp,          dport=319),
#            0xA : bind_layers(UDP, PdelayRespFollowUp, dport=319),
#        }
#        return ptp_msg.get(messageType)
#    else:
#        None

def add_eth_ip_udp_headers(dport):
    eth = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35')
    ip  = IP(dst='10.0.0.2', ttl=64)
    udp = UDP(sport=65231, dport=dport) / PTP()
    pkt = eth / ip / udp
    return pkt

def add_layers(nb_fields, nb_headers):
    class P4Bench(Packet):
        name = "P4Bench Message"
        fields_desc =  []
        for i in range(nb_fields):
            fields_desc.append(ShortField('field_%d' %i , 0))
    layers = ''
    for i in range(nb_headers):
        if i < (nb_headers - 1):
            layers = layers / P4Bench(field_0=1)
        else:
            layers = layers / P4Bench(field_0=0)
    return layers

def vary_header_field(nb_fields):
    class P4Bench(Packet):
        name = "P4Bench Message"
        fields_desc =  []
        for i in range(nb_fields):
            fields_desc.append(ShortField('field_%d' % i , i))
    return P4Bench()

def add_padding(pkt, packet_size):
    pad_len = packet_size - len(pkt)
    if pad_len < 0:
        print ("Packet size [%d] is greater than expected %d" % (len(pkt), packet_size))
    else:
        pad = '\x00' * pad_len
        pkt = pkt/pad
    return pkt

def get_parser_header_pcap(nb_fields, nb_headers, out_dir):
    pkt = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35') / PTP()
    pkt /= add_layers(nb_fields, nb_headers)
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

def get_parser_field_pcap(nb_fields, out_dir):
    pkt = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35') / PTP()
    pkt /= vary_header_field(nb_fields)
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

def get_read_state_pcap(udp_dest_port, out_dir):

    class MemTest(Packet):
        name = "P4Bench Message for MemTest"
        fields_desc =  [
            XBitField("op", 0x1, 4),
            XBitField("index", 0x1, 12),
            XBitField("data", 0xf1f2f3f4, 32),
        ]

    pkt = add_eth_ip_udp_headers(udp_dest_port)
    pkt /= MemTest(op=1, index=0)

    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

def get_write_state_pcap(udp_dest_port, out_dir):

    class MemTest(Packet):
        name = "P4Bench Message for MemTest"
        fields_desc =  [
            XBitField("op", 0x1, 4),
            XBitField("index", 0x1, 12),
            XBitField("data", 0xf1f2f3f4, 32),
        ]

    pkt = add_eth_ip_udp_headers(udp_dest_port)

    pkt /= MemTest(op=2, index=0, data=0)

    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

#no care xx
def get_pipeline_pcap(out_dir):
    pkt = add_eth_ip_udp_headers(15432)
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

"""
:funciton: generate ptpv2 ipv4 pcap
"""
def get_ptp_ipv4_pcap(out_dir):
    pkt = add_eth_ip_udp_headers(319)
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

"""
mod_type = 'add' -> 6 ptp pkt
"""
def get_packetmod_pcap(nb_headers, nb_fields, mod_type, out_dir):
    pkt = []
    if mod_type == 'multi':
        for i in range(nb_headers):
            eth = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35')
            ptp = PTP(reserved2=random.randrange(0,0xFFFFFFFF))
            pkt.append(eth / ptp)
    elif mod_type == 'add': #no care
        eth = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35')
        ptp = PTP(reserved2=0)
        pkt = eth / ptp * 2
    elif mod_type == 'rm':
        eth = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35')
        ptp = PTP(reserved2=1)
        pkt = eth / ptp
        pkt /= add_layers(nb_fields, nb_headers)
        #packet_size = len(pkt)
        #pkt = add_padding(pkt, packet_size)
    #elif mod_type == 'mod':
    #    eth = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35')
    #    ptp = PTP(reserved2=1)                                           # mod arr_ts
    #    pkt = eth / ptp
    #    pkt /= add_layers(nb_fields, nb_headers)
    #    #packet_size = len(pkt)
    #    #pkt = add_padding(pkt, packet_size)

    wrpcap('%s/test.pcap' % out_dir, pkt)

def get_set_field_pcap(out_dir):
    pkt = add_eth_ip_udp_headers(0x9091)
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

def set_custom_field_pcap(nb_fields, out_dir, packet_size):
    pkt = Ether(src='0C:C4:7A:A3:25:34', dst='0C:C4:7A:A3:25:35') / DelayResp()
    pkt /= add_layers(nb_fields, 1)
    print(type(pkt))
    packet_size = len(pkt)
    pkt = add_padding(pkt, packet_size)
    wrpcap('%s/test.pcap' % out_dir, pkt)

class ptp_generator(object):
    def __init__(self, src, dst, messageType, nb_fields, nb_headers, packet_size, out_dir):
        self.src = src
        self.dst = dst
        self.messageType = messageType
        self.nb_fields   = nb_fields
        self.nb_headers  = nb_headers
        self.packet_size = packet_size
        self.out_dir     = out_dir

#    def ptp_pkt(self, messageType):
#        if (messageType == "Sync"):
#            ptp_pkt = Sync()
#        elif(messageType == "DelayReq"):
#            ptp_pkt = DelayReq()
#        elif(messageType == "PdelayReq"):
#            ptp_pkt = PdelayReq()
#        elif(messageType == "PdelayResp"):
#            ptp_pkt = PdelayResp()
#        elif(messageType == "FollowUp"):
#            ptp_pkt = FollowUp()
#        elif(messageType == "DelayResp"):
#            ptp_pkt = DelayResp()
#        elif(messageType == "PdelayRespFollowUp"):
#            ptp_pkt = PdelayRespFollowUp()
#        else:
#            ptp_pkt = Sync()
#        return ptp_pkt
#
#    def add_layers(self, nb_fields, nb_headers):
#        class P4Bench(Packet):
#            name = "P4Bench Message"
#            fields_desc =  []
#            for i in range(nb_fields):
#                fields_desc.append(ShortField('field_%d' %i , 0))
#        layers = ''
#        for i in range(nb_headers):
#            if i < (nb_headers - 1):
#                layers = layers / P4Bench(field_0=1)
#            else:
#                layers = layers / P4Bench(field_0=0)
#        return layers
#
#    def add_padding(self, pkt, packet_size):
#        pad_len = packet_size - len(pkt)
#        if pad_len < 0:
#            print ("Packet size [%d] is greater than expected %d" % (len(pkt), packet_size))
#        else:
#            pad = '\x00' * pad_len
#            pkt = pkt/pad
#        return pkt
#
#    def set_custom_field_pcap(self):
#        pkt = Ether(src=self.src, dst=self.dst) / self.ptp_pkt(self.messageType)
#        pkt /= self.add_layers(self.nb_fields, self.nb_headers)
#        packet_size = len(pkt)
#        pkt = self.add_padding(pkt, packet_size)
#        wrpcap('%s/%s.pcap' % (self.out_dir, self.messageType), pkt)



    def ptp_pkt(messageType):
        if (messageType == "Sync"):
            ptp_pkt = Sync()
        elif(messageType == "DelayReq"):
            ptp_pkt = DelayReq()
        elif(messageType == "PdelayReq"):
            ptp_pkt = PdelayReq()
        elif(messageType == "PdelayResp"):
            ptp_pkt = PdelayResp()
        elif(messageType == "FollowUp"):
            ptp_pkt = FollowUp()
        elif(messageType == "DelayResp"):
            ptp_pkt = DelayResp()
        elif(messageType == "PdelayRespFollowUp"):
            ptp_pkt = PdelayRespFollowUp()
        else:
            ptp_pkt = Sync()
        return ptp_pkt

    def add_layers(nb_fields, nb_headers):
        class P4Bench(Packet):
            name = "P4Bench Message"
            fields_desc =  []
            for i in range(nb_fields):
                fields_desc.append(ShortField('field_%d' %i , 0))
        layers = ''
        for i in range(nb_headers):
            if i < (nb_headers - 1):
                layers = layers / P4Bench(field_0=1)
            else:
                layers = layers / P4Bench(field_0=0)
        return layers

    def add_padding(pkt, packet_size):
        pad_len = packet_size - len(pkt)
        if pad_len < 0:
            print ("Packet size [%d] is greater than expected %d" % (len(pkt), packet_size))
        else:
            pad = '\x00' * pad_len
            pkt = pkt/pad
        return pkt

    def set_custom_field_pcap(self):
        pkt = Ether(src=self.src, dst=self.dst) / ptp_generator.ptp_pkt(self.messageType)
        pkt /= ptp_generator.add_layers(self.nb_fields, self.nb_headers)
        packet_size = len(pkt)
        pkt = ptp_generator.add_padding(pkt, packet_size)
        wrpcap('%s/%s.pcap' % (self.out_dir, self.messageType), pkt)















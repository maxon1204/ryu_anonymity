# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp, ipv4
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
import random


class Host():
    def __init__(self,sw,mac_dst,in_port):
        self.sw_id = sw
        self.mac_dst = mac_dst
        self.in_port = in_port

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.switches = {}
        self.links = {}
        self.psevdo_set = set()
        self.Hosts = dict()
        self.psevdo_mac_to_ip = {}
        self.real_ip_to_real_mac = {}


    # формируем Packetout запрос на свитч для того чтобы отправлять arp запрос на все хосты
    def send_packet_out(self, datapath, buffer_id, in_port,out_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(out_port)]
        req = ofp_parser.OFPPacketOut(datapath, buffer_id,
                                      in_port, actions)
        datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



    def generate_mac(self):
        mac = '00:00:00:'

        z = 16 ** 6
        a = random.randint(0, z)
        b = set()
        while (a in b):
            a = random.randint(0, z)
        else:
            b.add(a)
        hex_num = hex(a)[2:].zfill(6)
        # print(hex_num)
        str = "{}{}{}:{}{}:{}{}".format(mac, *hex_num)

        return str

    #для обработки ARP-запроса
    def receive_arp(self, datapath, pkt_arp, etherFrame, inPort):

        arp_dst_mac = pkt_arp.dst_mac
        print(type(pkt_arp.dst_mac))
        if pkt_arp.opcode == arp.ARP_REQUEST:
            arp_dst_mac = pkt_arp.dst_mac
            arp_src_mac = pkt_arp.src_mac
            print("receive ARP request %s => %s (port%d)" % (etherFrame.src, etherFrame.dst, inPort))
            #запустить флуд

        elif pkt_arp.opcode == arp.ARP_REPLY:
            pass





    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        print("****************************")
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        print(switches)
        # self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        print(links_list)
        # print links_list
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        print(links)
        # print links
        # self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]




    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        #проверка на arp запрос
        '''
        arpPacket = pkt.get_protocol(arp.arp)
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if eth.opcode ==

        '''
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        switch_list = get_switch(self.topology_api_app, None)
        self.logger.info("list of switches %s", switch_list)
        self.switches = [switch.dp.id for switch in switch_list]
        #print(switches)
        self.net.add_nodes_from(self.switches)

        links_list = get_link(self.topology_api_app, None)
        #print(links_list)
        # print links_list
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(self.links)

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, attr_dict = {'port': in_port})
            self.net.add_edge(src, dpid)
        if dst in self.net:
            path = nx.shortest_path(self.net, src, dst)
            print("path is ")
            print(path)
            print("len path ")
            print(len(path))
            print("type path ")
            print(type(path))
            next = path[path.index(dpid) + 1]
            #out_port = self.net[dpid][next]['port']
            print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #print("**********List of links")


       # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        '''
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        '''
        print("Check if this is arp request")
        pkt_arp = pkt.get_protocol(arp.arp)
        #self.receive_arp(datapath,pkt_arp,eth,in_port)
        print(type(pkt_arp))
        if pkt_arp:
            if pkt_arp.opcode == arp.ARP_REQUEST:
                arp_dst_mac = pkt_arp.dst_mac
                arp_src_mac = pkt_arp.src_mac
                print("receive ARP request %s => %s (port%d)" % (eth.src, eth.dst, in_port))
                # запустить флуд
                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return
            elif pkt_arp.opcode == arp.ARP_REPLY:
                str = self.generate_mac()
                self.psevdo_mac_to_ip[str] = pkt_arp.src_ip
                self.real_ip_to_real_mac[pkt_arp.src_ip] = pkt_arp.dst_mac
                pass

        actions = [parser.OFPActionOutput(out_port)]

        print("creat road")

        for i in (len(path) - 2):
            str_src = self.generate_mac()
            str_dst = self.generate_mac()
            actions1 = [parser.OFPActionOutput(out_port), parser.OFPActionSetField(eth_dst=str_dst , eth_src=str_src)]
            self.links[i]


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        '''
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        '''


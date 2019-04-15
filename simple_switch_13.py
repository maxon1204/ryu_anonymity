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
from ryu.lib.dpid import dpid_to_str, str_to_dpid


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
        self.mac_to_dpid = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.switches = {}
        self.links = {}
        self.psevdo_set = set()
        self.Hosts = dict()
        self.psevdo_mac_to_ip = {}
        self.real_ip_to_real_mac = {}
        self.port_on_host = {} # будет словарь из switch.dpid и порты на которых есть хосты

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

        dst = eth.dst
        src = eth.src
        print("Type dpid")
        dpid = datapath.id
        print(type(dpid))
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_dpid[src] = dpid

        print('Get th topology')
        switch_list = get_switch(self.topology_api_app, None)
        self.logger.info("list of switches %s", switch_list)
        self.switches = [switch.dp.id for switch in switch_list]
        print("switches")
        print(self.switches)
        self.net.add_nodes_from(self.switches)

        links_list = get_link(self.topology_api_app, None)
        print(links_list)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        print(self.links)
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
        print("Check the ports on switch")
        ports_list = [switch.to_dict() for switch in switch_list]
        print("ports")
        print(ports_list)
        for i in range(len(ports_list)):
            self.port_on_host[str_to_dpid(ports_list[i]["dpid"])] = set(int(port["port_no"]) for port in ports_list[i]["ports"])
        print(self.port_on_host)
        port_on_links = {}
        for i in range(len(self.links)):
            port_on_links[self.links[i][0]] = set()
        for i in range(len(self.links)):
            port_on_links[self.links[i][0]].add(self.links[i][2]["port"])
        print("port_on_links")
        print(port_on_links)
        print("make difference")
        print(len(ports_list))
        for i in range(len(ports_list)):
            (self.port_on_host[i + 1]).difference_update(port_on_links[i + 1])
        print("without links ports")
        print(self.port_on_host)

        print("Check if this is arp request")
        pkt_arp = pkt.get_protocol(arp.arp)
        #self.receive_arp(datapath,pkt_arp,eth,in_port)
        print(type(pkt_arp))
        if pkt_arp:
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.real_ip_to_real_mac[pkt_arp.src_ip] = pkt_arp.src_mac
                arp_dst_mac = pkt_arp.dst_mac
                print('type')
                print(type(pkt_arp.dst_mac))
                arp_src_mac = pkt_arp.src_mac
                print("receive ARP request %s => %s (port%d)" % (eth.src, eth.dst, in_port))
                # запустить флуд
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                for i in range(len(self.port_on_host)):
                    if self.port_on_host[i]:
                        for port in self.port_on_host[i]:
                            fake_mac = self.generation_mac()
                            arp_req = packet.Packet()
                            arp_req.add_protocol(
                                ethernet.ethernet(
                                    ethertype=ether_types.ETH_TYPE_ARP,
                                    src=fake_mac,
                                    dst='ff:ff:ff:ff:ff:ff'
                                )
                            )
                            arp_req.add_protocol(
                                arp.arp(
                                    opcode=arp.ARP_REQUEST,
                                    src_mac=fake_mac,
                                    src_ip=pkt_arp.src_ip,# тут нужнdatapath.id = iо менять ip адрес или нет?
                                    dst_ip=pkt_arp.dst_ip,
                                )
                            )
                            arp_req.serialize()
                            actions = [parser.OFPActionOutput(port)]
                            datapath.id = i
                            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                    in_port=in_port, actions=actions, data=arp_req.data)
                            datapath.send_msg(out)
                return
            elif pkt_arp.opcode == arp.ARP_REPLY:
                fake_mac_answer = self.generate_mac()
                self.psevdo_mac_to_ip[fake_mac_answer] = pkt_arp.src_ip
                self.real_ip_to_real_mac[pkt_arp.src_ip] = pkt_arp.src_mac
                arp_rep = packet.Packet()
                arp_rep.add_protocol(
                    ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        src=fake_mac_answer,
                        dst=dst
                    )
                )
                arp_rep.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=fake_mac_answer,
                        src_ip=pkt_arp.src_ip,  # тут нужно менять ip адрес или нет?
                        dst_mac=pkt_arp.dst_mac,
                        dst_ip=pkt_arp.dst_ip,
                    )
                )
                arp_rep.serialize()
                #отправить arp ответ на соостветсвующий mac адресс
                real_mac_dst = self.real_ip_to_real_mac[pkt_arp.dst_ip]
                temp_dpid = self.mac_to_dpid[real_mac_dst]
                port = self.mac_to_port[temp_dpid][real_mac_dst]
                actions = [parser.OFPActionOutput(port)]
                datapath.id = temp_dpid
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=arp_rep.data)
                datapath.send_msg(out)
                return
        else:
            print("Not the arp")
        actions = [parser.OFPActionOutput(out_port)]

        print("creat road")
        #построить путь
        '''
        for i in (len(path) - 2):
            str_src = self.generate_mac()
            str_dst = self.generate_mac()
            actions1 = [parser.OFPActionOutput(out_port), parser.OFPActionSetField(eth_dst=str_dst , eth_src=str_src)]
            self.links[i]

        '''
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

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
        self.path = []
        self.real_mac_to_psevdomac = {}
        self.b = set()
        self.set_ip = set()

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

    # нужно будет добавить параметр для множетсва
    def generate_mac(self, b):
        mac = '00:00:00:'

        z = 16 ** 6
        a = random.randint(0, z)
        while (a in b):
            a = random.randint(0, z)
        else:
            b.add(a)
        hex_num = hex(a)[2:].zfill(6)
        # print(hex_num)
        str = "{}{}{}:{}{}:{}{}".format(mac, *hex_num)
        return str

    # нужно будет добавить параметр для множества
    def random_ipv4(self, set_ip):
        temp = '.'.join(str(random.randint(0, 255)) for _ in range(4))
        while temp in set_ip:
            temp = '.'.join(str(random.randint(0, 255)) for _ in range(4))
        else:
            set_ip.add(temp)
        return temp

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #print("PAcket")
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
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.mac_to_dpid[src] = dpid

        switch_list = get_switch(self.topology_api_app, None)
        #self.logger.info("list of switches %s", switch_list)
        self.switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(self.switches)

        links_list = get_link(self.topology_api_app, None)
        #print(links_list)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(self.links)

        if src not in self.net:
            #print("Добавить mac_src = %s", src)
            self.net.add_node(src)
            self.net.add_edge(dpid, src, attr_dict = {'port': in_port})
            self.net.add_edge(src, dpid)

        #print("**********List of links")
       # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        ports_list = [switch.to_dict() for switch in switch_list]

        for i in range(len(ports_list)):
            self.port_on_host[str_to_dpid(ports_list[i]["dpid"])] = set(int(port["port_no"]) for port in ports_list[i]["ports"])
        port_on_links = {}
        for i in range(len(self.links)):
            port_on_links[self.links[i][0]] = set()
        for i in range(len(self.links)):
            port_on_links[self.links[i][0]].add(self.links[i][2]["port"])
        if port_on_links:
            for i in range(len(ports_list)):
                (self.port_on_host[i + 1]).difference_update(port_on_links[i + 1])

        pkt_arp = pkt.get_protocol(arp.arp)
        #self.receive_arp(datapath,pkt_arp,eth,in_port)
        if pkt_arp:
            print("Arp")
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.real_ip_to_real_mac[pkt_arp.src_ip] = pkt_arp.src_mac
                arp_dst_mac = pkt_arp.dst_mac
                arp_src_mac = pkt_arp.src_mac
                print("receive ARP request %s => %s (port%d)" % (eth.src, eth.dst, in_port))
                for i in range(len(self.port_on_host)):
                    if (self.port_on_host[i + 1]):
                        for port in self.port_on_host[i + 1]:
                            if port == in_port and dpid == i + 1:
                                continue
                            fake_mac = self.generate_mac(self.b)
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
                            switch = get_switch(self.topology_api_app, i + 1)
                            current_parser = switch[0].dp.ofproto_parser
                            actions = [current_parser.OFPActionOutput(port)]
                            out = parser.OFPPacketOut(datapath=switch[0].dp, buffer_id=msg.buffer_id,
                                                      in_port=ofproto_v1_3.OFPP_CONTROLLER, actions=actions, data=arp_req.data)
                            switch[0].dp.send_msg(out)
                            print("send arp request")
                return
            elif pkt_arp.opcode == arp.ARP_REPLY:
                print(pkt_arp.dst_ip)
                print("receive ARP reply %s => %s (port%d)" % (eth.src, eth.dst, in_port))
                real_dst_mac = self.real_ip_to_real_mac[pkt_arp.dst_ip]
                self.real_mac_to_psevdomac[real_dst_mac] = pkt_arp.dst_mac
                fake_mac_answer = self.generate_mac(self.b)
                self.psevdo_mac_to_ip[fake_mac_answer] = pkt_arp.src_ip
                self.real_ip_to_real_mac[pkt_arp.src_ip] = pkt_arp.src_mac
                arp_rep = packet.Packet()
                arp_rep.add_protocol(
                    ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        src=fake_mac_answer,
                        dst=real_dst_mac
                    )
                )
                arp_rep.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=fake_mac_answer,
                        src_ip=pkt_arp.src_ip,  # тут нужно менять ip адрес или нет?
                        dst_mac=real_dst_mac,
                        dst_ip=pkt_arp.dst_ip,
                    )
                )
                arp_rep.serialize()
                #отправить arp ответ на соостветсвующий mac адресс
                real_mac_dst = self.real_ip_to_real_mac[pkt_arp.dst_ip]
                temp_dpid = self.mac_to_dpid[real_mac_dst]
                port = self.mac_to_port[temp_dpid][real_mac_dst]
                actions = [parser.OFPActionOutput(port)]
                switch = get_switch(self.topology_api_app, temp_dpid)
                out = parser.OFPPacketOut(datapath=switch[0].dp, buffer_id=msg.buffer_id,
                                          in_port=ofproto_v1_3.OFPP_CONTROLLER, actions=actions, data=arp_rep.data)
                switch[0].dp.send_msg(out)
                print("src_mac = ", fake_mac_answer)
                print("dst_mac = ", real_dst_mac)
                return

        if dst in self.psevdo_mac_to_ip:
            dst1 = self.real_ip_to_real_mac[self.psevdo_mac_to_ip[dst]] # реальный mac адрес получателя
            psevdo_mac_src = self.real_mac_to_psevdomac[src]
            self.path = nx.shortest_path(self.net, src, dst1)
            path1 = nx.shortest_path(self.net, dst1, src)
            # next = self.path[self.path.index(dpid) + 1]
            # out_port = self.net[dpid][next]['port']
            print("creat road")
            out_port = self.mac_to_port[self.mac_to_dpid[dst1]][dst1]
            reverse_path = nx.shortest_path(self.net, dst1, src)
            print(dst)
            print(src)
            if len(self.path) == 3:
                actions1 = [parser.OFPActionSetField(eth_dst=dst1),
                            parser.OFPActionSetField(eth_src=psevdo_mac_src), parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

                actions2 = [parser.OFPActionSetField(eth_dst=src),
                            parser.OFPActionSetField(eth_src=dst), parser.OFPActionOutput(in_port)]
                match2 = parser.OFPMatch(in_port=out_port, eth_dst=self.real_mac_to_psevdomac[src], eth_src=dst1)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions1, msg.buffer_id)
                    self.add_flow(datapath, 1, match2, actions2, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions1)
                    self.add_flow(datapath, 1, match2, actions2)

            else:
                temp_out_port1 = 0
                temp_in_port1 = 0
                temp_fake_src1 = ''
                temp_fake_dst1 = ''
                temp_dst = dst
                temp_src = src
                print(dst)
                print(src)
                for i in range(1, len(self.path) - 1):
                    if i == 1:
                        temp_out_port1 = self.net[self.path[1]][self.path[2]]["port"]
                        print("port = ", temp_out_port1)
                        temp_fake_src1 = self.generate_mac(self.b)
                        temp_fake_dst1 = self.generate_mac(self.b)
                        temp_in_port1 = in_port
                    elif i == (len(self.path) - 2):
                        temp_out_port1 = self.mac_to_port[self.mac_to_dpid[dst1]][dst1]
                        print("port = ", temp_out_port1)
                        temp_dst = temp_fake_dst1
                        temp_src = temp_fake_src1
                        temp_fake_src1 = psevdo_mac_src
                        temp_fake_dst1 = dst1
                        temp_in_port1 = self.net[self.path[len(self.path) - 2]][self.path[len(self.path) - 3]]["port"]
                    else:
                        temp_out_port1 = self.net[self.path[i]][self.path[i + 1]]["port"]
                        print("port = ", temp_out_port1)
                        temp_dst = temp_fake_dst1
                        temp_src = temp_fake_src1
                        temp_fake_src1 = self.generate_mac(self.b)
                        temp_fake_dst1 = self.generate_mac(self.b)
                        temp_in_port1 = self.net[self.path[i + 1]][self.path[i]]["port"]

                    temp_match1 = parser.OFPMatch(in_port=temp_in_port1, eth_dst=temp_dst, eth_src=temp_src)
                    temp_actions1 = [parser.OFPActionSetField(eth_dst=temp_fake_dst1),
                                      parser.OFPActionSetField(eth_src=temp_fake_src1),
                                      parser.OFPActionOutput(temp_out_port1)]
                    switch = get_switch(self.topology_api_app, self.path[i])
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(switch[0].dp, 1, temp_match1, temp_actions1, msg.buffer_id)
                        return
                    else:
                        self.add_flow(switch[0].dp, 1, temp_match1, temp_actions1)
                temp_dst = self.real_mac_to_psevdomac[src]# изменить src так в цикле выше мы его меняли завести переменную чтобы не портить src
                temp_src = dst1
                for i in range(1, len(reverse_path) - 1):
                    if i == 1:
                        temp_out_port1 = self.net[reverse_path[1]][reverse_path[2]]["port"]
                        print("reverse_port = ", temp_out_port1)
                        temp_fake_src1 = self.generate_mac(self.b)
                        temp_fake_dst1 = self.generate_mac(self.b)
                        temp_in_port1 = self.mac_to_port[self.mac_to_dpid[dst1]][dst1]
                    elif i == (len(self.path) - 2):
                        temp_out_port1 = in_port
                        print("reverse_port = ", temp_out_port1)
                        temp_dst = temp_fake_dst1
                        temp_src = temp_fake_src1
                        temp_fake_src1 = dst
                        temp_fake_dst1 = src
                        temp_in_port1 = self.net[reverse_path[len(reverse_path) - 2]][reverse_path[len(reverse_path) - 3]]["port"]
                    else:
                        temp_out_port1 = self.net[reverse_path[i]][reverse_path[i + 1]]["port"]
                        print("reverse_port = ", temp_out_port1)
                        temp_dst = temp_fake_dst1
                        temp_src = temp_fake_src1
                        temp_fake_src1 = self.generate_mac(self.b)
                        temp_fake_dst1 = self.generate_mac(self.b)
                        temp_in_port1 = self.net[reverse_path[i + 1]][reverse_path[i]]["port"]

                    temp_match1 = parser.OFPMatch(in_port=temp_in_port1, eth_dst=temp_dst, eth_src=temp_src)
                    temp_actions1 = [parser.OFPActionSetField(eth_dst=temp_fake_dst1),
                                      parser.OFPActionSetField(eth_src=temp_fake_src1),
                                      parser.OFPActionOutput(temp_out_port1)]
                    switch = get_switch(self.topology_api_app, reverse_path[i])
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(switch[0].dp, 1, temp_match1, temp_actions1, msg.buffer_id)
                        return
                    else:
                        self.add_flow(switch[0].dp, 1, temp_match1, temp_actions1)

            print("Send")
            print("out_port = ", out_port)
            print("in_port = ", in_port)
            temp_actions = [parser.OFPActionSetField(eth_dst=dst1),
                             parser.OFPActionSetField(eth_src=psevdo_mac_src),
                             parser.OFPActionOutput(self.mac_to_port[self.mac_to_dpid[dst1]][dst1])]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            temp_switch = get_switch(self.topology_api_app, self.path[len(self.path) - 2])
            out = parser.OFPPacketOut(datapath=temp_switch[0].dp, buffer_id=msg.buffer_id,
                                      in_port=ofproto_v1_3.OFPP_CONTROLLER, actions=temp_actions, data=data)
            temp_switch[0].dp.send_msg(out)

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

    # нужно будет добавить параметр для множества
    def random_ipv4(self):
        b = set()
        temp = '.'.join(str(random.randint(0, 255)) for _ in range(4))
        while temp in b:
            temp = '.'.join(str(random.randint(0, 255)) for _ in range(4))
        else:
            b.add(temp)
        return temp

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
        #self.logger.info("list of switches %s", switch_list)
        self.switches = [switch.dp.id for switch in switch_list]
        print("switches")
        print(self.switches)
        self.net.add_nodes_from(self.switches)

        links_list = get_link(self.topology_api_app, None)
        #print(links_list)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        print(self.links)
        self.net.add_edges_from(self.links)

        if src not in self.net:
            print("Добавить mac_src = %s", src)
            self.net.add_node(src)
            self.net.add_edge(dpid, src, attr_dict = {'port': in_port})
            self.net.add_edge(src, dpid)

        #print("**********List of links")
       # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        print("Check the ports on switch")
        ports_list = [switch.to_dict() for switch in switch_list]
        print("ports")
        #print(ports_list)
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
        if port_on_links:
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
                for i in range(len(self.port_on_host)):
                    if (self.port_on_host[i + 1]):
                        print("Отправил")
                        for port in self.port_on_host[i + 1]:
                            print("Отправляю на порт")
                            print(port)
                            print("dpid")
                            print(i + 1)
                            fake_mac = self.generate_mac()
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
                            switch = get_switch(self.topology_api_app, i + 1)
                            out = parser.OFPPacketOut(datapath=switch[0].dp, buffer_id=msg.buffer_id,
                                                      in_port=in_port, actions=actions, data=arp_req.data)
                            switch[0].dp.send_msg(out)
                print("End of Arp reqest")
                return
            elif pkt_arp.opcode == arp.ARP_REPLY:
                print("Get Arp Reply")
                print(pkt_arp.dst_ip)
                real_dst_mac = self.real_ip_to_real_mac[pkt_arp.dst_ip]
                self.real_mac_to_psevdomac[real_dst_mac] = pkt_arp.dst_mac
                fake_mac_answer = self.generate_mac()
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
                print("Значение таблиц")
                print(self.real_ip_to_real_mac)
                print(self.mac_to_dpid)
                print(pkt_arp.dst_ip)
                #отправить arp ответ на соостветсвующий mac адресс
                real_mac_dst = self.real_ip_to_real_mac[pkt_arp.dst_ip]
                print("mac_dst")
                print(real_mac_dst)
                temp_dpid = self.mac_to_dpid[real_mac_dst]
                port = self.mac_to_port[temp_dpid][real_mac_dst]
                print("port")
                print(self.mac_to_port)
                print(port)
                actions = [parser.OFPActionOutput(port)]
                switch = get_switch(self.topology_api_app, temp_dpid)
                out = parser.OFPPacketOut(datapath=switch[0].dp, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=arp_rep.data)
                switch[0].dp.send_msg(out)
                print("End of Arp Reply")
                return
        else:
            print("Not the arp")
        #actions = [parser.OFPActionOutput(out_port)]
        print("path")
        print(dst)
        print(src)
        '''
        if dst in self.psevdo_mac_to_ip:
            dst1 = self.real_ip_to_real_mac[self.psevdo_mac_to_ip[dst]]
            psevdo_mac_src = self.real_mac_to_psevdomac[src]
            self.path = nx.shortest_path(self.net, src, dst1)
            next = self.path[self.path.index(dpid) + 1]
            # out_port = self.net[dpid][next]['port']
            print(self.path)
            print("creat road")
            out_port = self.mac_to_port[self.mac_to_dpid[dst1]][dst1]
            if len(self.path) == 3:
                actions1 = [parser.OFPActionSetField(eth_dst=dst1),
                            parser.OFPActionSetField(eth_src=psevdo_mac_src),parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

                actions2 = [parser.OFPActionSetField(eth_dst=src),
                            parser.OFPActionSetField(eth_src=dst),parser.OFPActionOutput(in_port)]
                match2 = parser.OFPMatch(in_port=out_port, eth_dst=self.real_mac_to_psevdomac[src], eth_src=dst1)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions1, msg.buffer_id)
                    self.add_flow(datapath, 1, match2, actions2, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions1)
                    self.add_flow(datapath, 1, match2, actions2)

            else:
                dst2 = ''
                src2 = ''
                temp_in_port = 0
                temp_out_port = 0
                for i in range(len(self.path) - 2):
                    fake_src1 = self.generate_mac()
                    fake_dst1 = self.generate_mac()
                    match1 = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    actions1 = [parser.OFPActionSetField(eth_dst=fake_src1),
                                parser.OFPActionSetField(eth_src=fake_dst1),parser.OFPActionOutput(out_port)]

                    fake_src2 = self.generate_mac()
                    fake_dst2 = self.generate_mac()
                    match2 = parser.OFPMatch(in_port=in_port, eth_dst=dst2, eth_src=src2)
                    actions2 = [parser.OFPActionSetField(eth_dst=fake_src2),
                                parser.OFPActionSetField(eth_src=fake_dst2),parser.OFPActionOutput()]
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match1, actions1, msg.buffer_id)
                        self.add_flow(datapath, 1, match2, actions2, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match1, actions1)
                        self.add_flow(datapath, 1, match2, actions2)
                    dst = fake_dst1
                    src = fake_src1
            
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            '''

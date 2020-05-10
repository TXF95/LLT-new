# qos base bandwidth

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.topology.api import get_link
from ryu.lib.packet import ether_types
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from collections import defaultdict, OrderedDict
import network_monitor
import json
import re
import logging
import time


LINK_CAPACITY = 50000000

LINK_NEED = 30000000
ISOTIMEFORMAT='%Y-%m-%d %X'


class QosBw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(QosBw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.mac_to_dpid = {}  # {mac:(dpid,port)}

        self.datapaths = defaultdict(lambda: None)
        self.topology_api_app = self
        self.src_links = defaultdict(lambda: defaultdict(lambda: None))

        self.check_ip_dpid = defaultdict(list)

        self.qos_ip_bw_list = []

        self.network_monitor = kwargs["Network_Monitor"]

        self.bandwidth = {}

        self.json_bandwidth = []

        self.gateway = ['10.0.0.1', '20.0.0.1']  # the list of gateway
        #  set the mac of gateway
        self.gateway_to_mac = 'aa:aa:aa:aa:aa:aa'

        self.ip_to_port = {}  #{ip:(dpid,port)}

        wsgi = kwargs['wsgi']
        wsgi.register(GetBandwidthRESTAPI, {'qos_ip_bw_list': self.qos_ip_bw_list, 'datapaths': self.datapaths, 'bandwidth': self.bandwidth, 'json_bandwidth': self.json_bandwidth})
        wsgi.register(SetBandwidthController, {'qos_ip_bw_list': self.qos_ip_bw_list, 'datapaths': self.datapaths})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
            # self.logger.info("pkt_tcp: %s", 8)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
            # self.logger.info("pkt_tcp: %s", 9)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

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
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # in rest_topology, self.mac_to_port is for the find for host
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # arp handle
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)

            if pkt_arp.dst_ip in self.gateway:
                gateway_mac = self.gateway_to_mac
                self.handle_arpre(datapath=datapath, port=in_port, src_mac=gateway_mac, dst_mac=src,
                                  src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
                return

            elif pkt_arp.dst_ip in self.ip_to_mac:
                self.handle_arpre(datapath=datapath, port=in_port, src_mac=self.ip_to_mac[pkt_arp.dst_ip], dst_mac=src,
                                  src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
            else:
                # to avoid flood when the dst ip not in the network
                if datapath.id not in self.check_ip_dpid[pkt_arp.dst_ip]:
                    self.check_ip_dpid[pkt_arp.dst_ip].append(datapath.id)
                    out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            return

        elif pkt_arp and pkt_arp.opcode == arp.ARP_REPLY:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)
            dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
            (dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
            self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=src, dst_mac=dst_mac,
                              src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
            return

        if pkt_ipv4 and (self.ip_to_port.get(pkt_ipv4.dst)) and (self.ip_to_port.get(pkt_ipv4.src)):
            (src_dpid, src_port) = self.ip_to_port[pkt_ipv4.src]  # src dpid and port
            (dst_dpid, dst_port) = self.ip_to_port[pkt_ipv4.dst]  # dst dpid and port
            self.install_path(src_dpid=src_dpid, dst_dpid=dst_dpid, src_port=src_port, dst_port=dst_port,
                              ev=ev, src=src, dst=dst, pkt_ipv4=pkt_ipv4, pkt_tcp=pkt_tcp)

    def send_pkt(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        self.send_pkt(datapath, port, pkt)

    def install_path(self, src_dpid, dst_dpid, src_port, dst_port, ev, src, dst, pkt_ipv4, pkt_tcp):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mid_path = None

        if pkt_tcp:
            self.logger.info("src_port : %s", pkt_tcp.src_port)
            self.logger.info("dst_port : %s", pkt_tcp.dst_port)
            self.logger.info("qos_ip_bw_list: %s", self.qos_ip_bw_list)
            qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
            self.logger.info("qos_info_dict: %s", qos_info_dict)
            if qos_info_dict:
                queue_id = 1
                mid_path = self.short_path(src=src_dpid, dst=dst_dpid, bw=qos_info_dict['bw'])
                if mid_path is None:
                    # self.logger.debug("the current network can't satisfy")
                    mid_path = self.short_path(src=src_dpid, dst=dst_dpid)
            else:
                # self.logger.info("pkt_tcp: %s", 1)
                queue_id = 0
                mid_path = self.short_path(src=src_dpid, dst=dst_dpid)
        else:

            # if pkt_ipv4.src in self.qos_ip_bw:
            #     queue_id = 1
            #     mid_path = self.short_path(src=src_dpid, dst=dst_dpid, bw=self.qos_ip_bw[pkt_ipv4.src])
            #     if mid_path is None:
            #         # self.logger.debug("the current network can't satisfy")
            #         mid_path = self.short_path(src=src_dpid, dst=dst_dpid)
            #
            # else:
                # self.logger.info("pkt_tcp: %s", 2)
            queue_id = 0
            mid_path = self.short_path(src=src_dpid, dst=dst_dpid)

        if mid_path is None:
            return


        path = [(src_dpid, src_port)] + mid_path + [(dst_dpid, dst_port)]

        #self.logger.info("path : %s", str(path))
        if pkt_tcp:
            for i in xrange(len(path) - 2, -1, -2):
                datapath_path = self.datapaths[path[i][0]]
                # self.logger.info("pkt_tcp: %s", 3)
                # self.logger.info("pkt_tcp: %s", pkt_tcp.src_port)
                match = parser.OFPMatch(in_port=path[i][1], eth_src=src, eth_dst=dst, eth_type=0x0800,
                                        ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, ip_proto=6,
                                        tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port
                                        )
                # self.logger.info("pkt_tcp: %s", 5)
                if i < (len(path) - 2):
                    actions = [parser.OFPActionSetQueue(queue_id=queue_id), parser.OFPActionOutput(path[i + 1][1])]
                    # self.logger.info("pkt_tcp: %s", 10)
                else:
                    actions = [parser.OFPActionSetField(eth_dst=self.ip_to_mac.get(pkt_ipv4.dst)),
                               parser.OFPActionSetQueue(queue_id=queue_id),
                               parser.OFPActionOutput(path[i + 1][1])]
                    # self.logger.info("pkt_tcp: %s", 11)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath_path, 100, match, actions, msg.buffer_id, idle_timeout=5, hard_timeout=0)
                    # self.logger.info("pkt_tcp: %s", 6)
                else:
                    self.add_flow(datapath_path, 100, match, actions, idle_timeout=5, hard_timeout=0)
                    # self.logger.info("pkt_tcp: %s", 7)
        else:
            for i in xrange(len(path) - 2, -1, -2):
                datapath_path = self.datapaths[path[i][0]]
                # self.logger.info("pkt_tcp: %s", 4)
                match = parser.OFPMatch(in_port=path[i][1], eth_src=src, eth_dst=dst, eth_type=0x0800,
                                        ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)

                if i < (len(path) - 2):
                    actions = [parser.OFPActionSetQueue(queue_id=queue_id), parser.OFPActionOutput(path[i + 1][1])]
                else:
                    actions = [parser.OFPActionSetField(eth_dst=self.ip_to_mac.get(pkt_ipv4.dst)),
                               parser.OFPActionSetQueue(queue_id=queue_id),
                               parser.OFPActionOutput(path[i + 1][1])]
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath_path, 100, match, actions, msg.buffer_id, idle_timeout=5, hard_timeout=0)
                else:
                    self.add_flow(datapath_path, 100, match, actions, idle_timeout=5, hard_timeout=0)

    def judge(self, pkt_ipv4, pkt_tcp, info_list):
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        src_port = pkt_tcp.src_port
        dst_port = pkt_tcp.dst_port
        for dict in info_list:
            # self.logger.info("dict_src_ip: %s", dict['src_ip'])
            # self.logger.info("src_ip: %s", src_ip)
            # self.logger.info("dict_dst_ip: %s", dict['dst_ip'])
            # self.logger.info("dst_ip: %s", dst_ip )
            # self.logger.info("dict_src_port: %s", dict['src_port'])
            # self.logger.info("src_port: %s", src_port)
            # self.logger.info("dict_dst_port: %s", dict['dst_port'])
            # self.logger.info("dst_port : %s", dst_port )
            if dict.get('src_ip')!= None and dict.get('dst_ip') == None and \
                    dict.get('src_port') == None and dict.get('dst_port') == None:
                if dict['src_ip'] == src_ip:
                    return dict
                elif dict['src_ip'] == dst_ip:
                    return dict
            elif dict.get('src_ip')!= None and dict.get('dst_ip') != None and \
                    dict.get('src_port') == None and dict.get('dst_port') == None:
                if dict['src_ip'] == src_ip and dict['dst_ip'] == dst_ip:
                    return dict
                elif dict['src_ip'] == dst_ip and dict['dst_ip'] == src_ip:
                    return dict
            elif dict.get('src_ip')!= None and dict.get('dst_ip') != None and \
                    dict.get('src_port') != None and dict.get('dst_port') != None:
                if dict['src_ip'] == src_ip and dict['dst_ip'] == dst_ip and \
                                int(dict['src_port']) == src_port and int(dict['dst_port']) == dst_port:
                    return dict
                elif dict['src_ip'] == dst_ip and dict['dst_ip'] == src_ip and \
                                int(dict['src_port']) == dst_port and int(dict['dst_port']) == src_port:
                    return dict
        return False

    def short_path(self, src, dst, bw=0):
        if src == dst:
            return []
        result = defaultdict(lambda: defaultdict(lambda: None))
        distance = defaultdict(lambda: defaultdict(lambda: None))

        # the node is checked
        seen = [src]

        # the distance to src
        distance[src] = 0

        w = 0  # weight
        bw_bps = bw * 1000000  # translate Mbps to bps
        # self.logger.debug("speed : %s", str(self.network_monitor.get_port_speed()))
        # self.logger.debug("qos_ip_bw : %s", str(self.qos_ip_bw))

        while len(seen) < len(self.src_links):
            node = seen[-1]
            if node == dst:
                break
            for (temp_src, temp_dst) in self.src_links[node]:
                if temp_dst not in seen:
                    temp_src_port = self.src_links[node][(temp_src, temp_dst)][0]
                    temp_dst_port = self.src_links[node][(temp_src, temp_dst)][1]
                    # bps

                    # if (bw != 0) and (LINK_CAPACITY - self.network_monitor.get_port_speed(temp_src, temp_src_port)[0] < bw_bps):
                    #     continue

                    w = self.cal_weight(temp_src, temp_dst, temp_src_port, temp_dst_port, bw_bps)
                    if (distance[temp_dst] is None) or (distance[temp_dst] > distance[temp_src] + w):
                        distance[temp_dst] = distance[temp_src] + w
                        # result = {"dpid":(link_src, src_port, link_dst, dst_port)}
                        result[temp_dst] = (temp_src, temp_src_port, temp_dst, temp_dst_port)
            min_node = None
            min_path = 999
            # get the min_path node
            for temp_node in distance:
                if (temp_node not in seen) and (distance[temp_node] is not None):
                    if distance[temp_node] < min_path:
                        min_node = temp_node
                        min_path = distance[temp_node]
            if min_node is None:
                break
            seen.append(min_node)

        path = []

        if dst not in result:
            return None

        while (dst in result) and (result[dst] is not None):
            path = [result[dst][2:4]] + path
            path = [result[dst][0:2]] + path
            dst = result[dst][0]
        # self.logger.info("path : %s", str(path))
        return path


    def cal_weight(self, temp_src, temp_dst, temp_src_port, temp_dst_port, bw_bps):

        link_remain = LINK_CAPACITY - self.bandwidth.get((temp_src, temp_dst, temp_src_port, temp_dst_port))[0]
        if link_remain > bw_bps:
            weight = 1 / (link_remain - bw_bps)
        elif link_remain == bw_bps:
            weight = 1
        elif link_remain < bw_bps:
            tnow = self.cal_Tnow(temp_src, temp_dst, temp_src_port, bw_bps - link_remain)
            weight = (link_remain + tnow) / bw_bps + tnow
        elif link_remain == 0:
            weight = float('inf')
        return weight

    def cal_Tnow(self, temp_src, temp_dst, temp_src_port, link_now):
        ip_to_speed = {}
        key = (temp_src, temp_src_port)
        for (ip_src, ip_dst) in self.network_monitor.DpidPort_to_ip.get(key):
            if ip_src or ip_dst is not None:
                key1 = (temp_src, ip_src, ip_dst)
                speed = self.network_monitor.get_flow_speed_dict.get(key1)
                key2 = (ip_src, ip_dst)
                ip_to_speed[key2] = speed
        speed_list_tmp = []
        # sort_ip_to_speed = sorted(ip_to_speed.items(), key=lambda x: x[1])
        for key in ip_to_speed:
            speed_list_tmp.append(ip_to_speed.get(key))

        speed_list_tmp.sort()
        speed_sum_tmp = 0

        speed_list = []
        for speed in speed_list_tmp:
            speed_sum_tmp += speed
            speed_list.append(speed)
            if speed_sum_tmp >= link_now:
                break
        speed_list.sort(reverse=True)
        speed_sum =0
        for speed in speed_list:
            speed_sum += speed
            speed_list.append(speed)
            if speed_sum >= link_now:
                break
        return speed_sum

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
        # self.logger.info("datapaths : %s", self.datapaths)

    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventPortAdd, event.EventPortDelete,
                 event.EventPortModify, event.EventLinkAdd, event.EventLinkDelete])
    def get_topology(self, ev):
        links_list = get_link(self.topology_api_app, None)
        for link in links_list:
            sw_src = link.src.dpid
            sw_dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            self.src_links[sw_src][(sw_src, sw_dst)] = (src_port, dst_port)
            self.src_links[sw_dst][(sw_dst, sw_src)] = (dst_port, src_port)
        # self.logger.info("src_links : %s", str(self.src_links))

    # @set_ev_cls(ofp_event.EventOFPPortStatsReply, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    # def _get_bandwidth(self, ev):
    #     for key in self.src_links:
    #         tmp = self.src_links[key]
    #         for key1 in tmp:
    #             sw_src = key1[0]
    #             sw_dst = key1[1]
    #             src_port = tmp[key1][0]
    #             dst_port = tmp[key1][1]
    #             key_speed = (sw_src, sw_dst, src_port, dst_port)
    #             value_speed = self.network_monitor.get_port_speed(sw_src, src_port)[0]
    #             self.bandwidth[key_speed] = value_speed
    #     self.logger.info("port_speed : %s", str(self.bandwidth))
    #     self._json_bandwidth(self.bandwidth)
    #     return self.bandwidth

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _get_bandwidth(self, ev):
        for key in self.src_links:
            tmp = self.src_links[key]
            for key1 in tmp:
                sw_src = key1[0]
                sw_dst = key1[1]
                src_port = tmp[key1][0]
                dst_port = tmp[key1][1]
                key_speed = (sw_src, sw_dst, src_port, dst_port)
                value_speed = self.network_monitor.get_port_speed(sw_src, src_port)
                self.bandwidth[key_speed] = value_speed
        #self.logger.info("port_speed : %s", str(self.bandwidth))
        self._json_bandwidth(self.bandwidth)
        return self.bandwidth

    def _json_bandwidth(self, dist):
        del self.json_bandwidth[:]
        for key in dist:
            _bandwidth = OrderedDict()
            _bandwidth['src_sw'] = key[0]
            _bandwidth['dst_sw'] = key[1]
            _bandwidth['src_port'] = key[2]
            _bandwidth['dst_port'] = key[3]
            _bandwidth['port_speed'] = dist.get(key)[0]
            _bandwidth['time'] = dist.get(key)[1]
            #self.logger.info("dist.gey(key): %s", str(dist.get(key)))
            #self.json_bandwidth.append(_bandwidth)
            #self.logger.info("json_bandwidth : %s", str(self.json_bandwidth))
            self.json_bandwidth.append(_bandwidth)
            #del _bandwidth
        #self.logger.info("json_bandwidth : %s", str(self.json_bandwidth))
        return self.json_bandwidth

    # get the bandwidth between 2 special switches (downlink and uplink)

    # def _get_bandwidth_2switch(self, sw_src=None, sw_dst=None, src_port=None, dst_port=None):
    #     bandwidth_2switch = {}
    #     if sw_src is None or sw_dst is None or src_port is None or dst_port is None:
    #         return self.bandwidth
    #     in_port_speed = self.bandwidth.get((sw_src, sw_dst, src_port, dst_port))
    #     out_port_speed = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))
    #     if in_port_speed is not None and out_port_speed is not None:
    #         bandwidth_2switch['in_port_speed'] = in_port_speed
    #         bandwidth_2switch['out_port_speed'] = out_port_speed
    #         #bandwidth_2switch = (in_port_speed, out_port_speed)
    #
    #         return json.dumps(bandwidth_2switch)
    #     else:
    #         return self.bandwidth
#
class SetBandwidthController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SetBandwidthController, self).__init__(req, link, data, **config)
        self.re_ip = ur'^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$'
        self.qos_ip_bw_list = data['qos_ip_bw_list']
        self.datapaths = data['datapaths']

        self.logger = logging.getLogger('my_logger')

    def delete_flow(self, src_ip=None, src_port=None, dst_ip=None, dst_port=None):
        for datapath_id in self.datapaths:
            datapath = self.datapaths[datapath_id]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            if src_ip and src_port and dst_ip and dst_port:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, tcp_src=src_port,
                                        ipv4_dst=dst_ip, tcp_dst=dst_port, ip_proto=6)
            elif src_ip and dst_ip:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6)
            elif src_ip:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ip_proto=6)
            elif dst_ip:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip, ip_proto=6)
            # OFPFlowMod:The controller sends this message to modify the flow table.
            mod = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            datapath.send_msg(mod)

    # curl http://127.0.0.1:8080/get/bandwidth/limit/all
    # curl http://127.0.0.1:8080/get/bandwidth/limit/10.0.0.1
    @route('getqoslimit', '/get/qos/limit/all', methods=['GET'])
    def get_bw_limit_all(self, req, **kwargs):
        body = json.dumps(self.qos_ip_bw_list)
        return Response(content_type='application/json', body=body)

    #  curl -d '{"src_ip":10.0.0.100,"src_port":8000,"dst_ip":20.0.0.101,"dst_port":9000}' http://127.0.0.1:8080/get/bandwidth/limit
    @route('getbandwidth_two', '/get/qos/limit', methods=['POST'])
    def get_bw_limit_one(self, req, **kwargs):
        try:
            get_qos_dict = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body="failure")
        for qos_ip_bw_dict in self.qos_ip_bw_list:
            if get_qos_dict.get('src_ip') and get_qos_dict.get('dst_ip') and get_qos_dict.get('src_port') and get_qos_dict.get('dst_port'):
                if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip') and get_qos_dict['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
                        and get_qos_dict['src_port'] == qos_ip_bw_dict.get('src_port') and get_qos_dict['dst_port'] == qos_ip_bw_dict.get('dst_port'):
                    body = json.dumps(qos_ip_bw_dict)
            elif get_qos_dict.get('src_ip') and get_qos_dict.get('dst_ip'):
                if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip') and get_qos_dict['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
                    body = json.dumps(qos_ip_bw_dict)
            elif get_qos_dict.get('src_ip'):
                if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip'):
                    body = json.dumps(qos_ip_bw_dict)
        return Response(content_type='application/json', body=body)


    # curl -d '{"src_ip":10.0.0.100,"src_port":8000,"dst_ip":20.0.0.101,"dst_port":9000,"bw":5}' http://127.0.0.1:8080/set/bandwidth/limit
    # curl -d '[{"10.0.0.1":10},{"10.0.0.2":5}]' http://127.0.0.1:8080/set/bandwidth/limit
    @route('setbandwidth', '/set/qos/limit', methods=['POST'])
    def set_bw_limit(self, req, **kwargs):
        try:
            set_qos_bw = req.json if req.body else {}
            self.logger.info("ip_bw: %s", set_qos_bw)
        except ValueError:
            return Response(status=400)

        if set_qos_bw.get('src_ip') and set_qos_bw.get('src_port') and set_qos_bw.get('dst_ip') and set_qos_bw.get('dst_port'):
            if re.match(self.re_ip, set_qos_bw['src_ip']) and re.match(self.re_ip, set_qos_bw['dst_ip']) and set_qos_bw not in self.qos_ip_bw_list:
                self.qos_ip_bw_list.append(set_qos_bw)
                self.delete_flow(set_qos_bw['src_ip'], int(set_qos_bw['src_port']), set_qos_bw['dst_ip'], int(set_qos_bw['dst_port']))
                self.delete_flow(set_qos_bw['dst_ip'], int(set_qos_bw['dst_port']), set_qos_bw['src_ip'], int(set_qos_bw['src_port']))
        elif set_qos_bw.get('src_ip') and set_qos_bw.get('dst_ip'):
            if re.match(self.re_ip, set_qos_bw['src_ip']) and re.match(self.re_ip, set_qos_bw['dst_ip']) and set_qos_bw not in self.qos_ip_bw_list:
                self.qos_ip_bw_list.append(set_qos_bw)
                self.delete_flow(src_ip=set_qos_bw['src_ip'], dst_ip=set_qos_bw['dst_ip'])
                self.delete_flow(src_ip=set_qos_bw['dst_ip'], dst_ip=set_qos_bw['src_ip'])
        elif set_qos_bw.get('src_ip'):
            if re.match(self.re_ip, set_qos_bw['src_ip']) and set_qos_bw not in self.qos_ip_bw_list:
                self.qos_ip_bw_list.append(set_qos_bw)
                self.delete_flow(src_ip=set_qos_bw['src_ip'])
                self.delete_flow(dst_ip=set_qos_bw['src_ip'])


        return Response(status=200, body='success')

    @route('modifybandwidth', '/modify/qos/limit', methods=['POST'])
    def modify_bw_limit(self, req, **kwargs):
        try:
            modify_bw_info = req.json if req.body else {}
        except ValueError:
            return Response(status=400)
        if modify_bw_info.get('src_ip') and modify_bw_info.get('src_port') and modify_bw_info.get('dst_ip') and modify_bw_info.get('dst_port'):
            if re.match(self.re_ip, modify_bw_info['src_ip']) and re.match(self.re_ip, modify_bw_info['dst_ip']):
                for qos_ip_bw_dict in self.qos_ip_bw_list:
                    if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip') and modify_bw_info['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
                            and modify_bw_info['src_port'] == qos_ip_bw_dict.get('src_port') and modify_bw_info['dst_port'] == qos_ip_bw_dict.get('dst_port'):
                        self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                        self.qos_ip_bw_list.append(modify_bw_info)
                        self.delete_flow(qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']),
                                         qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']))
                        self.delete_flow(qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']),
                                         qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']))
                body = json.dumps(self.qos_ip_bw_list)
        elif modify_bw_info.get('src_ip') and modify_bw_info.get('dst_ip'):
            if re.match(self.re_ip, modify_bw_info['src_ip']) and re.match(self.re_ip, modify_bw_info['dst_ip']):
                for qos_ip_bw_dict in self.qos_ip_bw_list:
                    if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip') and modify_bw_info['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
                        self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                        self.qos_ip_bw_list.append(modify_bw_info)
                        self.delete_flow(src_ip=modify_bw_info['src_ip'], dst_ip=modify_bw_info['dst_ip'])
                        self.delete_flow(src_ip=modify_bw_info['dst_ip'], dst_ip=modify_bw_info['src_ip'])
                body = json.dumps(self.qos_ip_bw_list)

        elif modify_bw_info.get('src_ip'):
            if re.match(self.re_ip, modify_bw_info['src_ip']):
                for qos_ip_bw_dict in self.qos_ip_bw_list:
                    if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip'):
                        self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                        self.qos_ip_bw_list.append(modify_bw_info)
                        self.delete_flow(src_ip=modify_bw_info['src_ip'])
                        self.delete_flow(dst_ip=modify_bw_info['src_ip'])
                body = json.dumps(self.qos_ip_bw_list)

        return Response(content_type='application/json', body=body)



    #curl - d '{"src_ip":"10.0.0.100", "src_port":"20.0.0.101", "dst_port":"51092"}' http://127.0.0.1:8080/delete/bandwidth/limit
    @route('delbandwidth_one', '/delete/qos/limit', methods=['POST'])
    def del_bw_limit_one(self, req, **kwargs):
        try:
            del_qos = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body="failure")
        if del_qos.get('src_ip') and del_qos.get('dst_ip') and del_qos.get('src_port') and del_qos.get('dst_port'):
            for qos_ip_bw_dict in self.qos_ip_bw_list:
                if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip') and del_qos['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
                        and del_qos['src_port'] == qos_ip_bw_dict.get('src_port') and del_qos['dst_port'] == qos_ip_bw_dict.get('dst_port'):
                    self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                    self.delete_flow(del_qos['src_ip'], int(del_qos['src_port']), del_qos['dst_ip'], int(del_qos['dst_port']))
                    self.delete_flow(del_qos['dst_ip'], int(del_qos['dst_port']), del_qos['src_ip'], int(del_qos['src_port']))
            body = json.dumps(self.qos_ip_bw_list)
        elif del_qos.get('src_ip') and del_qos.get('dst_ip'):
            for qos_ip_bw_dict in self.qos_ip_bw_list:
                if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip') and del_qos['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
                    self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                    self.delete_flow(src_ip=del_qos['src_ip'], dst_ip=del_qos['dst_ip'])
                    self.delete_flow(src_ip=del_qos['dst_ip'], dst_ip=del_qos['src_ip'])
            body = json.dumps(self.qos_ip_bw_list)
        elif del_qos.get('src_ip'):
            for qos_ip_bw_dict in self.qos_ip_bw_list:
                if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip'):
                    self.qos_ip_bw_list.remove(qos_ip_bw_dict)
                    self.delete_flow(src_ip=del_qos['src_ip'])
                    self.delete_flow(dst_ip=del_qos['src_ip'])
            body = json.dumps(self.qos_ip_bw_list)

        return Response(content_type='application/json', body=body)

    @route('delbandwidth_two', '/delete/qos/limit/all', methods=['GET'])
    def del_bw_limit_all(self, req, **kwargs):
        for qos_ip_bw_dict in self.qos_ip_bw_list:
            if qos_ip_bw_dict.get('src_ip') and qos_ip_bw_dict.get('dst_ip') and qos_ip_bw_dict.get('src_port') and qos_ip_bw_dict.get('dst_port'):
                self.delete_flow(qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']),
                                 qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']))
                self.delete_flow(qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']),
                                 qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']))
            elif qos_ip_bw_dict.get('src_ip') and qos_ip_bw_dict.get('dst_ip'):
                self.delete_flow(src_ip=qos_ip_bw_dict['src_ip'], dst_ip=qos_ip_bw_dict['dst_ip'])
                self.delete_flow(src_ip=qos_ip_bw_dict['dst_ip'], dst_ip=qos_ip_bw_dict['src_ip'])
            elif qos_ip_bw_dict.get('src_ip'):
                self.delete_flow(src_ip=qos_ip_bw_dict['src_ip'])
                self.delete_flow(dst_ip=qos_ip_bw_dict['src_ip'])
        del self.qos_ip_bw_list[:]
        body = json.dumps(self.qos_ip_bw_list)
        return Response(content_type='application/json', body=body)


class GetBandwidthRESTAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GetBandwidthRESTAPI, self).__init__(req, link, data, **config)
        self.json_bandwidth = data['json_bandwidth']
        self.bandwidth = data['bandwidth']

    def _get_bandwidth_2switch(self, sw_src=None, sw_dst=None, src_port=None, dst_port=None):
        bandwidth_2switch = {}
        if sw_src is None or sw_dst is None or src_port is None or dst_port is None:
            return
        in_port_speed = self.bandwidth.get((sw_src, sw_dst, src_port, dst_port))[0]
        out_port_speed = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))[0]
        time = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))[1]

        if in_port_speed is not None and out_port_speed is not None:
            bandwidth_2switch['in_port_speed'] = in_port_speed
            bandwidth_2switch['out_port_speed'] = out_port_speed
            bandwidth_2switch['time'] = time
            #bandwidth_2switch['time'] = time.strftime(ISOTIMEFORMAT, time.localtime())

            #bandwidth_2switch = (in_port_speed, out_port_speed)

            return json.dumps(bandwidth_2switch)
        else:
            return

    @route('getbandwidth', '/get/bandwidth/all', methods=['GET'])
    def get_all_speed(self, req, **kwargs):
        body = json.dumps(self.json_bandwidth)
        return Response(content_type='application/json', body=body)

    # curl -d '{"src_sw": 2, "src_port": 1, "dst_sw": 1, "dst_port": 2}' http://127.0.0.1:8080/get/linkspeed
    # @route('getlinkspeed','/get/linkspeed', methods=['POST'])
    # def get_link_speed(self,req,**kwargs):
    #     try:
    #         link_state=req.json if req.body else{}
    #     except ValueError:
    #         return Response(status=400,body="failure")
    #
    #     sw_src=link_state['src_sw']
    #     sw_dst=link_state['dst_sw']
    #     src_port=link_state['src_port']
    #     dst_port=link_state['dst_port']
    #     bandwidth_2switch = {}
    #     in_port_speed = self.bandwidth.get((sw_src, sw_dst, src_port, dst_port))
    #     out_port_speed = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))
    #     bandwidth_2switch['in_port_speed'] = in_port_speed
    #     bandwidth_2switch['out_port_speed'] = out_port_speed
    #
    #     body = json.dumps(bandwidth_2switch)
    #     return Response(content_type='application/json', body=body)

    # curl -d '{"src_sw": 2, "src_port": 1, "dst_sw": 1, "dst_port": 2}' http://127.0.0.1:8080/get/linkspeed
    @route('getlinkspeed', '/get/linkspeed', methods=['POST'])
    def get_link_speed(self, req, **kwargs):
        try:
            link_state = req.json if req.body else{}
        except ValueError:
            return Response(status=400, body="failure")

        sw_src = link_state['src_sw']
        sw_dst = link_state['dst_sw']
        src_port = link_state['src_port']
        dst_port = link_state['dst_port']
        body = self._get_bandwidth_2switch(sw_src, sw_dst, src_port, dst_port)
        return Response(content_type='application/json', body=body)

# qos base bandwidth

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types
from ryu.topology.api import get_link
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from collections import defaultdict
import network_monitor
import json
from copy import deepcopy
from time import sleep
import re
import sys
sys.path.append('..')
import add_rate_limit as RateLimit



class TrafficControl(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TrafficControl, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.topology_api_app = self
        self.check_ip_dpid = defaultdict(list)
        self.ip_to_mac = defaultdict(lambda: None)
        self.mac_to_dpid = defaultdict(lambda: None)  # {mac:(dpid,port)}
        self.datapaths = defaultdict(lambda: None)
        self.src_links = defaultdict(lambda: defaultdict(lambda: None))
        self.proto_to_type = {'TCP': 6, 'UDP': 17, '*': 0}
        self.qos_to_dscp = {0: 20, 1: 40, 2: 60}   # ip map dscp
        self.network_monitor = kwargs["Network_Monitor"]
        self.strategy = defaultdict(lambda: None)
        self.paths = defaultdict(lambda: defaultdict(lambda: None))
        self.flowid_list = [0,0,0,0,0,0,0,0]
        wsgi = kwargs['wsgi']

        wsgi.register(TrafficControlRestAPI, {'tc': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
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
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        eth_src = eth.src
        eth_dst = eth.dst
        dpid = datapath.id

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # in rest_topology, self.mac_to_port is for the find for host
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port

        # handle arp
        if pkt_arp:
            self.handle_arp(pkt_arp=pkt_arp, datapath=datapath, in_port=in_port, eth_src=eth_src, msg=msg)

        # handle ipv4
        if pkt_ipv4 and eth_src in self.mac_to_dpid and eth_dst in self.mac_to_dpid:
            self.handle_ipv4(pkt_ipv4=pkt_ipv4, eth_src=eth_src, eth_dst=eth_dst, msg=msg)

    def send_pkt(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp(self, pkt_arp, datapath, in_port, eth_src, msg):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # arp request
        if pkt_arp.opcode == arp.ARP_REQUEST:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = eth_src
                self.mac_to_dpid[eth_src] = (dpid, in_port)

            if pkt_arp.dst_ip in self.ip_to_mac:
                self.handle_arpre(datapath=datapath, port=in_port, src_mac=self.ip_to_mac[pkt_arp.dst_ip], dst_mac=eth_src,
                                  src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
            else:
                # to avoid flood when the dst ip not in the network
                if dpid not in self.check_ip_dpid[pkt_arp.dst_ip]:
                    self.check_ip_dpid[pkt_arp.dst_ip].append(dpid)
                    out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            return
        # arp Response
        elif pkt_arp.opcode == arp.ARP_REPLY:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = eth_src
                self.mac_to_dpid[eth_src] = (dpid, in_port)
            dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
            (dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
            self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=eth_src, dst_mac=dst_mac,
                              src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
            return

    def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        self.send_pkt(datapath, port, pkt)

    def handle_ipv4(self, pkt_ipv4, eth_src, eth_dst, msg):
        (src_dpid, src_port) = self.mac_to_dpid[eth_src]
        (dst_dpid, dst_port) = self.mac_to_dpid[eth_dst]

        # when the path is not exist, recalculate the path
        if not self.paths[src_dpid][dst_dpid]:
            mid_path = self.compute_path(src=src_dpid, dst=dst_dpid)
            if mid_path is None:
                self.logger.info('no path from the src host to the dst host')
                return
            self.paths[src_dpid][dst_dpid] = mid_path
        path = [(src_dpid, src_port)] + self.paths[src_dpid][dst_dpid] + [(dst_dpid, dst_port)]

        self.logger.info("path: %s", path)

        ip_dscp = 20

        for i in xrange(len(path) - 2, -1, -2):
            datapath_path = self.datapaths[path[i][0]]
            ofproto = datapath_path.ofproto
            parser = datapath_path.ofproto_parser


            match = parser.OFPMatch(in_port=path[i][1], eth_src=eth_src, eth_dst=eth_dst, eth_type=0x0800, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)
          

            if i == 0: # the first switch motify the dscp
                actions = [parser.OFPActionSetField(ip_dscp=ip_dscp), parser.OFPActionOutput(path[i + 1][1])]
            else:
                actions = [parser.OFPActionOutput(path[i + 1][1])]
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath_path, 1, match, actions, msg.buffer_id, idle_timeout=200, hard_timeout=0)
            else:
                self.add_flow(datapath_path, 1, match, actions, idle_timeout=200, hard_timeout=0)

            if i == 0:
                out = parser.OFPPacketOut(datapath=datapath_path, buffer_id=msg.buffer_id, in_port=path[i][0], actions=actions, data=msg.data)
                datapath_path.send_msg(out)


    def re_install_path(self, flow, old_paths):
        (old_match, old_actions, priority) = flow
        (src_dpid, src_port) = self.mac_to_dpid[old_match.get('eth_src')]
        (dst_dpid, dst_port) = self.mac_to_dpid[old_match.get('eth_dst')]

        old_path = old_paths[src_dpid].get(dst_dpid, [])

        eth_src = old_match.get('eth_src')
        eth_dst = old_match.get('eth_dst')
        ipv4_src = old_match.get('ipv4_src')
        ipv4_dst = old_match.get('ipv4_dst')
        ip_proto = old_match.get('ip_proto')

        tp_src = old_match.get('tcp_src') or old_match.get('udp_src') or 0
        tp_dst = old_match.get('tcp_dst') or old_match.get('udp_dst') or 0

        mid_path = self.compute_path(src=src_dpid, dst=dst_dpid)
        if mid_path is None:
            self.logger.info('no path from the src host to the dst host')
            return
        self.paths[src_dpid][dst_dpid] = mid_path
        path = [(src_dpid, src_port)] + self.paths[src_dpid][dst_dpid] + [(dst_dpid, dst_port)]

        self.logger.info("path: %s", path)

        match_dict = {
            'eth_src' : eth_src,
            'eth_dst' : eth_dst,
            'eth_type': 0x0800,
            'ipv4_src': ipv4_src,
            'ipv4_dst': ipv4_dst
        }

        idle_timeout = 0
        if ip_proto == 6:
            match_dict['ip_proto'] = ip_proto
            if tp_src:
                match_dict['tcp_src'] = tp_src
            if tp_dst:
                match_dict['tcp_dst'] = tp_dst
            tp_proto = 'TCP'
        elif ip_proto == 17:
            match_dict['ip_proto'] = ip_proto
            if tp_src:
                match_dict['udp_src'] = tp_src
            if tp_dst:
                match_dict['udp_dst'] = tp_dst
            tp_proto = 'UDP'
        else:
            tp_proto = '*'
            idle_timeout = 200

        (flow_qos, flow_bw, flow_id) = self.strategy.get((ipv4_src, ipv4_dst, tp_proto, tp_src, tp_dst), (0, 0, 0))
        ip_dscp = self.qos_to_dscp.get(flow_qos, 20)
        # delete the old flow
        for i in xrange(0, len(old_path), 2):
            datapath_path = self.datapaths[old_path[i][0]]
            ofproto = datapath_path.ofproto
            parser = datapath_path.ofproto_parser
          
            match = parser.OFPMatch(**match_dict)
            
            mod = parser.OFPFlowMod(datapath=datapath_path, match=match, command=ofproto.OFPFC_DELETE, priority=priority, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            datapath_path.send_msg(mod)

        sleep(3)

        for i in xrange(0, len(old_path), 2):
            if flow_id and old_path[i][0]:
                dev = 's' + str(path[i][0]) + '-eth' + str(path[i+1][1])
                # delete the old rate limit
                RateLimit.delete_flow_rate_limit(dev=dev, priority=2-flow_qos, flow_id=flow_id)


        for i in xrange(len(path) - 2, -1, -2):
            datapath_path = self.datapaths[path[i][0]]
            parser = datapath_path.ofproto_parser
            
            match = parser.OFPMatch(in_port=path[i][1], **match_dict)
            
            if i == 0: # the first switch motify the dscp
                actions = [parser.OFPActionSetField(ip_dscp=ip_dscp), parser.OFPActionOutput(path[i + 1][1])]
            else:
                actions = [parser.OFPActionOutput(path[i + 1][1])]
            self.add_flow(datapath_path, priority, match, actions, idle_timeout=idle_timeout, hard_timeout=0)

        sleep(1)

        for i in xrange(len(path) - 2, -1, -2):
            if flow_id and path[i][0]:
                dev = 's' + str(path[i][0]) + '-eth' + str(path[i+1][1])
                RateLimit.add_flow_rate_limit(dev=dev, priority=2-flow_qos, flow_id=flow_id, rate=flow_bw, ip_src=ipv4_src, ip_dst=ipv4_dst, port_src=str(tp_src), port_dst=str(tp_dst), protocol=tp_proto)

    def compute_path(self, src, dst):
        if src == dst:
            return []
        result = defaultdict(lambda: defaultdict(lambda: None))
        distance = defaultdict(lambda: defaultdict(lambda: None))

        # the node is checked
        seen = [src]

        # the distance to src
        distance[src] = 0

        w = 1  # weight

        while len(seen) < len(self.src_links):
            node = seen[-1]
            if node == dst:
                break
            for (temp_src, temp_dst) in self.src_links[node]:
                if temp_dst not in seen:
                    temp_src_port = self.src_links[node][(temp_src, temp_dst)][0]
                    temp_dst_port = self.src_links[node][(temp_src, temp_dst)][1]

                    if (distance[temp_dst] is None) or (distance[temp_dst] > distance[temp_src] + w):
                        distance[temp_dst] = distance[temp_src] + w
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
        return path

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

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def failure_recovery(self, ev):
        msg = ev.msg
        desc = msg.desc
        name = desc.name
        datapath = msg.datapath
        dpid = datapath.id


        port = int(re.findall(r'\d+$', name)[0])
        key = (dpid, port)
        flowList = self.network_monitor.dpidport_to_flow.get(key, [])

        # save the old paths to delete the flow
        # when different flow use the same path, to avoid the later flow path be covered by the preview flow
        old_paths = deepcopy(self.paths)

        for (sw_src, sw_dst) in self.src_links[dpid].keys():
            if sw_src == dpid and self.src_links[dpid][(sw_src, sw_dst)][0] == port:
                del self.src_links[dpid][(sw_src, sw_dst)]

        for flow in flowList:
            self.re_install_path(flow, old_paths)

    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventPortAdd, event.EventPortDelete,
                 event.EventPortModify, event.EventLinkAdd, event.EventLinkDelete])
    def get_topology(self, ev):
        links_list = get_link(self.topology_api_app, None)

        self.src_links.clear()

        for link in links_list:
            sw_src = link.src.dpid
            sw_dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            self.src_links[sw_src][(sw_src, sw_dst)] = (src_port, dst_port)
            self.src_links[sw_dst][(sw_dst, sw_src)] = (dst_port, src_port)

    def add_strategy(self, strategy):
        ipv4_src = strategy.get('nw_src', '*')
        ipv4_dst = strategy.get('nw_dst', '*')
        tp_proto = strategy.get('tp_proto', '*')

        try:
            tp_src = int(strategy.get('tp_src', 0))
            tp_dst = int(strategy.get('tp_dst', 0))
            flow_qos = int(strategy.get('priority', 0))
            flow_bw = int(strategy.get('bandwidth', 0))
        except:
            self.logger.info('the input is illegal')
            return 'failure'

        ip_dscp  = self.qos_to_dscp.get(flow_qos, 20)

        if ipv4_src == '*' or ipv4_dst == '*' or tp_proto == '*':
            self.logger.info('the input is illegal')
            return 'failure'

        # when the src ip or the dst ip has not been found, return
        if not self.ip_to_mac[ipv4_src] or not self.ip_to_mac[ipv4_dst]:
            self.logger.info('the src ip or the dst ip has not been found')
            return 'failure'

        eth_src = self.ip_to_mac[ipv4_src]
        eth_dst = self.ip_to_mac[ipv4_dst]

        # when the src mac or the dst mac has not been found, return
        if not self.mac_to_dpid[eth_src] or not self.mac_to_dpid[eth_dst]:
            self.logger.info('the src mac or the dst mac has not been found')
            return 'failure'

        (src_dpid, src_port) = self.mac_to_dpid[eth_src]
        (dst_dpid, dst_port) = self.mac_to_dpid[eth_dst]

        if not self.paths[src_dpid][dst_dpid]:
            mid_path = self.compute_path(src=src_dpid, dst=dst_dpid)
            if mid_path is None:
                self.logger.info('not path exist')
                return 'failure'
            self.paths[src_dpid][dst_dpid] = mid_path

        path = [(src_dpid, src_port)] + self.paths[src_dpid][dst_dpid] + [(dst_dpid, dst_port)]

        self.logger.info('strategy path: %s', path)

        strategy_item = self.strategy.get((ipv4_src, ipv4_dst, tp_proto, tp_src, tp_dst), None)

        try:
            flow_id = self.flowid_list.index(0) + 1
            self.flowid_list[flow_id-1] = 1
        except:
            self.logger.info('the num of strategies can not be more than 8')
            return 'failure'

        self.strategy[(ipv4_src, ipv4_dst, tp_proto, tp_src, tp_dst)] = (flow_qos, flow_bw, flow_id)

        match_dict = {
            'eth_src': eth_src,
            'eth_dst': eth_dst,
            'eth_type': 0x0800,
            'ipv4_src': ipv4_src,
            'ipv4_dst': ipv4_dst,
        }

        if tp_proto == 'TCP':
            match_dict['ip_proto'] = 6
            if tp_src:
                match_dict['tcp_src']  = tp_src
            if tp_dst:
                match_dict['tcp_dst']  = tp_dst
        elif tp_proto == 'UDP':
            match_dict['ip_proto'] = 17
            if tp_src:
                match_dict['udp_src']  = tp_src
            if tp_dst:
                match_dict['udp_dst']  = tp_dst

        for i in xrange(len(path) - 2, -1, -2):
            datapath_path = self.datapaths[path[i][0]]
            parser = datapath_path.ofproto_parser
          
            match = parser.OFPMatch(in_port=path[i][1], **match_dict)
      
            if i == 0: # the first switch motify the dscp
                actions = [parser.OFPActionSetField(ip_dscp=ip_dscp), parser.OFPActionOutput(path[i + 1][1])]
            else:
                actions = [parser.OFPActionOutput(path[i + 1][1])]
            self.add_flow(datapath_path, 100, match, actions, idle_timeout=0, hard_timeout=0)

        sleep(1)

        # add rate limit
        for i in xrange(len(path) - 2, -1, -2):
            dev = 's' + str(path[i][0]) + '-eth' + str(path[i+1][1])
            RateLimit.add_flow_rate_limit(dev=dev, priority=2-flow_qos, flow_id=flow_id, rate=flow_bw, ip_src=ipv4_src, ip_dst=ipv4_dst, port_src=str(tp_src), port_dst=str(tp_dst), protocol=tp_proto)

        return 'success'

    def del_strategy(self, strategy):
        ipv4_src = strategy.get('nw_src', '*')
        ipv4_dst = strategy.get('nw_dst', '*')
        tp_proto = strategy.get('tp_proto', '*')
        try:
            tp_src = int(strategy.get('tp_src', 0))
            tp_dst = int(strategy.get('tp_dst', 0))
        except:
            self.logger.info('the input is illegal')
            return 'failure'

        if ipv4_src == '*' or ipv4_dst == '*' or tp_proto == '*':
            self.logger.info('the input is illegal')
            return 'failure'

        eth_src = self.ip_to_mac[ipv4_src]
        eth_dst = self.ip_to_mac[ipv4_dst]
        (src_dpid, src_port) = self.mac_to_dpid[eth_src]
        (dst_dpid, dst_port) = self.mac_to_dpid[eth_dst]

        if not self.paths[src_dpid][dst_dpid]:
            self.logger.info('error: the path is not stored')
            return 'failure'

        strategy_item = self.strategy.get((ipv4_src, ipv4_dst, tp_proto, tp_src, tp_dst), None)

        if not strategy_item:
            self.logger.info('error: the strategy is not exist')
            return 'failure'

        flow_qos = strategy_item[0]
        flow_id  = strategy_item[2]
        self.flowid_list[flow_id-1] = 0
        del self.strategy[(ipv4_src, ipv4_dst, tp_proto, tp_src, tp_dst)]

        path = [(src_dpid, src_port)] + self.paths[src_dpid][dst_dpid] + [(dst_dpid, dst_port)]

        self.logger.info('strategy path: %s', path)

        match_dict = {
            'eth_src': eth_src,
            'eth_dst': eth_dst,
            'eth_type': 0x0800,
            'ipv4_src': ipv4_src,
            'ipv4_dst': ipv4_dst,
        }

        if tp_proto == 'TCP':
            match_dict['ip_proto'] = 6
            if tp_src:
                match_dict['tcp_src']  = tp_src
            if tp_dst:
                match_dict['tcp_dst']  = tp_dst
        elif tp_proto == 'UDP':
            match_dict['ip_proto'] = 17
            if tp_src:
                match_dict['udp_src']  = tp_src
            if tp_dst:
                match_dict['udp_dst']  = tp_dst

        for i in xrange(len(path) - 2, -1, -2):
            datapath_path = self.datapaths[path[i][0]]
            ofproto = datapath_path.ofproto
            parser = datapath_path.ofproto_parser

            match = parser.OFPMatch(in_port=path[i][1], **match_dict)
        
            mod = parser.OFPFlowMod(datapath=datapath_path, match=match, command=ofproto.OFPFC_DELETE, priority=100, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPP_ANY)
            datapath_path.send_msg(mod)

        sleep(3)

        for i in xrange(len(path) - 2, -1, -2):
            dev = 's' + str(path[i][0]) + '-eth' + str(path[i+1][1])
            RateLimit.delete_flow_rate_limit(dev=dev, priority=2-flow_qos, flow_id=flow_id)

        return 'success'

class TrafficControlRestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TrafficControlRestAPI, self).__init__(req, link, data, **config)
        self.tc = data['tc']

    @route('portspeed', '/speed/port/{dpid}', methods=['GET'])
    def get_port_speed(self, req, **kwargs):
        dpid = kwargs['dpid']
        port_speed_dpid = self.tc.network_monitor.port_speed.get(int(dpid), None)
        if port_speed_dpid is None:
            body = {}
        else:
            body = json.dumps({dpid: port_speed_dpid})
        return Response(content_type='application/json', body=body)

    @route('flowspeed', '/speed/flow/{dpid}', methods=['GET'])
    def get_flow_speed_dpid(self, req, **kwargs):
        dpid = kwargs['dpid']
        flow_speed_dpid = self.tc.network_monitor.flow_speed.get(int(dpid), None)
        if flow_speed_dpid is None:
            body = {}
        else:
            flow_speed_list = []
            for keys in flow_speed_dpid:
                match = {}
                for key in keys:
                    if key[1] is not None:
                        match[key[0]] = key[1]
                flow_speed_list.append({'match': match, 'speed': flow_speed_dpid[keys]})
            body = json.dumps({dpid: flow_speed_list})
        return Response(content_type='application/json', body=body)

    @route('showstrategy', '/strategy/strategies', methods=['GET'])
    def show_strategy(self, req, **kwargs):
        strategy_list = []
        for key in self.tc.strategy:
            item = {'nw_src': key[0], 'nw_dst': key[1], 'tp_proto': key[2], 'tp_src': key[3],
                    'tp_dst': key[4], 'priority': self.tc.strategy[key][0], 'bandwidth': self.tc.strategy[key][1]}
            strategy_list.append(item)
        body = json.dumps(strategy_list)
        return Response(content_type='application/json', body=body)

    @route('addstrategy', '/strategy/add', methods=['POST'])
    def add_strategy(self, req, **kwargs):
        try:
            strategy = req.json if req.body else {}
        except ValueError:
            return Response(status=400, content_type='application/json', body=json.dumps({'result': 'illegal'}))
        result = self.tc.add_strategy(strategy)
        return Response(content_type='application/json', body=json.dumps({'result': result}))

    @route('delstrategy', '/strategy/delete', methods=['POST'])
    def del_strategy(self, req, **kwargs):
        try:
            strategy = req.json if req.body else {}
        except ValueError:
            return Response(status=400, content_type='application/json', body=json.dumps({'result': 'illegal'}))
        result = self.tc.del_strategy(strategy)
        return Response(content_type='application/json', body=json.dumps({'result': result}))

from __future__ import division
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from collections import defaultdict
SLEEP_PERIOD = 2


class Network_Monitor(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'Network_Monitor'

    def __init__(self, *args, **kwargs):
        super(Network_Monitor, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.port_stats = defaultdict(lambda: defaultdict(lambda: None))
        self.port_speed = defaultdict(lambda: defaultdict(lambda: None))
        self.flow_stats = defaultdict(lambda: None)
        self.flow_speed = defaultdict(lambda: None)
        # (dpid, port): [(match, action)]
        self.dpidport_to_flow = defaultdict(lambda: None)
        self.stats = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.stats['port'] = defaultdict(lambda: None)
            self.stats['flow'] = defaultdict(lambda: None)
            for datapath in self.datapaths.values():
                self._request_stats(datapath)
            hub.sleep(SLEEP_PERIOD)
            # self.logger.info("port speed : %s", self.get_port_speed(1, 2))

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _save_stats(self, dist, key, value, length):
        if key not in dist:
            dist[key] = []
        dist[key].append(value)

        if len(dist[key]) > length:
            dist[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / period
        else:
            return 0

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})

        # TODO
        for port in self.port_stats[dpid]:
            self.dpidport_to_flow[(dpid, port)] = []

        flow_list = {}
        for flow in body:
            if (flow.priority != 0) and (flow.priority != 65535):
                in_port = flow.match.get('in_port')
                nw_src = flow.match.get('ipv4_src')
                nw_dst = flow.match.get('ipv4_dst')
                nw_proto = flow.match.get('ip_proto')
                tp_src = flow.match.get('tcp_src') or flow.match.get('udp_src')
                tp_dst = flow.match.get('tcp_dst') or flow.match.get('udp_dst')
                key = (('in_port', in_port), ('nw_src', nw_src), ('nw_dst', nw_dst),
                       ('nw_proto', nw_proto), ('tp_src', tp_src), ('tp_dst', tp_dst))
                value = (flow.packet_count, flow.byte_count, flow.duration_sec, flow.duration_nsec)
                flow_list[key] = value

                out_port = flow.instructions[0].actions[-1].port
                self.dpidport_to_flow[(dpid, out_port)].append((flow.match, flow.instructions[0].actions, flow.priority))

        # self.logger.info("flow_list : %s", str(flow_list))

        for key in self.flow_stats[dpid].keys():
            if key not in flow_list:
                # the flow has been delete
                del self.flow_stats[dpid][key]
                del self.flow_speed[dpid][key]

        for key in flow_list:
            self._save_stats(self.flow_stats[dpid], key, flow_list[key], 20)
            # Get flow's speed.
            pre = 0
            period = SLEEP_PERIOD

            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3], tmp[-2][2], tmp[-2][3])
            speed = self._get_speed(self.flow_stats[dpid][key][-1][1], pre, period) * 8
            self._save_stats(self.flow_speed[dpid], key, int(speed), 20)
            # self.logger.info('flow speed %s', self.flow_speed)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.stats['port'][ev.msg.datapath.id] = body
        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
                dpid = ev.msg.datapath.id
                port = stat.port_no
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors, stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats[dpid], port, value, 20)

                # Get port speed.
                pre = 0
                period = SLEEP_PERIOD
                tmp = self.port_stats[dpid][port]
                if len(tmp) > 1:
                    pre = tmp[-2][0]
                    period = self._get_period(tmp[-1][3], tmp[-1][4], tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(self.port_stats[dpid][port][-1][0], pre, period) * 8

                # Downlink bandwidth
                # self.port_speed = {(dpid,port):speed}
                # speed bps
                self._save_stats(self.port_speed[dpid], port, int(speed), 20)

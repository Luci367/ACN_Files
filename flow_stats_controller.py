import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from statistics import stdev

from datetime import datetime

class CollectTrainingStatsApp(switch.SimpleSwitch):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {} #storing the active datapaths
        self.monitor_thread = hub.spawn(self.monitor)

    #Asynchronous message
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)


    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        

        body = ev.msg.body
        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
                tcp_flags = stat.match['tcp_flags']
                ack_flag_count = tcp_flags & tcp_flags.ACK != 0
                urg_flag_count = tcp_flags & tcp_flags.URG != 0

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
                packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
                byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                

            try:
                
                flow_bytes_per_second = stat.byte_count / stat.duration_sec
                
                avg_packet_size = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0
            except ZeroDivisionError:
                flow_bytes_per_second = 0
                avg_packet_size = 0

            try:
               
                packet_length_min = stat.min_len #not working
                packet_length_max = stat.max_len
            except :
               
                packet_length_min = 0
                packet_length_max = 0

            try:
               
                idle_std = stdev([stat.duration_sec] * len(body)) #not working
               
                idle_max = max([stat.duration_sec] * len(body))
            except ZeroDivisionError:
                idle_std = 0
                idle_max = 0

            #['Fwd Packets Length Total', 'Fwd Packet Length Min', 'Fwd Packet Length Std', 'Flow Bytes/s', 'Bwd Packets/s', 
            # 'Packet Length Min', 'Packet Length Max', 'ACK Flag Count', 'URG Flag Count', 'Avg Packet Size', 'Fwd Act Data Packets',
            #  'Idle Std', 'Idle Max'] these features were selected by using XGBoost in RFE .


            print(f'Flow Bytes/s: {flow_bytes_per_second}')
            print(f'Avg Packet Size: {avg_packet_size}')
            print(f'Packet Length Min: {packet_length_min}')
            print(f'Packet Length Max: {packet_length_max}')
            print(f'Idle Std: {idle_std}')
            print(f'Idle Max: {idle_max}')
            print(f'ACK Flag Count: {ack_flag_count}')
            print(f'URG Flag Count: {urg_flag_count}')
            print(f'flow stats for {ip_src} and {ip_dst}')
            print()

            
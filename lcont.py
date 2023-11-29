from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet ,icmp , ipv4, in_proto, udp
import time
from ryu.lib.packet import ether_types
import statistics

#ryu-manager --ofp-listen-host=127.0.0.1 --ofp-tcp-listen-port=6653 control.py
#sudo mn --controller remote

#xterm h1 h2
#h1 - iperf -s -u -t 1000
#h2 - iperf -c 10.0.0.1 -u -b 1M -t 100

#ping - h1 ping h2



class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ETHERTYPE_MAP = {
    ether_types.ETH_TYPE_IP: 'IPv4',
    ether_types.ETH_TYPE_ARP: 'ARP',
    ether_types.ETH_TYPE_IPV6: 'IPv6'
    }

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.packet_counters = {}
        self.mac_to_port = {}# for learning switch
        self.timeout = 5
        self.packet_info = {}  # Dictionary to store packet information for each flow
        self.flow_icmp_types = {}
        self.flow_header_lengths = {}  # Dictionary to store header lengths for each flow
        self.feature_values = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry (forward to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a MAC address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if eth.ethertype not in self.ETHERTYPE_MAP:
            packet_type = hex(eth.ethertype)
        else:
            packet_type = self.ETHERTYPE_MAP[eth.ethertype]
            print(f"Received {packet_type} packet on switch {datapath.id}, in_port {in_port}")

        if eth.ethertype != ether_types.ETH_TYPE_ARP:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                if ip:
                    protocol = ip.proto
                    print(f"IP Protocol: {protocol}")

                    # if ICMP Protocol
                    if protocol == in_proto.IPPROTO_ICMP:
                        self.handle_icmp_packet(parser, datapath, msg, pkt, eth, in_port, src, dst, ip,protocol,packet_type,actions)
                    elif protocol == in_proto.IPPROTO_UDP:
                        self.handle_udp_packet(parser, datapath, msg, pkt, eth, in_port, src, dst, ip,actions)
                        # icmp_packet = pkt.get_protocol(icmp.icmp)
                        # if icmp_packet is not None:
                        #     icmp_type = icmp_packet.type

                        #     # # Store ICMP type in the list
                        #     # self.icmp_types.append(icmp_type)

                        #     icmp_code = icmp_packet.code

                        #     match = parser.OFPMatch(
                        #         eth_type=ether_types.ETH_TYPE_IP,
                        #         ipv4_src=ip.src,
                        #         ipv4_dst=ip.dst,
                        #         ip_proto=protocol,
                        #         icmpv4_type=icmp_type,
                        #         icmpv4_code=icmp_code
                        #     )

                        #     flow_key = (src, dst, protocol, icmp_type, icmp_code)  # identifier

                        #     packet_length = len(msg.data)
                        #     print(f"Packet length: {packet_length} bytes")
                        #     print()
                        #     packet_time = time.time()
                        #     print(f"Packet received at time {packet_time}")
                        #     print()
                            

                        #     self.store_packet_info(flow_key, packet_length, packet_time)

                        #     #storing icmp types for flow
                        #     if flow_key not in self.flow_icmp_types:
                        #         self.flow_icmp_types[flow_key] = []

                        #     self.flow_icmp_types[flow_key].append(icmp_type)

                        #     #storing header length of a flow
                        #     eth_header_len = len(eth)  # Ethernet header length
                        #     ip_header_len = (ip.header_length & 0xF) * 4  # IPv4 header length
                        #     icmp_header_len = len(icmp_packet)  # ICMPv4 header length

                        #     if flow_key not in self.flow_header_lengths:
                        #         self.flow_header_lengths[flow_key] = {'eth': [], 'ip': [], 'icmp': []}

                        #     self.flow_header_lengths[flow_key]['eth'].append(eth_header_len)
                        #     self.flow_header_lengths[flow_key]['ip'].append(ip_header_len)
                        #     self.flow_header_lengths[flow_key]['icmp'].append(icmp_header_len)




                            

                            # if flow_key not in self.packet_counters:
                            #     self.packet_counters[flow_key] = 0
                            
                            # self.packet_counters[flow_key] += 1
                            # # print(f'{flow_key[0]} to {flow_key[1]}: No. {self.packet_counters[flow_key]}')

                            # if self.packet_counters[flow_key] == 10:
                            #     #adding flow after 100 packets
                            #     # match = parser.OFPMatch(eth_src=src, eth_dst=dst)
                            #     self.calculate_and_print_features(flow_key)
                            #     self.add_flow(datapath, 1, match, actions, hard=20)
                            #     print("Flow entry added.")

                            #     self.packet_counters[flow_key] = 0
                            # else:
                            #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                            #                         in_port=in_port, actions=actions, data=msg.data)
                            #     datapath.send_msg(out)
                        # else:
                        #     # Forward the packet to the destination without adding a flow entry
                        #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                        #                             in_port=in_port, actions=actions, data=msg.data)
                        #     datapath.send_msg(out)
                        #     print(f"{packet_type} packet forwarded")
                        #     print()
                    else:
                        # Add a flow entry for non-ICMP packets
                        match = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip.src,
                            ipv4_dst=ip.dst,
                            ip_proto=protocol 
                        )
                        self.add_flow(datapath, 1, match, actions)
                        print(f"Flow entry added for non-ICMP {packet_type} packet")

        # For non-IP packets or ARP, print packet features and forward the packet
        else:
            packet_length = len(msg.data)
            print(f"Packet length: {packet_length} bytes")
            print()
            # Add a flow entry for non-IP packets or ARP
            match = parser.OFPMatch(eth_type=eth.ethertype)
            self.add_flow(datapath, 1, match, actions)
            print(f"Flow entry added for {packet_type} packet")
            # Forward the packet to the destination without adding a flow entry
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            print(f"{packet_type} packet forwarded")
            print()
            

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)

    def store_header_lengths(self, flow_key, eth_header_len, ip_header_len, protocol_header_len):
        if flow_key not in self.flow_header_lengths:
            self.flow_header_lengths[flow_key] = {'eth': [], 'ip': [], 'protocol': []}

        self.flow_header_lengths[flow_key]['eth'].append(eth_header_len)
        self.flow_header_lengths[flow_key]['ip'].append(ip_header_len)
        self.flow_header_lengths[flow_key]['protocol'].append(protocol_header_len)

    def handle_udp_packet(self, parser, datapath, msg, pkt, eth, in_port, src, dst, ip,actions):
        udp_packet = pkt.get_protocol(udp.udp)
        if udp_packet is not None:
            udp_src_port = udp_packet.src_port
            udp_dst_port = udp_packet.dst_port

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src,
                ipv4_dst=ip.dst,
                ip_proto=in_proto.IPPROTO_UDP,
                udp_src=udp_src_port,
                udp_dst=udp_dst_port
            )

            flow_key = (src, dst, udp_src_port, udp_dst_port)
            packet_length = len(msg.data)
            print(f'UDP Packet Length: {packet_length} bytes')
            print()
            packet_time = time.time()
            print(f"Packet received at time {packet_time}")
            print()


            self.store_packet_info(flow_key, packet_length, packet_time)

            
            eth_header_len = len(eth)
            ip_header_len = (ip.header_length & 0xF) * 4
            udp_header_len = 8 #fixed udp header length

            self.store_header_lengths(flow_key, eth_header_len, ip_header_len, udp_header_len)

            self.handle_packet(parser,msg,in_port, match, actions, datapath, flow_key)

    def handle_icmp_packet(self, parser, datapath, msg, pkt, eth, in_port, src, dst, ip,protocol,packet_type,actions):
        icmp_packet = pkt.get_protocol(icmp.icmp)
        if icmp_packet is not None:
            icmp_type = icmp_packet.type

            # # Store ICMP type in the list
            # self.icmp_types.append(icmp_type)

            icmp_code = icmp_packet.code

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip.src,
                ipv4_dst=ip.dst,
                ip_proto=protocol,
                icmpv4_type=icmp_type,
                icmpv4_code=icmp_code
            )

            flow_key = (src, dst, protocol, icmp_type, icmp_code)  # identifier

            packet_length = len(msg.data)
            print(f"Packet length: {packet_length} bytes")
            print()
            packet_time = time.time()
            print(f"Packet received at time {packet_time}")
            print()
            

            self.store_packet_info(flow_key, packet_length, packet_time)

            #storing icmp types for flow
            if flow_key not in self.flow_icmp_types:
                self.flow_icmp_types[flow_key] = []

            self.flow_icmp_types[flow_key].append(icmp_type)

            #storing header length of a flow
            eth_header_len = len(eth)  # Ethernet header length
            ip_header_len = (ip.header_length & 0xF) * 4  # IPv4 header length
            icmp_header_len = len(icmp_packet)  # ICMPv4 header length

            self.store_header_lengths( flow_key, eth_header_len, ip_header_len, icmp_header_len)

            # if flow_key not in self.flow_header_lengths:
            #     self.flow_header_lengths[flow_key] = {'eth': [], 'ip': [], 'icmp': []}

            # self.flow_header_lengths[flow_key]['eth'].append(eth_header_len)
            # self.flow_header_lengths[flow_key]['ip'].append(ip_header_len)
            # self.flow_header_lengths[flow_key]['icmp'].append(icmp_header_len)

            self.handle_packet(parser,msg,in_port, match, actions, datapath, flow_key)



        
        else:
            # Forward the packet to the destination without adding a flow entry
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            print(f"{packet_type} packet forwarded")
            print()





            

            # if flow_key not in self.packet_counters:
            #     self.packet_counters[flow_key] = 0
            
            # self.packet_counters[flow_key] += 1
            # # print(f'{flow_key[0]} to {flow_key[1]}: No. {self.packet_counters[flow_key]}')

            # if self.packet_counters[flow_key] == 10:
            #     #adding flow after 100 packets
            #     # match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            #     self.calculate_and_print_features(flow_key)
            #     self.add_flow(datapath, 1, match, actions, hard=20)
            #     print("Flow entry added.")

            #     self.packet_counters[flow_key] = 0

    def handle_packet(self,parser,msg,in_port, match, actions, datapath, flow_key):

        if flow_key not in self.packet_counters:
            self.packet_counters[flow_key] = 0
        
        self.packet_counters[flow_key] += 1
        # print(f'{flow_key[0]} to {flow_key[1]}: No. {self.packet_counters[flow_key]}')

        if self.packet_counters[flow_key] == 10:#change this for threshold
            #adding flow after 100 packets
            # match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            self.calculate_and_print_features(flow_key)
            #TODO :yaha ML daalna hai
            self.add_flow(datapath, 1, match, actions, hard=20)
            print("Flow entry added.")

            self.packet_counters[flow_key] = 0
        else:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)

        # packet_time = time.time()
        # print(f"Packet received at time {packet_time}")
        # print()
        

        

        # if flow_key not in self.packet_counters:
        #     self.packet_counters[flow_key] = 0
        
        # self.packet_counters[flow_key] += 1

        # if self.packet_counters[flow_key] == 100:
        #     #adding flow after 100 packets
        #     # match = parser.OFPMatch(eth_src=src, eth_dst=dst)
        #     self.add_flow(datapath, 1, match, actions)
        #     print("Flow entry added.")

        #     self.packet_counters[flow_key] = 0
        # # else:
        # #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        # #                           in_port=in_port, actions=actions, data=data)
        # #     datapath.send_msg(out)

    def store_packet_info(self, flow_key, packet_length, packet_time):
        # Initialize information for the flow if not exists
        if flow_key not in self.packet_info:
            self.packet_info[flow_key] = {'lengths': [], 'times': []}

        # Store packet information
        self.packet_info[flow_key]['lengths'].append(packet_length)
        self.packet_info[flow_key]['times'].append(packet_time)
    
    def calculate_and_print_features(self, flow_key):
        # Get packet information from the stored data
        packet_lengths = self.packet_info[flow_key]['lengths']
        packet_times = self.packet_info[flow_key]['times']

        # Calculate features
        fwd_packet_length_min = min(packet_lengths)
        fwd_packet_length_mean = sum(packet_lengths) / len(packet_lengths)
        flow_bytes_per_sec = sum(packet_lengths) / (max(packet_times) - min(packet_times))
        flow_iat_mean = sum([t2 - t1 for t1, t2 in zip(packet_times[:-1], packet_times[1:])]) / len(packet_times)
        flow_iat_std = statistics.stdev([t2 - t1 for t1, t2 in zip(packet_times[:-1], packet_times[1:])])
        fwd_header_length = sum([eth_header_len + ip_header_len + protocol_header_len 
                                 for eth_header_len, ip_header_len, protocol_header_len in zip(self.flow_header_lengths[flow_key]['eth']
                                                                                           , self.flow_header_lengths[flow_key]['ip'],
                                                                                             self.flow_header_lengths[flow_key]['protocol'])])
        packet_length_min = min(packet_lengths)
        packet_length_max = max(packet_lengths)
        packet_length_mean = sum(packet_lengths) / len(packet_lengths)
        ack_flag_count = sum([1 for icmp_type in self.flow_icmp_types if icmp_type == 0x05])  # Assuming 0x05 is the ACK type
        average_packet_size = sum(packet_lengths) / len(packet_lengths)
        avg_fwd_segment_size = fwd_header_length/len(packet_lengths)
        # avg_fwd_segment_size = sum([eth_len + ip_len + icmp_len for eth_len, ip_len, icmp_len in zip(eth_lengths, ip_lengths, icmp_lengths)]) / len(packet_lengths)
        subflow_fwd_bytes = sum(packet_lengths) / len(packet_lengths)

        # Print or store the calculated features as needed
        print(f'Fwd Packet Length Min: {fwd_packet_length_min}')
        print(f'Fwd Packet Length Mean: {fwd_packet_length_mean}')
        print(f'Flow Bytes/s: {flow_bytes_per_sec}')
        print(f'Flow IAT Mean: {flow_iat_mean}')
        print(f'Flow IAT Std: {flow_iat_std}')
        print(f'Fwd Header Length: {fwd_header_length}')
        print(f'Packet Length Min: {packet_length_min}')
        print(f'Packet Length Max: {packet_length_max}')
        print(f'Packet Length Mean: {packet_length_mean}')
        print(f'ACK Flag Count: {ack_flag_count}')
        print(f'Average Packet Size: {average_packet_size}')
        print(f'Avg Fwd Segment Size: {avg_fwd_segment_size}')
        print(f'Subflow Fwd Bytes: {subflow_fwd_bytes}')

        # Store the calculated features if needed
        self.feature_values[flow_key] = {
            'Fwd Packet Length Min': fwd_packet_length_min,
            'Fwd Packet Length Mean': fwd_packet_length_mean,
            'Flow Bytes/s': flow_bytes_per_sec,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Std': flow_iat_std,
            'Fwd Header Length': fwd_header_length,
            'Packet Length Min': packet_length_min,
            'Packet Length Max': packet_length_max,
            'Packet Length Mean': packet_length_mean,
            'ACK Flag Count': ack_flag_count,
            'Average Packet Size': average_packet_size,
            'Avg Fwd Segment Size': avg_fwd_segment_size,
            'Subflow Fwd Bytes': subflow_fwd_bytes
        }
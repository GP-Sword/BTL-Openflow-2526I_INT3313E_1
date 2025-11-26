from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
import pox.openflow.libopenflow_01 as of

log = core.getLogger("ip_handler")

class IPHandler:
    def __init__(self, arp_handler, flow_installer, firewall):
        self.arp = arp_handler
        self.flows = flow_installer
        self.fw = firewall
        self.waiting_packets = {} 

    def get_gateway(self, ip_str):
        if ip_str.startswith("10.0.1"): return '10.0.1.1'
        if ip_str.startswith("10.0.2"): return '10.0.2.1'
        if ip_str.startswith("10.0.3"): return '10.0.3.1'
        return None

    def handle_packet(self, event, mac_to_port):
        packet = event.parsed
        ip_pkt = packet.payload
        dst_ip = str(ip_pkt.dstip)
        src_ip = str(ip_pkt.srcip)
        
        # 1. Firewall
        if not self.fw.is_allowed(ip_pkt):
            return True 

        # 2. Router Interaction
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8:
                self.send_icmp_reply(event, ip_pkt)
            return True 

        # 3. Routing
        src_gw = self.get_gateway(src_ip)
        dst_gw = self.get_gateway(dst_ip)

        # Intra-subnet (L2)
        if src_gw == dst_gw:
            return False 
            
        if not dst_gw: 
            return False 

        # Inter-subnet (L3)
        dst_mac = self.arp.arp_cache.get(dst_ip)
        
        if dst_mac:
            self.forward_l3_packet(event, dst_ip, dst_mac, dst_gw, mac_to_port)
        else:
            # Queue and Flood Discovery
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                # Use the new helper in arp_handler to flood safely
                self.arp._flood_arp_request_from_controller(dst_ip)
            
            self.waiting_packets[dst_ip].append(event)
            # log.debug("Buffered packet for %s, waiting for ARP", dst_ip)
            
        return True 

    def forward_l3_packet(self, event, dst_ip, dst_mac, dst_gw_ip, mac_to_port):
        dpid = event.dpid
        src_mac_gw = self.arp.router_macs[dst_gw_ip]
        
        out_port = None
        if dst_mac in mac_to_port.get(dpid, {}):
            out_port = mac_to_port[dpid][dst_mac]
        
        if out_port:
            self.flows.install_l3_flow(event.connection, dst_ip, src_mac_gw, dst_mac, out_port)
            
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gw))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
        else:
            # Path unknown: DROP (Do not flood data packets in ring)
            # We wait for ARP to populate mac_to_port tables
            pass

    def send_icmp_reply(self, event, ip_pkt):
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)

    def process_waiting_packets(self, ip_str, mac_addr, mac_to_port):
        if ip_str in self.waiting_packets:
            gw = self.get_gateway(ip_str)
            for event in self.waiting_packets[ip_str]:
                self.forward_l3_packet(event, ip_str, mac_addr, gw, mac_to_port)
            del self.waiting_packets[ip_str]
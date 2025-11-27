from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr
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

    def handle_ip_packet(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        
        # 1. Packet to Router (Ping Gateway)
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8: # Echo Req
                self.send_icmp_reply(event, ip_pkt)
            return True 
            
        src_gw = self.get_gateway(src_ip)
        dst_gw = self.get_gateway(dst_ip)
        
        # 2. Check Routing Necessity
        if not dst_gw or src_gw == dst_gw:
            return False 

        # 3. Inter-subnet Routing (L3)
        # If we know the Destination MAC and Location
        if dst_ip in self.arp.arp_cache and dst_ip in self.arp.ip_port_map:
            self.forward_l3_packet(event, dst_ip, dst_gw)
        else:
            # Unknown Info -> Queue packet and send ARP Request
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                self.arp.send_arp_request_from_controller(dst_ip, event)
            self.waiting_packets[dst_ip].append(event)
            
        return True

    def forward_l3_packet(self, event, dst_ip, dst_gw_ip):
        """
        Execute Routing logic using 'Teleportation' (Direct Egress Injection).
        Guarantees delivery by bypassing transit L2 lookups.
        """
        dst_mac = self.arp.arp_cache[dst_ip]
        src_mac_gateway = self.arp.router_macs[dst_gw_ip]
        
        # Get Destination Switch and Port
        # Thanks to the fix in ARPHandler, this is now guaranteed to be the Edge Switch
        egress_dpid, egress_port = self.arp.ip_port_map[dst_ip]
        
        if self.fw.check_firewall(egress_dpid, event.parsed.payload) == "DENY":
            self.send_icmp_unreachable(event.parsed.payload, event.parsed, event.ofp, event)
            return

        # --- STEP 1: SEND PACKET (Teleportation) ---
        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gateway))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=egress_port))
        
        # Send directly to the switch where the host is located
        core.openflow.sendToDPID(egress_dpid, msg)

        # --- STEP 2: INSTALL FLOW (Optimization) ---
        ingress_dpid = event.dpid
        out_port_ingress = None
        
        # Try to install flow on the ingress switch to speed up next packets
        if ingress_dpid == egress_dpid:
            out_port_ingress = egress_port
        elif dst_mac in self.arp.mac_to_port[ingress_dpid]:
            # Use L2 learning to find path
            out_port_ingress = self.arp.mac_to_port[ingress_dpid][dst_mac]
        
        if out_port_ingress:
            self.flows.install_l3_flow(event.connection, dst_ip, src_mac_gateway, dst_mac, out_port_ingress)

    def process_waiting_packets(self, ip_str):
        if ip_str in self.waiting_packets:
            gw = self.get_gateway(ip_str)
            for event in self.waiting_packets[ip_str]:
                if ip_str in self.arp.ip_port_map:
                    self.forward_l3_packet(event, ip_str, gw)
            del self.waiting_packets[ip_str]

    def send_icmp_reply(self, event, ip_pkt):
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)

    def send_icmp_unreachable(self, ip_pkt, eth_pkt, pkt_in, event):
        icmp_unr = icmp(type=3, code=0, payload=ip_pkt.pack()[:28])
        src_gw = self.get_gateway(str(ip_pkt.srcip))
        if not src_gw: return
        
        gw_mac = self.arp.router_macs[src_gw]
        
        ip_rpl = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=IPAddr(src_gw), dstip=ip_pkt.srcip, payload=icmp_unr)
        eth_rpl = ethernet(type=ethernet.IP_TYPE, src=gw_mac, dst=eth_pkt.src, payload=ip_rpl)
        
        msg = of.ofp_packet_out(data=eth_rpl.pack())
        msg.actions.append(of.ofp_action_output(port=pkt_in.in_port))
        event.connection.send(msg)
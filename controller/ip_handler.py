from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger("ip_handler")

class IPHandler:
    def __init__(self, arp_cache, ip_port_map, mac_to_port, flow_installer, firewall, arp_handler):
        self.arp_cache = arp_cache
        self.ip_port_map = ip_port_map
        self.mac_to_port = mac_to_port
        self.flows = flow_installer
        self.fw = firewall
        self.arp_h = arp_handler
        
        self.packet_waiting = {} # {dst_ip: [event, ...]}

    def get_gateway(self, ip_str):
        if ip_str.startswith("10.0.1"): return '10.0.1.1'
        if ip_str.startswith("10.0.2"): return '10.0.2.1'
        if ip_str.startswith("10.0.3"): return '10.0.3.1'
        return None

    def handle_ip_packet(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        dst_ip = str(ip_pkt.dstip)
        src_ip = str(ip_pkt.srcip)
        
        
        # 1. Packet to Router (Ping Gateway)
        if dst_ip in self.arp_h.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8: # Echo Req
                self.send_icmp_reply(event, ip_pkt)
            return True # Handled by L3
            
        src_gw = self.get_gateway(src_ip)
        dst_gw = self.get_gateway(dst_ip)
        
        # 2. Check Routing Necessity
        # If gateway not found (Internet?) or same subnet -> Let L2 handle
        if not dst_gw or src_gw == dst_gw:
            return False 

        # 3. Inter-subnet Routing (L3)
        # Check if we have MAC and Port info for destination
        if dst_ip in self.arp_cache and dst_ip in self.ip_port_map:
            self.forward_l3_packet(event, dst_ip, dst_gw)
        else:
            # Unknown info -> Queue packet and send ARP Request
            log.info("L3: Unknown MAC/Port for %s. Queueing and ARPing.", dst_ip)
            if dst_ip not in self.packet_waiting:
                self.packet_waiting[dst_ip] = []
                self.arp_h.send_arp_request_from_controller(dst_ip, event)
            self.packet_waiting[dst_ip].append(event)
            
        return True

    def forward_l3_packet(self, event, dst_ip, dst_gw_ip):
        """
        Execute Routing logic: Rewrite MAC + Forward + Install Flow
        """
        dst_mac = self.arp_cache[dst_ip]
        # Get router MAC of DESTINATION subnet to use as new source MAC
        src_mac_gateway = self.arp_h.router_macs[dst_gw_ip]
        
        # Find egress switch and port of destination host
        egress_dpid, egress_port = self.ip_port_map[dst_ip]
        
        # Find output port on CURRENT Switch (Ingress Switch) to reach destination
        # This is critical logic for Ring/Mesh Topology
        ingress_dpid = event.dpid
        out_port_on_ingress = None
        
        if ingress_dpid == egress_dpid:
            # Destination host is on this switch
            out_port_on_ingress = egress_port
        else:
            # Destination host is on another switch
            # Use L2 Learning table to find port to reach dest MAC
            if dst_mac in self.mac_to_port[ingress_dpid]:
                out_port_on_ingress = self.mac_to_port[ingress_dpid][dst_mac]
            else:
                log.warning("L3: Waiting for L2 path to %s on dpid %s", dst_mac, ingress_dpid)
                return # Wait for L2 to learn path (ARP flood will help)

        # Check Firewall (Proactive check for Egress)
        if self.fw.check_firewall(egress_dpid, event.parsed.payload) == "DENY":
            self.send_icmp_unreachable(event.parsed.payload, event.parsed, event.ofp, event)
            return

        # Install L3 Flow (MAC Rewrite) on current switch
        self.flows.install_l3_flow(event.connection, dst_ip, src_mac_gateway, dst_mac, out_port_on_ingress)
        
        # Send packet out
        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gateway))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port_on_ingress))
        event.connection.send(msg)
        
        log.info("L3: Routed %s -> %s via dpid %s port %s", 
                 event.parsed.payload.srcip, dst_ip, ingress_dpid, out_port_on_ingress)

    def process_waiting_packets(self, ip_str):
        """Process waiting packets after successful ARP"""
        if ip_str in self.packet_waiting:
            gw = self.get_gateway(ip_str)
            for event in self.packet_waiting[ip_str]:
                # Check IP_PORT_MAP again as ARP Handler just updated it
                if ip_str in self.ip_port_map:
                    self.forward_l3_packet(event, ip_str, gw)
            del self.packet_waiting[ip_str]

    def send_icmp_reply(self, event, ip_pkt):
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)

    def send_icmp_unreachable(self, ip_pkt, eth_pkt, pkt_in, event):
        # Create ICMP Destination Unreachable packet
        icmp_unr = icmp(type=3, code=0, payload=ip_pkt.pack()[:28])
        src_gw = self.get_gateway(str(ip_pkt.srcip))
        if not src_gw: return
        
        gw_mac = self.arp_h.router_macs[src_gw]
        
        ip_rpl = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=IPAddr(src_gw), dstip=ip_pkt.srcip, payload=icmp_unr)
        eth_rpl = ethernet(type=ethernet.IP_TYPE, src=gw_mac, dst=eth_pkt.src, payload=ip_rpl)
        
        msg = of.ofp_packet_out(data=eth_rpl.pack())
        msg.actions.append(of.ofp_action_output(port=pkt_in.in_port))
        event.connection.send(msg)
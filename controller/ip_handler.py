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
        self.waiting_packets = {} # IP -> List of events

    def get_gateway(self, ip_str):
        """Returns the gateway IP for a given host IP."""
        # Simple string matching for this lab
        if ip_str.startswith("10.0.1"): return '10.0.1.1'
        if ip_str.startswith("10.0.2"): return '10.0.2.1'
        if ip_str.startswith("10.0.3"): return '10.0.3.1'
        return None

    def handle_packet(self, event, mac_to_port):
        """
        Returns True if handled as L3 packet.
        Returns False if it should be handled as L2 (intra-subnet).
        """
        packet = event.parsed
        ip_pkt = packet.payload
        dst_ip = str(ip_pkt.dstip)
        src_ip = str(ip_pkt.srcip)
        
        # 1. Firewall Check
        if not self.fw.is_allowed(ip_pkt):
            return True # Drop (Handled)

        # 2. Check if packet is for Router itself (Ping Gateway)
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8:
                self.send_icmp_reply(event, ip_pkt)
            return True # Handled

        # 3. Routing Logic
        src_gw = self.get_gateway(src_ip)
        dst_gw = self.get_gateway(dst_ip)

        # FIX: Intra-subnet traffic (Same Gateway) should be handled by L2 Switching
        if src_gw == dst_gw:
            return False # Let controller do L2 switching
            
        if not dst_gw: 
            return False # Unknown network, maybe L2 broadcast or Internet

        # 4. Inter-subnet Routing
        # Check ARP cache for Final Destination Host
        dst_mac = self.arp.arp_cache.get(dst_ip)
        
        if dst_mac:
            # We have the MAC, perform L3 Forwarding
            self.forward_l3_packet(event, dst_ip, dst_mac, dst_gw, mac_to_port)
        else:
            # MAC unknown, queue packet and send ARP Request (Flood all switches)
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                for connection in core.openflow.connections:
                    self.arp.send_arp_request(connection, dst_ip, dst_gw)
            
            self.waiting_packets[dst_ip].append(event)
            log.debug("Buffered packet for %s, waiting for ARP", dst_ip)
            
        return True # Handled as L3

    def forward_l3_packet(self, event, dst_ip, dst_mac, dst_gw_ip, mac_to_port):
        dpid = event.dpid
        src_mac_gw = self.arp.router_macs[dst_gw_ip]
        
        # Rewrite Headers (Router Function)
        # We need to send this Modified Packet.
        # Logic: Rewrite MACs -> Treat as L2 packet to reach destination
        
        out_port = None
        # Check if we know the Output Port on THIS switch
        if dst_mac in mac_to_port.get(dpid, {}):
            out_port = mac_to_port[dpid][dst_mac]
        
        if out_port:
            # Path is known: Install Flow + Unicast
            # Install Flow matching Destination IP
            self.flows.install_l3_flow(event.connection, dst_ip, src_mac_gw, dst_mac, out_port)
            
            # Send Packet
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gw))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
            # log.debug("L3 Routed %s -> %s via port %s", dst_gw_ip, dst_ip, out_port)
        else:
            # Path unknown on this switch: Flood (Safe due to STP)
            # This allows the packet to traverse the mesh until it finds the host
            # Once reply comes back, switches will learn the path.
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gw))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            # log.debug("L3 Flooding %s -> %s (Path unknown)", dst_gw_ip, dst_ip)

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
                # Re-check ARP and forward
                self.forward_l3_packet(event, ip_str, mac_addr, gw, mac_to_port)
            del self.waiting_packets[ip_str]
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
        self.waiting_packets = {} # IP -> List of (event, packet)
        
        # Subnet Definitions
        self.subnets = {
            '10.0.1.1': '10.0.1.0/24',
            '10.0.2.1': '10.0.2.0/24',
            '10.0.3.1': '10.0.3.0/24'
        }

    def get_gateway(self, ip_str):
        """Returns the gateway IP for a given host IP."""
        # Simple string matching for this lab
        if ip_str.startswith("10.0.1"): return '10.0.1.1'
        if ip_str.startswith("10.0.2"): return '10.0.2.1'
        if ip_str.startswith("10.0.3"): return '10.0.3.1'
        return None

    def handle_packet(self, event, mac_to_port):
        packet = event.parsed
        ip_pkt = packet.payload
        dst_ip = str(ip_pkt.dstip)
        
        # 1. Firewall Check
        if not self.fw.is_allowed(ip_pkt):
            return # Drop

        # 2. Check if packet is for the Router itself (Ping Gateway)
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8: # Echo Req
                self.send_icmp_reply(event, ip_pkt)
            return

        # 3. Routing Logic
        dst_gw = self.get_gateway(dst_ip)
        if not dst_gw: return # Unknown subnet

        # Check ARP cache for Destination MAC
        dst_mac = self.arp.arp_cache.get(dst_ip)
        
        if dst_mac:
            # We know the MAC, forward it
            self.forward_packet(event, dst_ip, dst_mac, dst_gw, mac_to_port)
        else:
            # MAC unknown, queue packet and send ARP Request
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                # Send ARP Request from the correct gateway
                self.arp.send_arp_request(event.connection, dst_ip, dst_gw)
            
            self.waiting_packets[dst_ip].append((event, packet))
            log.debug("Buffered packet for %s, waiting for ARP", dst_ip)

    def forward_packet(self, event, dst_ip, dst_mac, dst_gw_ip, mac_to_port):
        # Determine Out Port
        # In a real Router, this comes from a routing table.
        # In this SDN Lab, we use L2 learning (mac_to_port) to find the path to the host.
        dpid = event.dpid
        
        if dst_mac in mac_to_port.get(dpid, {}):
            out_port = mac_to_port[dpid][dst_mac]
            src_mac = self.arp.router_macs[dst_gw_ip]
            
            # Send Packet Out
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
            
            # Install Flow for future packets
            self.flows.install_l3_flow(event.connection, dst_ip, src_mac, dst_mac, out_port)
        else:
            # If we don't know the port yet, Flood (L2 fallback) or wait
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

    def send_icmp_reply(self, event, ip_pkt):
        # Helper to send ICMP Echo Reply
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)

    def process_waiting_packets(self, ip_str, mac_addr, mac_to_port):
        """Called when ARP reply is received."""
        if ip_str in self.waiting_packets:
            gw = self.get_gateway(ip_str)
            for event, packet in self.waiting_packets[ip_str]:
                self.forward_packet(event, ip_str, mac_addr, gw, mac_to_port)
            del self.waiting_packets[ip_str]
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
import pox.openflow.libopenflow_01 as of

log = core.getLogger("ip_handler")

class IPHandler:
    def __init__(self, arp_handler, flow_installer, firewall, subnets):
        self.arp = arp_handler
        self.flows = flow_installer
        self.fw = firewall
        self.subnets = subnets
        self.waiting_packets = {} 

    def get_gateway_ip(self, ip_str):
        for cidr, info in self.subnets.items():
            prefix = cidr.split('/')[0].rsplit('.', 1)[0]
            if ip_str.startswith(prefix):
                return info['gw_ip']
        return None

    def _get_inter_switch_link(self, src_dpid, dst_dpid):
        """
        Find the output port on src_dpid that leads to dst_dpid
        using POX Discovery module (Adjacency list).
        """
        for link in core.openflow_discovery.adjacency:
            if link.dpid1 == src_dpid and link.dpid2 == dst_dpid:
                return link.port1
        return None

    def handle_ip_packet(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        
        # 1. Packet to Router (Ping Gateway)
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8:
                self.send_icmp_reply(event, ip_pkt)
            return True 
            
        src_gw = self.get_gateway_ip(src_ip)
        dst_gw = self.get_gateway_ip(dst_ip)
        
        # 2. Check Routing Necessity 
        if not dst_gw: return False 
        
        # If same Gateway (Same Subnet), Return False to let L2 Switching handle it
        if src_gw == dst_gw:
            return False

        # 3. L3 Routing
        if dst_ip in self.arp.arp_cache and dst_ip in self.arp.ip_port_map:
            self.forward_l3_packet(event, src_ip, dst_ip, dst_gw)
        else:
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                self.arp.send_arp_request_from_controller(dst_ip, event)
            self.waiting_packets[dst_ip].append(event)
            
        return True

    def forward_l3_packet(self, event, src_ip, dst_ip, dst_gw_ip):
        dst_mac = self.arp.arp_cache[dst_ip]
        src_mac_gateway = self.arp.router_macs[dst_gw_ip]
        
        ingress_dpid = event.dpid
        egress_dpid, egress_port = self.arp.ip_port_map[dst_ip]
        
        # 1. Find Path from Ingress -> Egress
        if ingress_dpid != egress_dpid:
            # Find the port on Ingress switch that leads to Egress switch
            link_port = self._get_inter_switch_link(ingress_dpid, egress_dpid)
            
            if link_port:
                # Install L3 Flow on Ingress Switch: Rewrite MACs + Send to Next Hop Switch
                # This ensures Packet 2+ goes directly via hardware
                self.flows.install_l3_flow(
                    event.connection, # Connection to Ingress Switch
                    dst_ip, src_mac_gateway, dst_mac, link_port
                )
                log.debug("Installed Ingress L3 Flow on s%s -> s%s (port %s)", 
                          ingress_dpid, egress_dpid, link_port)

        # 2. Install Flow on Egress Switch (Last Hop)
        # We need this so the last switch knows to output to the Host port
        self.flows.install_l3_flow(
            core.openflow.getConnection(egress_dpid), 
            dst_ip, src_mac_gateway, dst_mac, egress_port
        )

        # 3. Teleport Current Packet (Packet #1)
        # We still teleport packet #1 to ensure lowest latency for the very first packet
        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_gateway))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=egress_port))
        core.openflow.sendToDPID(egress_dpid, msg)

        # 4. Reverse Flow (Optimization for Reply)
        if src_ip in self.arp.ip_port_map:
            src_dpid, src_port = self.arp.ip_port_map[src_ip]
            src_gw_ip = self.get_gateway_ip(src_ip)
            if src_gw_ip:
                src_gw_mac = self.arp.router_macs[src_gw_ip]
                src_mac_host = self.arp.arp_cache.get(src_ip)
                if src_mac_host:
                    self.flows.install_l3_flow(
                        core.openflow.getConnection(src_dpid),
                        src_ip, src_gw_mac, src_mac_host, src_port
                    )

    def process_waiting_packets(self, ip_str):
        if ip_str in self.waiting_packets:
            gw = self.get_gateway_ip(ip_str)
            for event in self.waiting_packets[ip_str]:
                packet = event.parsed
                src_ip = str(packet.payload.srcip)
                if ip_str in self.arp.ip_port_map:
                    self.forward_l3_packet(event, src_ip, ip_str, gw)
            del self.waiting_packets[ip_str]

    def send_icmp_reply(self, event, ip_pkt):
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)
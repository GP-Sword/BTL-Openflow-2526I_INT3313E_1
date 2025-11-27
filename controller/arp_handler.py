from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import time

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self, arp_cache, ip_port_map, mac_to_port, subnets):
        self.arp_cache = arp_cache
        self.ip_port_map = ip_port_map
        self.mac_to_port = mac_to_port
        self.subnets = subnets
        
        self.router_macs = {}
        for cidr, info in self.subnets.items():
            self.router_macs[info['gw_ip']] = EthAddr(info['gw_mac'])
        
        self.arp_history = {}
        self.ARP_DEDUP_WINDOW = 2.0

    def handle_arp_packet(self, packet, event):
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc
        dpid = event.dpid
        in_port = event.port

        # 1. Update State
        self.arp_cache[src_ip] = src_mac
        
        if src_ip not in self.ip_port_map:
            if not self.is_switch_link(dpid, in_port):
                self.ip_port_map[src_ip] = (dpid, in_port)
                log.debug("ARP: Learned %s at Switch %s Port %s", src_ip, dpid, in_port)
        
        # 2. Handle ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            dst_ip = str(arp_pkt.protodst)
            
            if dst_ip in self.router_macs:
                self.send_arp_reply(packet, event, self.router_macs[dst_ip])
                return

            if dst_ip in self.arp_cache:
                dst_mac = self.arp_cache[dst_ip]
                self.send_arp_reply(packet, event, dst_mac)
            else:
                self.flood_arp_request(event, src_ip, dst_ip)
        
        # 3. Handle ARP Reply (Forwarding Unicast)
        elif arp_pkt.opcode == arp.REPLY:
            dst_ip = str(arp_pkt.protodst)
            if dst_ip not in self.router_macs and dst_ip in self.ip_port_map:
                self.forward_arp_packet(event, dst_ip)

    def is_switch_link(self, dpid, port):
        """Check if port connects to another switch (ISL)"""
        try:
            for link in core.openflow_discovery.adjacency:
                if (link.dpid1 == dpid and link.port1 == port) or \
                   (link.dpid2 == dpid and link.port2 == port):
                    return True
        except:
            pass
        return False

    def send_arp_reply(self, request_packet, event, src_mac):
        arp_req = request_packet.payload
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwdst = arp_req.hwsrc
        arp_rep.protosrc = arp_req.protodst
        arp_rep.protodst = arp_req.protosrc
        arp_rep.hwsrc = src_mac
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=request_packet.src)
        eth.payload = arp_rep
        
        msg = of.ofp_packet_out(data=eth.pack())
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

    def flood_arp_request(self, event, src_ip, dst_ip):
        req_key = (src_ip, dst_ip)
        now = time.time()
        if req_key in self.arp_history:
            if now - self.arp_history[req_key] < self.ARP_DEDUP_WINDOW:
                return
        self.arp_history[req_key] = now

        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        
    def forward_arp_packet(self, event, dst_ip):
        """Forward unicast ARP reply to the destination host"""
        dpid, out_port = self.ip_port_map[dst_ip]
        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_output(port=out_port))
        core.openflow.sendToDPID(dpid, msg)

    def send_arp_request_from_controller(self, target_ip):
        src_gw_ip = None
        for cidr, info in self.subnets.items():
            network_prefix = cidr.split('/')[0].rsplit('.', 1)[0]
            if target_ip.startswith(network_prefix):
                src_gw_ip = info['gw_ip']
                break
        
        if not src_gw_ip: return

        router_mac = self.router_macs[src_gw_ip]
        
        r = arp()
        r.opcode = arp.REQUEST
        r.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        r.hwsrc = router_mac
        r.protosrc = IPAddr(src_gw_ip)
        r.protodst = IPAddr(target_ip)
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=router_mac, dst=r.hwdst)
        eth.payload = r
        
        msg = of.ofp_packet_out(data=eth.pack())
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        
        for connection in core.openflow.connections:
            connection.send(msg)
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import time

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self, arp_cache, ip_port_map, mac_to_port):
        self.arp_cache = arp_cache
        self.ip_port_map = ip_port_map
        self.mac_to_port = mac_to_port
        
        self.router_macs = {
            '10.0.1.1': EthAddr('02:00:00:00:01:01'),
            '10.0.2.1': EthAddr('02:00:00:00:02:01'),
            '10.0.3.1': EthAddr('02:00:00:00:03:01')
        }
        
        # Anti-Loop: Track recently flooded ARP requests
        # Key: (src_mac, target_ip), Value: timestamp
        self.arp_flood_history = {}
        self.flood_suppress_sec = 2.0

    def handle_arp_packet(self, packet, event):
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc
        dpid = event.dpid
        in_port = event.port

        # 1. Update State
        self.arp_cache[src_ip] = src_mac
        # Note: We rely on Controller's Sticky Learning for Port Map stability
        if self.ip_port_map.get(src_ip) is None:
             self.ip_port_map[src_ip] = (dpid, in_port)

        # 2. Handle ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            dst_ip = str(arp_pkt.protodst)
            
            # A. Gateway Request
            if dst_ip in self.router_macs:
                self.send_arp_reply(packet, event, self.router_macs[dst_ip])
                return

            # B. Host Request (Proxy ARP)
            if dst_ip in self.arp_cache:
                dst_mac = self.arp_cache[dst_ip]
                self.send_arp_reply(packet, event, dst_mac)
            else:
                # C. Unknown Host -> Flood with Deduplication
                # Check if we already flooded this request recently
                flood_key = (src_mac, dst_ip)
                current_time = time.time()
                
                last_time = self.arp_flood_history.get(flood_key, 0)
                if current_time - last_time < self.flood_suppress_sec:
                    # We saw this request recently. It's likely a loop echo. DROP IT.
                    # log.debug("ARP: Suppressed loop flood for %s -> %s", src_mac, dst_ip)
                    return
                
                # Update timestamp and flood ONCE
                self.arp_flood_history[flood_key] = current_time
                
                msg = of.ofp_packet_out(data=event.ofp.data)
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                event.connection.send(msg)

    def send_arp_reply(self, request_packet, event, src_mac):
        """Send unicast ARP Reply"""
        arp_req = request_packet.payload
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwdst = arp_req.hwsrc
        arp_rep.protosrc = arp_req.protodst
        arp_rep.protodst = arp_req.protosrc
        arp_rep.hwsrc = src_mac
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=request_packet.src)
        eth.payload = arp_rep
        
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

    def send_arp_request_from_controller(self, target_ip, event):
        """
        Controller initiated ARP Request.
        """
        # Deduplication for controller-generated ARPs as well
        # Use a dummy MAC for key or just target_ip
        flood_key = (EthAddr("00:00:00:00:00:00"), target_ip)
        current_time = time.time()
        if current_time - self.arp_flood_history.get(flood_key, 0) < self.flood_suppress_sec:
            return

        self.arp_flood_history[flood_key] = current_time

        src_gw_ip = '10.0.1.1'
        if target_ip.startswith('10.0.2'): src_gw_ip = '10.0.2.1'
        elif target_ip.startswith('10.0.3'): src_gw_ip = '10.0.3.1'
        
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
        log.info("L3: Sent ARP Request for %s from Controller", target_ip)
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self, arp_cache, ip_port_map, mac_to_port):
        self.arp_cache = arp_cache         # Reference to shared ARP cache
        self.ip_port_map = ip_port_map     # Reference to shared IP Location map
        self.mac_to_port = mac_to_port     # Reference to shared L2 table
        
        # Virtual Gateway MACs
        self.router_macs = {
            '10.0.1.1': EthAddr('02:00:00:00:01:01'),
            '10.0.2.1': EthAddr('02:00:00:00:02:01'),
            '10.0.3.1': EthAddr('02:00:00:00:03:01') # Added support for s3
        }

    def handle_arp_packet(self, packet, event):
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc
        dpid = event.dpid
        in_port = event.port

        # 1. Learn Mapping (IP -> MAC) and (IP -> Location)
        self.arp_cache[src_ip] = src_mac
        if self.ip_port_map.get(src_ip) != (dpid, in_port):
            self.ip_port_map[src_ip] = (dpid, in_port)
            log.debug("ARP: Learned %s is at %s (connected to dpid %s port %s)", 
                      src_ip, src_mac, dpid, in_port)

        # 2. Handle ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            dst_ip = str(arp_pkt.protodst)
            
            # A. Request for Gateway (e.g., h1 asking for 10.0.1.1)
            if dst_ip in self.router_macs:
                self.send_arp_reply(packet, event, self.router_macs[dst_ip])
                return

            # B. Request for another Host (e.g., h1 asking for h2)
            # Proxy ARP: If Controller knows destination MAC, reply immediately (reduces flood)
            if dst_ip in self.arp_cache:
                dst_mac = self.arp_cache[dst_ip]
                self.send_arp_reply(packet, event, dst_mac)
            else:
                # Unknown -> Flood ARP Request to network to find host
                # Flood using packet-out, DO NOT install flow
                msg = of.ofp_packet_out(data=event.ofp.data)
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                event.connection.send(msg)

    def send_arp_reply(self, request_packet, event, src_mac):
        """Send unicast ARP Reply to the requester"""
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
        # log.debug("Sent ARP Reply: %s is at %s", arp_req.protodst, src_mac)

    def send_arp_request_from_controller(self, target_ip, event):
        """
        Controller actively sends ARP Request to find destination Host MAC.
        Used when IP packet needs routing but destination MAC is missing.
        """
        # Determine Gateway IP for that subnet to spoof sender
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
        
        # Flood to all switches to find host (since location is unknown)
        msg = of.ofp_packet_out(data=eth.pack())
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        
        for connection in core.openflow.connections:
            connection.send(msg)
        log.info("L3: Sent ARP Request for %s from Controller", target_ip)
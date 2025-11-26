from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self):
        self.arp_cache = {} # IP -> MAC
        self.router_macs = {
            '10.0.1.1': EthAddr('00:00:00:00:01:01'),
            '10.0.2.1': EthAddr('00:00:00:00:02:01'),
            '10.0.3.1': EthAddr('00:00:00:00:03:01')
        }

    def handle_arp_packet(self, packet, in_port, connection, mac_to_port):
        """
        Handles ALL ARP packets.
        Implements Proxy ARP to prevent flooding loops.
        """
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc

        # 1. Update ARP Cache & Learning
        self.arp_cache[src_ip] = src_mac
        
        # 2. Handle ARP Reply
        if arp_pkt.opcode == arp.REPLY:
            # We forward the reply back to the destination (the original requester)
            # using Unicast to avoid flooding loops.
            self._forward_arp_unicast(packet, arp_pkt.hwdst, connection, mac_to_port)
            return True

        # 3. Handle ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            dst_ip = str(arp_pkt.protodst)
            
            # Case A: Request for Router Gateway
            if dst_ip in self.router_macs:
                self.send_arp_reply(packet, connection, self.router_macs[dst_ip], in_port)
                return True

            # Case B: Request for Host
            if dst_ip in self.arp_cache:
                # Proxy ARP: We know the answer, reply immediately
                dst_mac = self.arp_cache[dst_ip]
                self.send_arp_reply(packet, connection, dst_mac, in_port)
            else:
                # We don't know. Flood a probe to find it.
                # Only Controller floods. Host packet is dropped/consumed.
                self._flood_arp_request_from_controller(dst_ip)
            
            return True

    def _forward_arp_unicast(self, packet, dst_mac, connection, mac_to_port):
        """Forward an ARP packet to a known MAC (Unicast) using Global L2 Table."""
        # Find the switch and port where the destination MAC resides
        target_dpid = None
        target_port = None
        
        # Search global table
        for dpid, table in mac_to_port.items():
            if dst_mac in table:
                target_dpid = dpid
                target_port = table[dst_mac]
                break
        
        if target_dpid and target_port:
            # Send Unicast PacketOut directly to that switch
            msg = of.ofp_packet_out(data=packet.pack())
            msg.actions.append(of.ofp_action_output(port=target_port))
            core.openflow.sendToDPID(target_dpid, msg)
            log.debug("Unicast ARP Reply forwarded to %s on Switch %s Port %s", dst_mac, target_dpid, target_port)
        else:
            # If we don't know where the requester is, we can't forward safely in a loop topology.
            # We drop it. The requester will retry later (and by then we might have learned their location).
            pass

    def send_arp_reply(self, request_pkt, connection, src_mac, out_port):
        """Constructs and sends an ARP Reply."""
        arp_req = request_pkt.payload
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwdst = arp_req.hwsrc
        arp_rep.protosrc = arp_req.protodst
        arp_rep.protodst = arp_req.protosrc
        arp_rep.hwsrc = src_mac
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=arp_req.hwsrc)
        eth.payload = arp_rep
        
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)

    def send_arp_request(self, connection, target_ip, src_gw_ip):
        """Send specific ARP request on a connection."""
        router_mac = self.router_macs.get(src_gw_ip)
        if not router_mac: return

        r = arp()
        r.opcode = arp.REQUEST
        r.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        r.hwsrc = router_mac
        r.protosrc = IPAddr(src_gw_ip)
        r.protodst = IPAddr(target_ip)
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=router_mac, dst=r.hwdst)
        eth.payload = r
        
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        connection.send(msg)

    def _flood_arp_request_from_controller(self, target_ip):
        """Controller sends ARP Request to ALL switches."""
        src_gw = '10.0.1.1'
        if target_ip.startswith('10.0.2'): src_gw = '10.0.2.1'
        elif target_ip.startswith('10.0.3'): src_gw = '10.0.3.1'

        for connection in core.openflow.connections:
            self.send_arp_request(connection, target_ip, src_gw)
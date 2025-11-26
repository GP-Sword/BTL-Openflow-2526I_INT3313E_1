from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self):
        self.arp_cache = {} # IP -> MAC
        # Virtual Router MACs
        self.router_macs = {
            '10.0.1.1': EthAddr('00:00:00:00:01:01'),
            '10.0.2.1': EthAddr('00:00:00:00:02:01'),
            '10.0.3.1': EthAddr('00:00:00:00:03:01')
        }

    def handle_arp_packet(self, packet, packet_in, connection):
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc

        # Update cache
        self.arp_cache[src_ip] = src_mac
        
        # Check if it is a request for one of our gateways
        dst_ip = str(arp_pkt.protodst)
        if dst_ip in self.router_macs:
            if arp_pkt.opcode == arp.REQUEST:
                self.send_arp_reply(packet, connection, self.router_macs[dst_ip])
                return True # Handled
        return False

    def send_arp_reply(self, request_pkt, connection, router_mac):
        arp_req = request_pkt.payload
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwdst = arp_req.hwsrc
        arp_rep.protosrc = arp_req.protodst
        arp_rep.protodst = arp_req.protosrc
        arp_rep.hwsrc = router_mac
        
        eth = ethernet(type=ethernet.ARP_TYPE, src=router_mac, dst=arp_req.hwsrc)
        eth.payload = arp_rep
        
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = connection.ports[of.OFPP_NONE] # Virtual source
        connection.send(msg)
        log.debug("Sent ARP Reply: %s is at %s", arp_rep.protosrc, router_mac)

    def send_arp_request(self, connection, target_ip, src_gw_ip):
        """Broadcasts ARP Request to find a host."""
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
        log.info("Sent ARP Request for %s from %s", target_ip, src_gw_ip)
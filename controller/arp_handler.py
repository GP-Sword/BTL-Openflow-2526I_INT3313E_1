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

    def handle_arp_packet(self, packet, in_port, connection):
        """
        Handles ARP logic.
        Args:
            packet: Parsed ethernet packet.
            in_port: Input port number.
            connection: OpenFlow connection object.
        """
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = arp_pkt.hwsrc

        # 1. Update ARP Cache
        self.arp_cache[src_ip] = src_mac
        
        # 2. Check if request is for Gateway
        # We only need to reply if they are asking for the Router's IP
        dst_ip = str(arp_pkt.protodst)
        if dst_ip in self.router_macs:
            if arp_pkt.opcode == arp.REQUEST:
                # We have all info needed, no need for packet_in object
                self.send_arp_reply(packet, connection, self.router_macs[dst_ip], in_port)
                return True # Handled by Router
        return False

    def send_arp_reply(self, request_pkt, connection, router_mac, out_port):
        """Constructs and sends an ARP Reply."""
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
        msg.actions.append(of.ofp_action_output(port=out_port))
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
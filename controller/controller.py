from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery

from arp_handler import ARPHandler
from ip_handler import IPHandler
from firewall import Firewall
from flow_installer import FlowInstaller
from monitor import Monitor

log = core.getLogger()

class SDNController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        
        self.arp_handler = ARPHandler()
        self.firewall = Firewall()
        self.flow_installer = FlowInstaller()
        self.monitor = Monitor()
        self.ip_handler = IPHandler(self.arp_handler, self.flow_installer, self.firewall)
        
        self.mac_to_port = {}
        Timer(5, self._timer_func, recurring=True)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        
        if not packet.parsed: return

        # 1. L2 Learning
        self.mac_to_port.setdefault(dpid, {})
        if packet.src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][packet.src] = in_port
            log.debug("Learned %s on dpid %s port %s", packet.src, dpid, in_port)

        # 2. Dispatch
        if packet.type == ethernet.ARP_TYPE:
            # Pass mac_to_port to ARP Handler so it can do Unicast Forwarding
            self.arp_handler.handle_arp_packet(packet, in_port, event.connection, self.mac_to_port)
            
            # If it was an ARP Reply, we might need to flush waiting L3 packets
            if packet.payload.opcode == arp.REPLY:
                src_ip = str(packet.payload.protosrc)
                self.ip_handler.process_waiting_packets(src_ip, packet.src, self.mac_to_port)

        elif packet.type == ethernet.IP_TYPE:
            # Try L3 Routing first
            is_l3 = self.ip_handler.handle_packet(event, self.mac_to_port)
            
            # If NOT handled as L3 (e.g. intra-subnet), fall back to L2 switching
            if not is_l3:
                self._handle_l2_switching(event)
            
        else:
            self._handle_l2_switching(event)

    def _handle_l2_switching(self, event):
        """
        Modified L2 Switching for Loop Protection (No STP).
        Policy: KNOWN UNICAST ONLY. Drop everything else.
        """
        packet = event.parsed
        dpid = event.dpid
        dst_mac = packet.dst
        
        # Case A: Multicast/Broadcast
        if dst_mac.is_multicast:
            return 

        # Case B: Unicast
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            self.flow_installer.install_l2_flow(event.connection, dst_mac, out_port)
            
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
        else:
            pass

    def _handle_FlowStatsReceived(self, event):
        self.monitor.handle_flow_stats(event)

    def _timer_func(self):
        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def launch():
    pox.openflow.discovery.launch()
    core.registerNew(SDNController)
    log.info("SDN Controller started!")
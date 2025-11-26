from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of

# Import standard POX modules for Spanning Tree
import pox.openflow.discovery
import pox.openflow.spanning_tree

# Import custom modules
from arp_handler import ARPHandler
from ip_handler import IPHandler
from firewall import Firewall
from flow_installer import FlowInstaller
from monitor import Monitor

log = core.getLogger()

class SDNController(object):
    def __init__(self):
        # We listen to ConnectionUp to differentiate between STP-blocked ports and active ports
        core.openflow.addListeners(self)
        
        # Initialize modules
        self.arp_handler = ARPHandler()
        self.firewall = Firewall()
        self.flow_installer = FlowInstaller()
        self.monitor = Monitor()
        self.ip_handler = IPHandler(self.arp_handler, self.flow_installer, self.firewall)
        
        # Global L2 Table (dpid -> mac -> port)
        self.mac_to_port = {}
        
        # Start Monitoring Timer (every 5 seconds)
        Timer(5, self._timer_func, recurring=True)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        
        if not packet.parsed: return

        # 1. L2 Learning (Learn Source Location)
        self.mac_to_port.setdefault(dpid, {})
        
        # Note: With Spanning Tree running, we don't need manual loop checks here.
        # STP will disable ports on the switch so packets won't loop.
        
        if packet.src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][packet.src] = in_port
            log.debug("Learned %s on dpid %s port %s", packet.src, dpid, in_port)

        # 2. Dispatch based on Type
        if packet.type == ethernet.ARP_TYPE:
            # Handle ARP (Route or Gateway)
            handled = self.arp_handler.handle_arp_packet(packet, event.ofp, event.connection)
            if handled:
                if packet.payload.opcode == arp.REPLY:
                    src_ip = str(packet.payload.protosrc)
                    self.ip_handler.process_waiting_packets(src_ip, packet.src, self.mac_to_port)
            else:
                # Flood normal ARP (L2 switching behavior)
                # STP ensures this flood doesn't loop forever
                self._flood_packet(event)

        elif packet.type == ethernet.IP_TYPE:
            # Handle IP Routing & Firewall
            self.ip_handler.handle_packet(event, self.mac_to_port)
            
        else:
            self._flood_packet(event)

    def _handle_FlowStatsReceived(self, event):
        self.monitor.handle_flow_stats(event)

    def _timer_func(self):
        # Request stats from all connected switches
        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _flood_packet(self, event):
        """Standard L2 flooding."""
        msg = of.ofp_packet_out(data=event.ofp.data)
        
        # OFPP_FLOOD is smart enough to respect Spanning Tree states in OVS
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    # 1. Launch Discovery (Required for STP to see links)
    pox.openflow.discovery.launch()
    
    # 2. Launch Spanning Tree (Disables ports to prevent loops)
    pox.openflow.spanning_tree.launch()
    
    # 3. Launch our Controller
    core.registerNew(SDNController)
    log.info("SDN Controller started with Spanning Tree (Loop Protection)!")
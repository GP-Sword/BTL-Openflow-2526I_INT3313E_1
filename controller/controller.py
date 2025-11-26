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
        
        # Shared State
        self.mac_to_port = {}       # {dpid: {mac: port}} -> L2 Learning
        self.arp_cache = {}         # {ip: mac} -> ARP Table
        self.ip_port_map = {}       # {ip: (dpid, port)} -> Location of Host
        
        # Components
        self.firewall = Firewall()
        self.flow_installer = FlowInstaller()
        self.monitor = Monitor()
        self.arp_handler = ARPHandler(self.arp_cache, self.ip_port_map, self.mac_to_port)
        self.ip_handler = IPHandler(self.arp_cache, self.ip_port_map, self.mac_to_port, 
                                    self.flow_installer, self.firewall, self.arp_handler)
        
        Timer(5, self._timer_func, recurring=True)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        
        if not packet.parsed: return

        # --- 1. Firewall Check (Ingress) ---
        # Check immediately when packet enters the first switch
        if packet.type == ethernet.IP_TYPE:
            if self.firewall.check_firewall(dpid, packet.payload) == "DENY":
                # If denied, send ICMP Unreachable and DROP
                self.ip_handler.send_icmp_unreachable(packet.payload, packet, event.ofp, event)
                return

        # --- 2. L2 Learning (Global) ---
        self.mac_to_port.setdefault(dpid, {})
        # Only learn unicast source
        if not packet.src.is_multicast:
            if self.mac_to_port[dpid].get(packet.src) != in_port:
                self.mac_to_port[dpid][packet.src] = in_port
                log.debug("L2: Learned %s on dpid %s port %s", packet.src, dpid, in_port)

        # --- 3. Dispatch Handling ---
        
        # Handle ARP (L3 Gateway ARP or Proxy ARP for Host)
        if packet.type == ethernet.ARP_TYPE:
            self.arp_handler.handle_arp_packet(packet, event)
            
            # If it is an ARP Reply, we might need to process waiting IP packets
            if packet.payload.opcode == arp.REPLY:
                src_ip = str(packet.payload.protosrc)
                self.ip_handler.process_waiting_packets(src_ip)

        # Handle IP (L3 Routing)
        elif packet.type == ethernet.IP_TYPE:
            is_handled_by_l3 = self.ip_handler.handle_ip_packet(event)
            
            # If not L3 (e.g., intra-subnet), fall back to L2
            if not is_handled_by_l3:
                self._handle_l2_switching(event)
            
        # Other packet types (L2 fallback)
        else:
            self._handle_l2_switching(event)

    def _handle_l2_switching(self, event):
        """
        L2 Switching logic:
        - If destination is known: Send unicast + Install Flow (High Performance)
        - If destination is unknown: Flood (using PacketOut, DO NOT install flood flow to avoid loops)
        """
        packet = event.parsed
        dpid = event.dpid
        dst_mac = packet.dst
        
        # If Multicast/Broadcast -> Flood
        if dst_mac.is_multicast:
            self._flood_packet(event)
            return 

        # If Unicast
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            
            # Install L2 Flow for high speed (avoid controller next time)
            self.flow_installer.install_l2_flow(event.connection, packet.src, dst_mac, out_port)
            
            # Send the current packet
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
            log.debug("L2: Switching %s -> %s on dpid %s port %s", packet.src, dst_mac, dpid, out_port)
        else:
            # Destination unknown -> Flood to find
            # Note: Only flood this packet, DO NOT install flood flow.
            self._flood_packet(event)

    def _flood_packet(self, event):
        """Flood packet to all ports except ingress port"""
        msg = of.ofp_packet_out(data=event.ofp.data)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_FlowStatsReceived(self, event):
        self.monitor.handle_flow_stats(event)

    def _timer_func(self):
        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def launch():
    pox.openflow.discovery.launch()
    core.registerNew(SDNController)
    log.info("SDN Controller (Ring Topology Optimized) started!")
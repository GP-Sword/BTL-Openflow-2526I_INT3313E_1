from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import time

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
        
        # Initialize ARPHandler with shared state
        self.arp_handler = ARPHandler(self.arp_cache, self.ip_port_map, self.mac_to_port)
        
        # --- UPDATE HERE ---
        # The new IPHandler only needs 3 arguments: arp_handler, flow_installer, firewall.
        # It accesses arp_cache and mac_to_port via arp_handler.
        self.ip_handler = IPHandler(self.arp_handler, self.flow_installer, self.firewall)
        
        Timer(5, self._timer_func, recurring=True)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        
        if not packet.parsed: return

        # --- 1. Firewall Check (Ingress) ---
        if packet.type == ethernet.IP_TYPE:
            if self.firewall.check_firewall(dpid, packet.payload) == "DENY":
                self.ip_handler.send_icmp_unreachable(packet.payload, packet, event.ofp, event)
                return

        # --- 2. L2 Learning (Sticky / Anti-Flapping) ---
        self.mac_to_port.setdefault(dpid, {})
        
        if not packet.src.is_multicast:
            if packet.src not in self.mac_to_port[dpid]:
                # New MAC, learn it
                self.mac_to_port[dpid][packet.src] = in_port
                log.debug("L2: Learned %s on dpid %s port %s", packet.src, dpid, in_port)
            elif self.mac_to_port[dpid][packet.src] != in_port:
                # Loop detected! Ignore update.
                pass 

        # --- 3. Dispatch Handling ---
        
        if packet.type == ethernet.ARP_TYPE:
            self.arp_handler.handle_arp_packet(packet, event)
            
            if packet.payload.opcode == arp.REPLY:
                src_ip = str(packet.payload.protosrc)
                self.ip_handler.process_waiting_packets(src_ip)

        elif packet.type == ethernet.IP_TYPE:
            is_handled_by_l3 = self.ip_handler.handle_ip_packet(event)
            if not is_handled_by_l3:
                self._handle_l2_switching(event)
            
        else:
            self._handle_l2_switching(event)

    def _handle_l2_switching(self, event):
        packet = event.parsed
        dpid = event.dpid
        dst_mac = packet.dst
        
        # Multicast/Broadcast -> Flood (handled carefully)
        if dst_mac.is_multicast:
            self._flood_packet(event)
            return 

        # Unicast
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            
            # Install Flow
            self.flow_installer.install_l2_flow(event.connection, packet.src, dst_mac, out_port)
            
            # Send Packet
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
        else:
            # Unknown unicast destination -> Flood to find it
            self._flood_packet(event)

    def _flood_packet(self, event):
        """Flood packet but DO NOT install a flood flow"""
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
    log.info("SDN Controller (Ring Safe Mode) started!")
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from arp_handler import ARPHandler
from ip_handler import IPHandler
from firewall import Firewall
from flow_installer import FlowInstaller
from monitor import Monitor

log = core.getLogger()

class SDNController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        
        # --- Dynamic Subnet Configuration ---
        self.subnets = {
            '10.0.1.0/24': {'gw_ip': '10.0.1.1', 'gw_mac': '02:00:00:00:01:01'},
            '10.0.2.0/24': {'gw_ip': '10.0.2.1', 'gw_mac': '02:00:00:00:02:01'},
            '10.0.3.0/24': {'gw_ip': '10.0.3.1', 'gw_mac': '02:00:00:00:03:01'}
        }
        
        self.mac_to_port = {}       
        self.arp_cache = {}        
        self.ip_port_map = {}       
        
        self.flow_installer = FlowInstaller()
        self.firewall = Firewall(self.flow_installer)
        
        # Pass arp_cache to Monitor to resolve MAC -> IP for stats
        self.monitor = Monitor(self.arp_cache)
        
        self.arp_handler = ARPHandler(self.arp_cache, self.ip_port_map, self.mac_to_port, self.subnets)
        self.ip_handler = IPHandler(self.arp_handler, self.flow_installer, self.firewall, self.subnets)
        
        Timer(5, self._timer_func, recurring=True)

    def _handle_ConnectionUp(self, event):
        self.firewall.install_firewall_policies(event.connection)
        log.info("Switch %s connected. Firewall rules installed.", event.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        
        if not packet.parsed: return

        # --- FILTER: Ignore IPv6 and LLDP ---
        if packet.type == ethernet.LLDP_TYPE: 
            return 
        if packet.type == 0x86dd: # IPv6
            return 

        # --- 1. L2 Learning (Strict) ---
        self.mac_to_port.setdefault(dpid, {})
        is_link_port = self.arp_handler.is_switch_link(dpid, in_port)
        
        if not is_link_port and not packet.src.is_multicast:
            self.mac_to_port[dpid][packet.src] = in_port

        # --- 2. Dispatch Handling ---
        if packet.type == ethernet.ARP_TYPE:
            self.arp_handler.handle_arp_packet(packet, event)
            if packet.payload.opcode == arp.REPLY:
                src_ip = str(packet.payload.protosrc)
                self.ip_handler.process_waiting_packets(src_ip)

        elif packet.type == ethernet.IP_TYPE:
            if self.firewall.check_firewall_packet(packet.payload) == "DENY":
                return 
            is_handled_by_l3 = self.ip_handler.handle_ip_packet(event)
            if not is_handled_by_l3:
                self._handle_l2_switching(event)
            
        else:
            self._handle_l2_switching(event)

    def _handle_l2_switching(self, event):
        packet = event.parsed
        dpid = event.dpid
        dst_mac = packet.dst
        
        if dst_mac.is_multicast:
            self._flood_packet(event)
            return 

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            
            # Check if payload is IPv4 to pass strictly to installer
            ip_payload = None
            if packet.type == ethernet.IP_TYPE and isinstance(packet.payload, ipv4):
                ip_payload = packet.payload
            
            self.flow_installer.install_l2_flow(event.connection, packet.src, dst_mac, out_port, ip_payload)
            
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_output(port=out_port))
            event.connection.send(msg)
        else:
            self._flood_packet(event)

    def _flood_packet(self, event):
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
    pox.openflow.spanning_tree.launch() 
    core.registerNew(SDNController)
    log.info("SDN Controller started!")
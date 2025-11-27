from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("flow_installer")

class FlowInstaller:
    def install_l2_flow(self, connection, src_mac, dst_mac, out_port, ip_packet=None):
        """
        Installs a generic L2 switching flow.
        """
        msg = of.ofp_flow_mod()
        msg.priority = 30000 
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        
        # Match Protocol to classify TCP/UDP/ICMP in Monitor
        if ip_packet and isinstance(ip_packet, ipv4):
            msg.match.nw_proto = ip_packet.protocol
            # Match Source IP to ensure Monitor calculates Tx correctly for that IP
            msg.match.nw_src = ip_packet.srcip
            msg.match.nw_dst = ip_packet.dstip

        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        connection.send(msg)

    def install_l3_flow(self, connection, src_ip, dst_ip, src_mac_rewrite, dst_mac_rewrite, out_port, ip_packet=None):
        if not connection: return
        
        msg = of.ofp_flow_mod()
        msg.priority = 100 
        msg.match.dl_type = ethernet.IP_TYPE
        
        # 1. Match Destination IP (Routing requirement)
        msg.match.nw_dst = dst_ip
        
        # 2. Match Source IP
        msg.match.nw_src = src_ip
        
        # 3. Match Protocol
        if ip_packet and isinstance(ip_packet, ipv4):
            msg.match.nw_proto = ip_packet.protocol

        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_rewrite))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac_rewrite))
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        msg.idle_timeout = 60
        connection.send(msg)

    def install_drop_flow(self, connection, proto, port, priority=200):
        msg = of.ofp_flow_mod()
        msg.priority = priority
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_proto = proto
        msg.match.tp_dst = port
        
        # No actions -> DROP
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        connection.send(msg)
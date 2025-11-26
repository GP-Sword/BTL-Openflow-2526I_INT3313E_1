from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("flow_installer")

class FlowInstaller:
    def install_l2_flow(self, connection, dst_mac, out_port):
        """Installs a simple L2 switching flow."""
        msg = of.ofp_flow_mod()
        msg.match.dl_dst = dst_mac
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.idle_timeout = 30
        connection.send(msg)

    def install_l3_flow(self, connection, dst_ip, src_mac, dst_mac, out_port):
        """Installs an L3 routing flow (rewrite MACs + forward)."""
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = dst_ip
        
        # Rewrite MAC addresses for L3 hop
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        connection.send(msg)
        log.debug("Installed L3 flow for %s -> port %s", dst_ip, out_port)
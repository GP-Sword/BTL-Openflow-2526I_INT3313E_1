from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

log = core.getLogger("flow_installer")

class FlowInstaller:
    def install_l2_flow(self, connection, src_mac, dst_mac, out_port):
        """
        Installs a generic L2 switching flow.
        Important: Match both Src and Dst MAC to avoid conflicts
        """
        msg = of.ofp_flow_mod()
        msg.match.dl_src = src_mac
        msg.match.dl_dst = dst_mac
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        connection.send(msg)

    def install_l3_flow(self, connection, dst_ip, src_mac_rewrite, dst_mac_rewrite, out_port):
        """
        Installs an L3 routing flow (Modify MACs + Forward).
        Match: Destination IP
        Actions: Set Src MAC (Gateway), Set Dst MAC (Next Hop/Host), Output
        """
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_dst = dst_ip
        
        # Rewrite MAC action is mandatory for L3 Router
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac_rewrite))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac_rewrite))
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        connection.send(msg)
        # log.debug("Installed L3 flow for -> %s via port %s", dst_ip, out_port)
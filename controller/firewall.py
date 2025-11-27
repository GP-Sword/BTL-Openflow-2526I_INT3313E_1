from pox.core import core
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("firewall")

class Firewall:
    def __init__(self, flow_installer):
        self.flows = flow_installer
        # Format: (Protocol_Name, Protocol_Code, Port, Action)
        self.rules = [
            ("SSH", ipv4.TCP_PROTOCOL, 22, "DENY"),
            ("HTTP", ipv4.TCP_PROTOCOL, 80, "DENY"),
            ("DNS", ipv4.UDP_PROTOCOL, 53, "ALLOW"),
        ]
    
    def install_firewall_policies(self, connection):
        """
        Install these rules as soon as switch connects (Proactive).
        """
        log.info("Installing Firewall rules on Switch %s", connection.dpid)
        
        for name, proto, port, action in self.rules:
            if action == "DENY":
                # Install DROP Flow with High Priority (e.g., 200)
                # Match: DL_TYPE=IP, NW_PROTO, TP_DST
                self.flows.install_drop_flow(connection, proto, port, priority=200)
                log.info("  Rule: Block %s (Port %s) -> Installed DROP Flow", name, port)
            
            elif action == "ALLOW":
                # SDN defaults to Drop if no flow, but POX usually runs PacketIn.
                # With ALLOW, we do nothing, letting packet pass to Routing logic (Lower Priority).
                # Or install Forward flow with lower priority.
                pass

    def check_firewall_packet(self, ip_pkt):
        """
        Redundant check for first packets to controller (before flow takes effect)
        """
        proto = ip_pkt.protocol
        dst_port = None
        
        if proto == ipv4.TCP_PROTOCOL or proto == ipv4.UDP_PROTOCOL:
            try: dst_port = ip_pkt.payload.dstport
            except: return "ALLOW"
        
        for name, rule_proto, rule_port, rule_action in self.rules:
            if proto == rule_proto and dst_port == rule_port:
                if rule_action == "DENY":
                    log.info("FIREWALL: Software Blocked %s packet port %s", name, dst_port)
                    return "DENY"
        
        return "ALLOW"
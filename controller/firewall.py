from pox.core import core
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("firewall")

class Firewall:
    def __init__(self):
        # Initialize firewall rules applied to ALL switches
        # Rule format: (Protocol, Port, Action)
        self.rules = [
            ("TCP", 22, "DENY"),   # Block SSH
            ("TCP", 80, "DENY"),   # Block HTTP
            ("UDP", 53, "ALLOW"),  # Allow DNS
        ]
        log.info("Firewall initialized with rules: %s", self.rules)

    def check_firewall(self, dpid, ip_pkt):
        """
        Check if the packet is allowed.
        This ACL applies to ALL switches (dpid is used for logging only).
        Return: "ALLOW" or "DENY"
        Policy: Default Allow.
        """
        proto = None
        dst_port = None
        
        # Determine protocol (TCP or UDP)
        if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
            proto = "TCP"
            try: dst_port = ip_pkt.payload.dstport
            except: return "ALLOW" # Malformed packet, let it pass or drop based on policy
        elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
            proto = "UDP"
            try: dst_port = ip_pkt.payload.dstport
            except: return "ALLOW"
        else:
            # Allow ICMP and other protocols
            return "ALLOW"

        # Check against the rule list
        for rule_proto, rule_port, rule_action in self.rules:
            if rule_proto == proto and rule_port == dst_port:
                if rule_action == "DENY":
                    log.info("FIREWALL: DENIED %s packet to port %s on Switch %s", proto, dst_port, dpid)
                    return "DENY"
                if rule_action == "ALLOW":
                    return "ALLOW"
        
        # Default behavior if no rule matches
        return "ALLOW"
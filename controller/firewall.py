from pox.core import core
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("firewall")

class Firewall:
    def __init__(self):
        # Rule format: (Protocol, Port, Action)
        self.rules = [
            ("TCP", 22, "DENY"),   # Block SSH
            ("TCP", 80, "DENY"),   # Block HTTP
            ("UDP", 53, "ALLOW"),  # Allow DNS
        ]
        log.info("Firewall initialized with rules: %s", self.rules)

    def is_allowed(self, ip_pkt):
        """
        Checks L4 Firewall rules. 
        Returns True if allowed, False if denied.
        """
        # Determine protocol
        proto = None
        if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
            proto = "TCP"
        elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
            proto = "UDP"
        
        # If not TCP/UDP (e.g., ICMP), allow by default
        if proto is None:
            return True

        # Extract destination port
        # Helper to get transport layer payload
        transport_pkt = ip_pkt.payload
        try:
            dst_port = transport_pkt.dstport
        except AttributeError:
            return True # Not a transport packet

        # Check against rules (Priority: DENY > ALLOW)
        for rule_proto, rule_port, rule_action in self.rules:
            if rule_proto == proto and rule_port == dst_port:
                if rule_action == "DENY":
                    log.info("BLOCKED %s packet to port %s", proto, dst_port)
                    return False
                elif rule_action == "ALLOW":
                    return True
        
        # Default policy: ALLOW
        return True
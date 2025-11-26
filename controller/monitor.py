from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger("monitor")

class Monitor:
    def __init__(self):
        # Timer will be started by the controller
        pass

    def send_stats_request(self, connections):
        """Sends stats request to all connected switches."""
        for connection in connections:
            msg = of.ofp_stats_request(body=of.ofp_flow_stats_request())
            connection.send(msg)

    def handle_flow_stats(self, event):
        """Parses flow stats to count bytes per protocol/host."""
        dpid = dpid_to_str(event.dpid)
        bytes_host = {} # IP -> Bytes
        bytes_proto = {'TCP': 0, 'UDP': 0, 'ICMP': 0}

        for f in event.stats:
            # Count Protocol
            if f.match.nw_proto == 6: bytes_proto['TCP'] += f.byte_count
            elif f.match.nw_proto == 17: bytes_proto['UDP'] += f.byte_count
            elif f.match.nw_proto == 1: bytes_proto['ICMP'] += f.byte_count
            
            # Count Host (Source IP)
            if f.match.nw_src:
                src = str(f.match.nw_src)
                bytes_host[src] = bytes_host.get(src, 0) + f.byte_count

        log.info("Stats [SW-%s]: TCP:%s UDP:%s ICMP:%s | Top Hosts: %s", 
                 dpid, bytes_proto['TCP'], bytes_proto['UDP'], bytes_proto['ICMP'], 
                 str(bytes_host)[:50] + "...")
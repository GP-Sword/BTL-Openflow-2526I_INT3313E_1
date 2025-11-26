from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger("monitor")

class Monitor:
    def handle_flow_stats(self, event):
        """
        Display stats of traffic passing through switches.
        Helps debug if flows are working.
        """
        dpid = str(event.dpid)
        bytes_host = {} # IP -> Bytes
        bytes_proto = {'TCP': 0, 'UDP': 0, 'ICMP': 0}

        for f in event.stats:
            # Count Protocol
            if f.match.nw_proto == 6: bytes_proto['TCP'] += f.byte_count
            elif f.match.nw_proto == 17: bytes_proto['UDP'] += f.byte_count
            elif f.match.nw_proto == 1: bytes_proto['ICMP'] += f.byte_count
            
            # Check IP
            ip_src = str(f.match.nw_src) if f.match.nw_src else None
            ip_dst = str(f.match.nw_dst) if f.match.nw_dst else None
            
            if ip_src and ip_src != "None":
                bytes_host[ip_src] = bytes_host.get(ip_src, 0) + f.byte_count
            if ip_dst and ip_dst != "None":
                bytes_host[ip_dst] = bytes_host.get(ip_dst, 0) + f.byte_count

        # Get top 3 hosts consuming most bandwidth
        top_hosts = sorted(bytes_host.items(), key=lambda x: x[1], reverse=True)[:3]
        
        if top_hosts or bytes_proto['TCP'] > 0:
            log.info("Stats [SW-%s]: TCP:%s UDP:%s ICMP:%s | Top Hosts: %s", 
                     dpid, bytes_proto['TCP'], bytes_proto['UDP'], bytes_proto['ICMP'], 
                     str(top_hosts))
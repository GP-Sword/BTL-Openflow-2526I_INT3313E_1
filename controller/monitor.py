from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger("monitor")

class Monitor:
    def handle_flow_stats(self, event):
        """
        Analyze flow stats to track traffic by Host and Protocol.
        Triggered every 5 seconds by the Controller's Timer.
        """
        dpid = event.connection.dpid
        
        # Data structure for aggregation
        # host_stats = { 'IP_Host': {'tx': bytes_sent, 'rx': bytes_received} }
        host_stats = {} 
        
        # proto_stats = {'TCP': bytes, 'UDP': bytes, 'ICMP': bytes, 'Other': bytes}
        proto_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

        # Iterate through each flow entry returned by the switch
        for f in event.stats:
            # --- 1. Stats by Protocol ---
            # nw_proto: 6=TCP, 17=UDP, 1=ICMP
            if f.match.nw_proto == 6:
                proto_stats['TCP'] += f.byte_count
            elif f.match.nw_proto == 17:
                proto_stats['UDP'] += f.byte_count
            elif f.match.nw_proto == 1:
                proto_stats['ICMP'] += f.byte_count
            else:
                proto_stats['Other'] += f.byte_count
            
            # --- 2. Stats by Host (TX/RX) ---
            # Routing flows usually match src IP (TX) or dst IP (RX)
            
            # Process Source (TX - Transmit)
            src_ip = None
            if f.match.nw_src:
                src_ip = str(f.match.nw_src)
            
            if src_ip and src_ip != "None":
                if src_ip not in host_stats: host_stats[src_ip] = {'tx': 0, 'rx': 0}
                host_stats[src_ip]['tx'] += f.byte_count
            
            # Process Destination (RX - Receive)
            dst_ip = None
            if f.match.nw_dst:
                dst_ip = str(f.match.nw_dst)

            if dst_ip and dst_ip != "None":
                if dst_ip not in host_stats: host_stats[dst_ip] = {'tx': 0, 'rx': 0}
                host_stats[dst_ip]['rx'] += f.byte_count

        # --- 3. Display Statistics ---
        # Only log if there is traffic to avoid console spam
        total_bytes = sum(proto_stats.values())
        if total_bytes > 0:
            log.info(" ")
            log.info("========== TRAFFIC STATS [Switch %s] ==========", dpid)
            
            # Print protocol stats
            log.info("   [Protocol] TCP: %s B | UDP: %s B | ICMP: %s B | Other: %s B",
                     proto_stats['TCP'], proto_stats['UDP'], proto_stats['ICMP'], proto_stats['Other'])
            
            log.info("   [Host Activity]")
            # Sort by total activity (TX + RX) descending
            sorted_hosts = sorted(host_stats.items(), 
                                  key=lambda item: item[1]['tx'] + item[1]['rx'], 
                                  reverse=True)
            
            # Print top 5 most active hosts
            if not sorted_hosts:
                log.info("     (No specific Host activity)")
            else:
                for host, stats in sorted_hosts[:5]:
                    log.info("     Host %-15s | Sent (TX): %-10s B | Recv (RX): %-10s B", 
                             host, stats['tx'], stats['rx'])
            log.info("=====================================================")
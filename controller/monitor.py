from pox.core import core
from pox.lib.packet.ethernet import ethernet

log = core.getLogger("monitor")

class Monitor:
    def __init__(self, arp_cache):
        self.arp_cache = arp_cache

    def _get_ip_from_mac(self, mac_addr):
        """
        Helper to resolve MAC to IP using the controller's ARP cache.
        Robust comparison by converting both to lowercase strings.
        """
        if mac_addr is None:
            return None
            
        mac_str = str(mac_addr).lower()
        
        for ip, mac in self.arp_cache.items():
            # Convert cached EthAddr object to string for comparison
            if str(mac).lower() == mac_str:
                return ip
        return None

    def _format_bytes(self, size):
        """Format bytes to human readable string (B, KB, MB, GB)"""
        power = 1024
        n = 0
        power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power:
            size /= float(power)
            n += 1
        return "{:.2f} {}".format(size, power_labels.get(n, 'TB+'))

    def handle_flow_stats(self, event):
        dpid = event.connection.dpid
        host_stats = {} 
        
        # Stats categories
        proto_stats = {
            'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0,
            'IP_Aggr': 0, # Aggregated IP traffic (L3 Routing flows wildcard the protocol)
            'Ctrl': 0     # LLDP or unknown
        }

        for f in event.stats:
            # --- 1. Classify by Protocol ---
            if f.match.dl_type == ethernet.ARP_TYPE:
                proto_stats['ARP'] += f.byte_count
            
            elif f.match.dl_type == ethernet.IP_TYPE:
                # Check if Flow matches specific Protocol
                if f.match.nw_proto == 6:
                    proto_stats['TCP'] += f.byte_count
                elif f.match.nw_proto == 17:
                    proto_stats['UDP'] += f.byte_count
                elif f.match.nw_proto == 1:
                    proto_stats['ICMP'] += f.byte_count
                else:
                    # L3 Routing flows usually wildcard the protocol (*), 
                    # so TCP/UDP/ICMP traffic falls into here.
                    proto_stats['IP_Aggr'] += f.byte_count
            else:
                proto_stats['Ctrl'] += f.byte_count
            
            # --- 2. Stats by Host ---
            
            # A. TX Stats (Bytes Sent)
            # - L3 Flows: nw_src is usually wildcarded -> TX = 0 (Normal for aggregation)
            # - L2 Flows: dl_src is matched -> Resolve MAC to IP -> TX > 0 (Expected for Intra-subnet)
            src_ip = None
            
            if f.match.nw_src:
                src_ip = str(f.match.nw_src)
            elif f.match.dl_src: # L2 Flow matches on MAC
                src_ip = self._get_ip_from_mac(f.match.dl_src)
            
            if src_ip:
                if src_ip not in host_stats: host_stats[src_ip] = {'tx': 0, 'rx': 0}
                host_stats[src_ip]['tx'] += f.byte_count
            
            # B. RX Stats (Bytes Received)
            dst_ip = None
            if f.match.nw_dst:
                dst_ip = str(f.match.nw_dst)
            elif f.match.dl_dst:
                dst_ip = self._get_ip_from_mac(f.match.dl_dst)

            if dst_ip:
                if dst_ip not in host_stats: host_stats[dst_ip] = {'tx': 0, 'rx': 0}
                host_stats[dst_ip]['rx'] += f.byte_count

        # --- 3. Display Log ---
        total_bytes = sum(proto_stats.values())
        if total_bytes > 0:
            log.info(" ")
            log.info("========== TRAFFIC STATS [Switch %s] ==========", dpid)
            
            # Dynamic log string construction using formatted bytes
            log_parts = []
            if proto_stats['TCP'] > 0: log_parts.append("TCP:%s" % self._format_bytes(proto_stats['TCP']))
            if proto_stats['UDP'] > 0: log_parts.append("UDP:%s" % self._format_bytes(proto_stats['UDP']))
            if proto_stats['ICMP'] > 0: log_parts.append("ICMP:%s" % self._format_bytes(proto_stats['ICMP']))
            if proto_stats['ARP'] > 0: log_parts.append("ARP:%s" % self._format_bytes(proto_stats['ARP']))
            
            # Aggregated IP traffic label
            if proto_stats['IP_Aggr'] > 0: 
                log_parts.append("IP(Aggr):%s" % self._format_bytes(proto_stats['IP_Aggr']))
                
            if proto_stats['Ctrl'] > 0: log_parts.append("Ctrl:%s" % self._format_bytes(proto_stats['Ctrl']))
            
            if not log_parts:
                log_parts.append("No Data")

            log.info("   [Proto] " + " | ".join(log_parts))
            
            # Filter and Sort Hosts
            active_hosts = {k: v for k, v in host_stats.items() if v['tx'] > 0 or v['rx'] > 0}
            sorted_hosts = sorted(active_hosts.items(), 
                                  key=lambda item: item[1]['tx'] + item[1]['rx'], 
                                  reverse=True)
            
            if sorted_hosts:
                log.info("   [Host Activity]    ")
                for host, stats in sorted_hosts[:5]:
                    log.info("     Host %-15s | TX: %-10s | RX: %-10s", 
                             host, 
                             self._format_bytes(stats['tx']), 
                             self._format_bytes(stats['rx']))
            log.info("=====================================================")
from pox.core import core
from pox.lib.packet.ethernet import ethernet
import logging
import datetime

log = core.getLogger("monitor")

class Monitor:
    def __init__(self, arp_cache):
        self.arp_cache = arp_cache
        self.stats_buffer = {}
        self._setup_logger()

    def _setup_logger(self):
        """
        Logger configuration: Write to file, overwrite on each run.
        Format: Only message content (Time is handled manually).
        """
        if len(log.handlers) == 0:
            # mode='w' -> Write (Overwrite old file on every POX restart)
            fh = logging.FileHandler('monitor.log', mode='w')
            fh.setLevel(logging.INFO)
            
            # Use simple message formatting
            formatter = logging.Formatter('%(message)s')
            fh.setFormatter(formatter)
            
            log.addHandler(fh)
            log.propagate = False

    def _get_ip_from_mac(self, mac_addr):
        if mac_addr is None:
            return None 
        mac_str = str(mac_addr).lower()
        for ip, mac in self.arp_cache.items():
            if str(mac).lower() == mac_str:
                return ip
        return None

    def _format_bytes(self, size):
        power = 1024
        n = 0
        power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power:
            size /= float(power)
            n += 1
        return "{:.2f} {}".format(size, power_labels.get(n, 'TB+'))

    def handle_flow_stats(self, event):
        dpid = event.connection.dpid
        
        # --- 1. Process Data ---
        host_stats = {} 
        proto_stats = {
            'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0,
            'IP_Aggr': 0, 'Ctrl': 0     
        }

        for f in event.stats:
            # Protocol Classification
            if f.match.dl_type == ethernet.ARP_TYPE:
                proto_stats['ARP'] += f.byte_count
            elif f.match.dl_type == ethernet.IP_TYPE:
                if f.match.nw_proto == 6:
                    proto_stats['TCP'] += f.byte_count
                elif f.match.nw_proto == 17:
                    proto_stats['UDP'] += f.byte_count
                elif f.match.nw_proto == 1:
                    proto_stats['ICMP'] += f.byte_count
                else:
                    proto_stats['IP_Aggr'] += f.byte_count
            else:
                proto_stats['Ctrl'] += f.byte_count
            
            # Host Statistics
            src_ip = str(f.match.nw_src) if f.match.nw_src else self._get_ip_from_mac(f.match.dl_src)
            if src_ip:
                if src_ip not in host_stats: host_stats[src_ip] = {'tx': 0, 'rx': 0}
                host_stats[src_ip]['tx'] += f.byte_count
            
            dst_ip = str(f.match.nw_dst) if f.match.nw_dst else self._get_ip_from_mac(f.match.dl_dst)
            if dst_ip:
                if dst_ip not in host_stats: host_stats[dst_ip] = {'tx': 0, 'rx': 0}
                host_stats[dst_ip]['rx'] += f.byte_count

        # --- 2. Format Output for this Switch ---
        lines = []
        
        header_str = " [ Switch %s ] " % dpid
        lines.append(header_str.center(77, "="))
        
        # Protocol Line
        log_parts = []
        display_order = ['TCP', 'UDP', 'ICMP', 'ARP', 'IP_Aggr', 'Ctrl']
        for p in display_order:
            val = proto_stats.get(p, 0)
            val_str = self._format_bytes(val) if val > 0 else "X"
            log_parts.append("%s:%s" % (p, val_str))
        lines.append("   [Proto] " + " | ".join(log_parts))

        # Host Activity
        lines.append("   [Host Activity]")
        
        active_hosts = {k: v for k, v in host_stats.items() if v['tx'] > 0 or v['rx'] > 0}
        if not active_hosts:
            lines.append("          --- No activities at this moment ---")
        else:
            sorted_hosts = sorted(active_hosts.items(), 
                                  key=lambda item: item[1]['tx'] + item[1]['rx'], 
                                  reverse=True)
            for host, stats in sorted_hosts[:5]: # Top 5
                lines.append("     Host %-15s | TX: %-12s | RX: %-12s" % (
                             host, 
                             self._format_bytes(stats['tx']), 
                             self._format_bytes(stats['rx'])))
        
        lines.append(" ") # Empty line for spacing between switches

        self.stats_buffer[dpid] = "\n".join(lines)

        # --- 3. Check Condition to Flush Log ---
        connected_count = len(core.openflow.connections)
        
        if len(self.stats_buffer) >= connected_count:
            self._flush_log()

    def _flush_log(self):
        """Write the buffered stats to log file in one go"""
        log.info(" ")
        log.info("========================= NETWORK TRAFFIC STATISTIC =========================")
        log.info("Timestamp: %s", datetime.datetime.now().strftime('%H:%M:%S'))
        
        # Print switches in order (1, 2, 3...)
        for dpid in sorted(self.stats_buffer.keys()):
            log.info(self.stats_buffer[dpid])
        
        log.info("============================= END OF STATISTIC ==============================")
        
        # Clear buffer for next cycle
        self.stats_buffer.clear()
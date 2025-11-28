from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
import pox.openflow.libopenflow_01 as of
import collections

log = core.getLogger("ip_handler")

class IPHandler:
    def __init__(self, arp_handler, flow_installer, firewall, subnets):
        self.arp = arp_handler
        self.flows = flow_installer
        self.fw = firewall
        self.subnets = subnets
        self.waiting_packets = {} 
        self.discovery = core.openflow_discovery

    def get_gateway_ip(self, ip_str):
        for cidr, info in self.subnets.items():
            prefix = cidr.split('/')[0].rsplit('.', 1)[0]
            if ip_str.startswith(prefix):
                return info['gw_ip']
        return None

    def _get_path_bfs(self, src_dpid, dst_dpid):
        """
        Finds shortest path between switches using BFS.
        Treats links as Bidirectional (Undirected Graph) to handle async discovery.
        Returns list of DPIDs: [src, ..., dst]
        """
        if src_dpid == dst_dpid: return [src_dpid]
        
        # Build adjacency graph
        adj = collections.defaultdict(set)
        for link in self.discovery.adjacency:
            # Add edge A -> B
            adj[link.dpid1].add(link.dpid2)
            # Add edge B -> A 
            adj[link.dpid2].add(link.dpid1)
            
        # BFS
        queue = collections.deque([[src_dpid]])
        visited = set([src_dpid])
        
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == dst_dpid: return path
            for neighbor in adj[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)
        return None

    def _get_port_to_next_hop(self, src_dpid, next_dpid):
        """
        Returns the port on src_dpid that connects to next_dpid.
        Checks both link directions in discovery.
        """
        for link in self.discovery.adjacency:
            # Case 1: Discovery found Src -> Next
            if link.dpid1 == src_dpid and link.dpid2 == next_dpid:
                return link.port1
            # Case 2: Discovery found Next -> Src (Infer Src -> Next)
            if link.dpid1 == next_dpid and link.dpid2 == src_dpid:
                return link.port2
        return None

    def handle_ip_packet(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)
        
        # 1. Handle Ping to Gateway
        if dst_ip in self.arp.router_macs:
            if ip_pkt.protocol == ipv4.ICMP_PROTOCOL and ip_pkt.payload.type == 8:
                self.send_icmp_reply(event, ip_pkt)
            return True 
            
        src_gw = self.get_gateway_ip(src_ip)
        dst_gw = self.get_gateway_ip(dst_ip)
        
        # 2. Skip if destination is unknown or same subnet (L2 handles same subnet)
        if not dst_gw: return False 
        if src_gw == dst_gw: return False

        # 3. L3 Routing Logic
        if dst_ip in self.arp.arp_cache and dst_ip in self.arp.ip_port_map:
            self.install_end_to_end_routing(event, src_ip, dst_ip, dst_gw)
        else:
            # Queue packet and ARP for destination
            if dst_ip not in self.waiting_packets:
                self.waiting_packets[dst_ip] = []
                self.arp.send_arp_request_from_controller(dst_ip)
            self.waiting_packets[dst_ip].append(event)
            
        return True

    def install_end_to_end_routing(self, event, src_ip, dst_ip, dst_gw_ip):
        """Installs flows for both Forward and Reverse paths across all switches."""
        ingress_dpid = event.dpid
        egress_dpid, egress_port = self.arp.ip_port_map[dst_ip]
        
        dst_mac = self.arp.arp_cache[dst_ip]
        dst_gw_mac = self.arp.router_macs[dst_gw_ip]

        # --- A. Forward Path Installation (Src -> Dst) ---
        path = self._get_path_bfs(ingress_dpid, egress_dpid)
        
        if path:
            log.info("Installing Path %s: %s -> %s", path, src_ip, dst_ip)
            
            for i, dpid in enumerate(path):
                # Determine output port
                if dpid == egress_dpid:
                    out_port = egress_port # Last hop: output to host
                else:
                    out_port = self._get_port_to_next_hop(dpid, path[i+1]) # Middle hop: output to next switch
                
                if out_port:
                    self.flows.install_l3_flow(
                        core.openflow.getConnection(dpid),
                        src_ip, dst_ip,
                        dst_gw_mac, dst_mac, # Rewrite MACs to look like Router->Host
                        out_port, event.parsed.payload
                    )

            # Send the first packet directly to Egress to minimize latency
            msg = of.ofp_packet_out(data=event.ofp.data)
            msg.actions.append(of.ofp_action_dl_addr.set_src(dst_gw_mac))
            msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            msg.actions.append(of.ofp_action_output(port=egress_port))
            core.openflow.sendToDPID(egress_dpid, msg)
        else:
            log.warning("No Path found from %s to %s. Discovery might be incomplete.", ingress_dpid, egress_dpid)

        # --- B. Reverse Path Installation (Dst -> Src) ---
        # Only if we know the Source Host info (to rewrite MACs correctly)
        if src_ip in self.arp.arp_cache and src_ip in self.arp.ip_port_map:
            src_mac = self.arp.arp_cache[src_ip]
            src_gw_ip = self.get_gateway_ip(src_ip)
            src_gw_mac = self.arp.router_macs[src_gw_ip]
            src_egress_dpid, src_egress_port = self.arp.ip_port_map[src_ip]

            # Reverse path is just the forward path reversed
            rev_path = path[::-1] if path else self._get_path_bfs(egress_dpid, src_egress_dpid)
            
            if rev_path:
                log.info("Installing Reverse Path %s: %s -> %s", rev_path, dst_ip, src_ip)
                for i, dpid in enumerate(rev_path):
                    if dpid == src_egress_dpid:
                        out_port = src_egress_port
                    else:
                        out_port = self._get_port_to_next_hop(dpid, rev_path[i+1])
                    
                    if out_port:
                        # Note: Swap src/dst IPs for reverse flow
                        self.flows.install_l3_flow(
                            core.openflow.getConnection(dpid),
                            dst_ip, src_ip,
                            src_gw_mac, src_mac,
                            out_port, event.parsed.payload
                        )

    def process_waiting_packets(self, ip_str):
        if ip_str in self.waiting_packets:
            gw = self.get_gateway_ip(ip_str)
            for event in self.waiting_packets[ip_str]:
                packet = event.parsed
                src_ip = str(packet.payload.srcip)
                if ip_str in self.arp.ip_port_map:
                    self.install_end_to_end_routing(event, src_ip, ip_str, gw)
            del self.waiting_packets[ip_str]

    def send_icmp_reply(self, event, ip_pkt):
        icmp_req = ip_pkt.payload
        icmp_rep = icmp(type=0, code=0, payload=icmp_req.payload)
        ip_rep = ipv4(protocol=ipv4.ICMP_PROTOCOL, srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, payload=icmp_rep)
        eth_rep = ethernet(type=ethernet.IP_TYPE, src=event.parsed.dst, dst=event.parsed.src, payload=ip_rep)
        msg = of.ofp_packet_out(data=eth_rep.pack())
        msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
        event.connection.send(msg)
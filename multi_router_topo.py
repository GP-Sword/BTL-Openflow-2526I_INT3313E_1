from mininet.topo import Topo

class MultiRouterTopo(Topo):
    "Topology for SDN Lab: Triangle Topology (s1-s2-s3 connected in a ring)"

    def __init__(self):
        Topo.__init__(self)

        # Create Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Create Hosts for Subnet A (10.0.1.0/24)
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        
        # Create Hosts for Subnet B (10.0.2.0/24)
        h3 = self.addHost('h3', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        h4 = self.addHost('h4', ip='10.0.2.3/24', defaultRoute='via 10.0.2.1')

        # Create Hosts for Subnet C (10.0.3.0/24)
        h5 = self.addHost('h5', ip='10.0.3.2/24', defaultRoute='via 10.0.3.1')
        h6 = self.addHost('h6', ip='10.0.3.3/24', defaultRoute='via 10.0.3.1')

        # Link Hosts to Switches
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)

        # Link Switches (Triangle/Ring Topology)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s1, s3)

topos = {'multirouter': (lambda: MultiRouterTopo())}
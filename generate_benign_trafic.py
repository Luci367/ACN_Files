from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep

from datetime import datetime
from random import randrange, choice

class MyTopo( Topo ):

    def build( self ):

        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        h1 = self.addHost( 'h1', mac="00:00:00:00:00:01", ip="10.0.0.1/24" )
        h2 = self.addHost( 'h2',  mac="00:00:00:00:00:02", ip="10.0.0.2/24" )
        h3 = self.addHost( 'h3',  mac="00:00:00:00:00:03", ip="10.0.0.3/24" )    

        h4 = self.addHost( 'h4',  mac="00:00:00:00:00:04", ip="10.0.0.4/24" )
        h5 = self.addHost( 'h5',  mac="00:00:00:00:00:05", ip="10.0.0.5/24" )
        h6 = self.addHost( 'h6',  mac="00:00:00:00:00:06", ip="10.0.0.6/24" )
        
        h7 = self.addHost( 'h7',  mac="00:00:00:00:00:07", ip="10.0.0.7/24" )
        h8 = self.addHost( 'h8',  mac="00:00:00:00:00:08", ip="10.0.0.8/24" )
        h9 = self.addHost( 'h9',  mac="00:00:00:00:00:09", ip="10.0.0.9/24" )

        h10 = self.addHost( 'h10',  mac="00:00:00:00:00:10", ip="10.0.0.10/24" )
        h11 = self.addHost( 'h11',  mac="00:00:00:00:00:11", ip="10.0.0.11/24" )
        h12 = self.addHost( 'h12',  mac="00:00:00:00:00:12", ip="10.0.0.12/24" )

        
        # Add links

        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )

        self.addLink( h4, s1 )
        self.addLink( h5, s1 )
        self.addLink( h6, s1 )

        self.addLink( h7, s1 )
        self.addLink( h8, s1 )
        self.addLink( h9, s1 )

        self.addLink( h10, s1 )
        self.addLink( h11, s1 )
        self.addLink( h12, s1 )

    
        

def random_host_ip():

    ip = ".".join(["10","0","0",str(randrange(7,12))])
    return ip
        
def startNetwork():

    print("Starting Mininet Topology")
    topo = MyTopo()
    

    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    net.start()
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h5 = net.get('h5')
    h6 = net.get('h6')
    h7 = net.get('h7')
    h8 = net.get('h8')
    h9 = net.get('h9')
    h10 = net.get('h10')
    h11 = net.get('h11')
    h12 = net.get('h12')
    
    
    host1 = [h1, h2, h3, h4, h5, h6]    
    # host2 = [h7, h8, h9, h10, h11, h12]

    for i in range(1):
        src = choice(host1)
        dst_ip = random_host_ip()

        print(f"Sending ICMP ping from {src.name} to {dst_ip}")
        src.cmd(f"ping {dst_ip} -c 50 &")
        sleep(10)

        print(f"Sending UDP traffic from {src.name} to {dst_ip} at 50Mbps for 20 seconds")
        src.cmd(f"iperf -u -c {dst_ip} -b 50M -t 20 &")
        sleep(10)



    CLI(net)
    net.stop()

if __name__ == '__main__':
    
    start = datetime.now()
    
    setLogLevel( 'info' )
    startNetwork()
    
    end = datetime.now()
    
    print(end-start)

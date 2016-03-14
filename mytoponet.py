#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import Intf
from mininet.log import setLogLevel, info

def myNetwork():

    net = Mininet( topo=None,
                   build=False)


    info( '*** Adding controller\n' )
    net.addController(name='c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1')
    Intf( 'eth1', node=s1 )
    net.addNAT().configDefault()
    s2 = net.addSwitch('s2')

    s3 = net.addSwitch('s3')


    info( '*** Add hosts\n')
    h1 = net.addHost('h1', ip='0.0.0.0')
    h2 = net.addHost('h2', ip='0.0.0.0')
    h3 = net.addHost('h3', ip='0.0.0.0')
    h4 = net.addHost('h4', ip='0.0.0.0')
#    h1 = net.addHost('h1', ip='10.0.3.16')
#    h2 = net.addHost('h2', ip='10.0.3.18')
#    h3 = net.addHost('h3', ip='10.0.3.19')
#    h4 = net.addHost('h4', ip='10.0.3.20')
#    h1 = net.addHost('h1')

    

    info( '*** Add links\n')
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(h3, s3)
    net.addLink(h4, s3)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s1, s3)
#    net.addLink(h1, s1)

    info( '*** Starting network\n')
    net.start()
    h1.cmdPrint('dhclient '+h1.defaultIntf().name)
    h2.cmdPrint('dhclient '+h2.defaultIntf().name)
    h3.cmdPrint('dhclient '+h3.defaultIntf().name)
    h4.cmdPrint('dhclient '+h4.defaultIntf().name)
    CLI(net)
    net.stop()
if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

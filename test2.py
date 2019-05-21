from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import Ryu, RemoteController

class Controller(Ryu):
    def __init__(self, port=6653):
        print("Creat")
        args = '--observe-links '
        app = 'ryu.app.ryu_anon ryu.app.gui_topology.gui_topology'
        ryu_args = args + ' ' + app
        Ryu.__init__(self, 'ryu', ryu_args, port=port)
        #self.url = 'http://localhost:%d' % 8080


res = [0] * 11

class linear(Topo):
    def build(self, n=1):
        switch = self.addSwitch('s1')
        for h in range(1,n):
            host = self.addHost('h%s' % (h))
            switch1 = self.addSwitch('s%s' % (h + 1))
            self.addLink(host, switch)
            self.addLink(switch, switch1)
            switch, switch1 = switch1, switch

def Test(var, i):
    global res
    res1 = 0
    controller = Controller()
    controller.start()
    topo = linear(var)
    net = Mininet(topo=topo, controller=RemoteController(controller.name, port=6653))
    #net = Mininet(topo=topo)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    res1=net.pingAllFull()
    res[i] += res1
    net.stop()
    controller.stop()

if __name__ == '__main__':
    setLogLevel('info')
    i = 0
    for var in range(10, 120, 10):
        for var1 in range(0, 10):
            Test(var, i)
            res[i] = res[i] / 10
        i+=1
print("res = ", res)

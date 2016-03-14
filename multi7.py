from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
from ryu.lib.packet import ipv4


GOOGLE_IP = '189.124.133.187'
FILAB_IP = '130.206.81.46'	#orion.lab.fi-ware.org eh o endereco IP valido da instancia do Orion Context Broker no FiLAB


GID = 50
UDP_PROTO = 17
TCP_PROTO = 6

#./bin/ryu-manager ~/ryu/ryu/app/multi7.py

#sudo ~/mininet/examples/mynat.py

#mininet> h4 ping h1 -c1

#mininet> h3 ping h1 -c1

#mininet> xterm h1 h3

#h3> iperf -u -s

#h1> iperf -u -c 10.0.0.3

#This command below is to change a value
#h1> (curl 130.206.81.46:1026/v1/updateContext -s -S --header 'Content-Type: application/json' --header 'Accept: application/json' --header "X-Auth-Token: 37L3brQOMxlp6yBfqsDIDp79BQC2kl" -d @- ) <<EOF
#{
#    "contextElements": [
#        {
#            "type": "Room",
#            "isPattern": "false",
#            "id": "Room2",
#            "attributes": [
#                {
#                    "name": "temperature",
#                    "type": "float",
#                    "value": "100.0"
#               }
#            ]
#        }
#    ],
#    "updateAction": "UPDATE"
#}
#EOF

#This command below is to subscribe to a resource
#(curl 130.206.81.46:1026/v1/subscribeContext -s -S --header 'Content-Type: application/json' --header 'Accept: application/json' #--header "X-Auth-Token: 37L3brQOMxlp6yBfqsDIDp79BQC2kl" -d @- ) <<EOF
#> {
#>     "entities": [
#>         {
#>             "type": "Room",
#>             "isPattern": "false",
#>             "id": "Room2"
#>         }
#>     ],
#>     "attributes": [
#>         "temperature"
#>     ],
#>     "reference": "http://localhost:1028/accumulate",
#>     "duration": "P1M",
#>     "notifyConditions": [
#>         {
#>             "type": "ONCHANGE",
#>             "condValues": [
#>                 "temperature"
#>             ]
#>         }
#>     ],
#>     "throttling": "PT5S"
#> }
#> EOF


#h1> sudo ./accumulator-server.py 1028 /accumulate on



#hostOS> sudo pip install Flask

#hostOS> Download file 'accumulator-server.py'

#hostOS> sudo chmod +x accumulator-server.py







class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i = 0
        self.dpset = dpset.DPSet()
        self.mac_to_port = {}
        self.ip_to_port = {}
#	self.ip_to_switch = {'10.0.3.16' : 2, '10.0.3.18' : 2, '10.0.3.3' : 2, '10.0.3.19' : 3, '10.0.3.20' : 3}
	self.ip_to_switch = {GOOGLE_IP : 1, FILAB_IP : 1, '10.0.0.1' : 2, '10.0.0.2' : 2,  '10.0.0.3' : 3, '10.0.0.4' : 3}
#	self.ip_to_switch = { 1: {}, 2: {}, 3 : {} }
	self.switch_to_buckets = { 1: [] }
	self.src_to_groups = { 1: {}, 2: {}, 3: {} }
	self.src_to_buckets = { 1: {}, 2: {}, 3: {} }
        self.dpset = dpset.DPSet()

	buckets = []


    # Handy function that lists all attributes in the given object

    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                 datapath=datapath, match=match, cookie=0,
                 command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                 priority=0, instructions=inst)
        datapath.send_msg(mod)

        # add rule for multipath transmission in s1
        if ev.msg.datapath.id == 3:
	    print "switch "+str(ev.msg.datapath.id)
	    sid=3
        # add rule for multipath transmission in s2
        if ev.msg.datapath.id == 1:
	    print "switch "+str(ev.msg.datapath.id)
	    sid=1
        # add rule for multipath transmission in s3
        if ev.msg.datapath.id == 2:
	    print "switch "+str(ev.msg.datapath.id)
	    sid=2
        # add rule for multipath transmission in s4
        if ev.msg.datapath.id == 4:
	    print "switch "+str(ev.msg.datapath.id)
	    sid=4
            # in_port=1,src=10.0.0.1,dst=10.0.0.2--->output port:2
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=3, instructions=inst)
            datapath.send_msg(mod)
            # in_port=2,src=10.0.0.1,dst=10.0.0.2--->output port:3
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
#            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="10.0.0.1", ipv4_dst="10.0.0.2", ip_proto=17, udp_dst=5555)
            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="10.0.0.1", ip_proto=17, udp_dst=5555)
            actions = [parser.OFPActionOutput(3)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=3, instructions=inst)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        ip = pkt.get_protocol(ipv4.ipv4)


	if ip != None and out_port != ofproto.OFPP_FLOOD:
		ip_src = ip.src
		ip_dst = ip.dst
	      	self.logger.info("packet in switch %s from %s to %s in_port %s  \n", dpid, ip_src, ip_dst, in_port)

	        actions = [ parser.OFPActionSetField(ipv4_dst=ip_src),
				parser.OFPActionSetField(eth_dst=src),
				parser.OFPActionOutput(in_port) ]
				
		bucket = parser.OFPBucket(weight=0,
				watch_port=ofproto_v1_3.OFPP_ANY,
				watch_group=ofproto_v1_3.OFPQ_ALL,
				actions=actions) 


	       	self.logger.info("actions "+str(actions)+" bucket "+str(bucket))

		sid = self.ip_to_switch[ip_dst]
		if sid==None:
			print "entry not found: "+str(ip_dst)
			return


		print "sid "+str(sid)+"/ dpid "+str(dpid)+" / ip_dst= "+str(ip_dst)+" / self.src_to_groups[sid] is "+str(self.src_to_groups[sid])

		if sid != dpid:
			print "This sw "+str(dpid)+" is not the edge ("+str(sid)+") from the destination "+str(ip_dst)
			if ip_src not in self.src_to_groups[dpid]:
				print "ip_src "+str(ip_src)+ " / is not in "+str(self.src_to_groups[dpid])
				if len(self.src_to_groups[dpid]) != 0:
					print "len %d" % len(self.src_to_groups[dpid])
					gid = self.src_to_groups[dpid].values()[0]
					print "gid "+str(gid)
					cmd = ofproto.OFPGC_MODIFY

					self.src_to_buckets[dpid][gid].append(bucket)
					buckets = self.src_to_buckets[dpid][gid]
					print buckets
	
					req = parser.OFPGroupMod(datapath=datapath,
								command=cmd,
								type_=ofproto.OFPGT_ALL,
								group_id=gid,
								buckets=self.src_to_buckets[dpid][gid])
					datapath.send_msg(req)

#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17, udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17)
				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=TCP_PROTO)
				    	actions = [datapath.ofproto_parser.OFPActionGroup(gid)]
				    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
				    	mod = datapath.ofproto_parser.OFPFlowMod(
					        datapath=datapath, match=match, cookie=0,
					        command=cmd, idle_timeout=0, hard_timeout=0,
					        priority=3, instructions=inst)
					datapath.send_msg(mod)
		
		      			self.logger.info("****** %s subscribes to %s *******", ip_src, ip_dst)	
				else:
					self.src_to_groups[dpid][ip_src] = len(self.src_to_groups[dpid])+1
					gid = self.src_to_groups[dpid][ip_src]
					cmd = ofproto.OFPFC_ADD
					self.src_to_buckets[dpid][gid] = []
					self.src_to_buckets[dpid][gid].append(bucket)
	
					req = parser.OFPGroupMod(datapath=datapath,
								command=cmd,
								type_=ofproto.OFPGT_ALL,
								group_id=gid,
								buckets=self.src_to_buckets[dpid][gid])
					datapath.send_msg(req)
		
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17, udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17)

				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=TCP_PROTO)

				    	actions = [datapath.ofproto_parser.OFPActionGroup(gid)]
				    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
				    	mod = datapath.ofproto_parser.OFPFlowMod(
						datapath=datapath, match=match, cookie=0,
						command=cmd, idle_timeout=0, hard_timeout=0,
						priority=3, instructions=inst)
					datapath.send_msg(mod)

		      			self.logger.info("****** %s subscribes to %s *******", ip_src, ip_dst)	


		else:
			if ip_src not in self.src_to_groups[sid]:
				print "ip_src "+str(ip_src)+ " / is not in "+str(self.src_to_groups[sid])
				if len(self.src_to_groups[sid]) != 0:
					gid = self.src_to_groups[sid].values()[0]
					print "gid "+str(gid)
		#			gid = GID+1
					cmd = ofproto.OFPGC_MODIFY
	
					self.src_to_buckets[sid][gid].append(bucket)
					buckets = self.src_to_buckets[sid][gid]
					print buckets

					req = parser.OFPGroupMod(datapath=datapath,
								command=cmd,
								type_=ofproto.OFPGT_ALL,
		#						type_=ofproto.OFPGT_SELECT,
								group_id=gid,
								buckets=self.src_to_buckets[sid][gid])
		#						buckets=bucket)
					datapath.send_msg(req)


#			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ipv4_dst=ip_src, ip_proto=17, udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17, udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17)
				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=TCP_PROTO)


				    	actions = [datapath.ofproto_parser.OFPActionGroup(gid)]
				    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
				    	mod = datapath.ofproto_parser.OFPFlowMod(
					        datapath=datapath, match=match, cookie=0,
					        command=cmd, idle_timeout=0, hard_timeout=0,
					        priority=3, instructions=inst)
					datapath.send_msg(mod)
		
		      			self.logger.info("****** %s subscribes to %s *******", ip_src, ip_dst)	
				else:
					self.src_to_groups[sid][ip_src] = len(self.src_to_groups[sid])+1
					gid = self.src_to_groups[sid][ip_src]
		#			gid = GID+1
					cmd = ofproto.OFPFC_ADD
		##			cmd = ofproto.OFPGC_MODIFY
					self.src_to_buckets[sid][gid] = []
					self.src_to_buckets[sid][gid].append(bucket)
	
					req = parser.OFPGroupMod(datapath=datapath,
								command=cmd,
								type_=ofproto.OFPGT_ALL,
			#					type_=ofproto.OFPGT_SELECT,
								group_id=gid,
								buckets=self.src_to_buckets[sid][gid])
			#					buckets=bucket)
					datapath.send_msg(req)
		
	
	
	#			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ipv4_dst=ip_src, ip_proto=17, 	udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17, udp_dst=5555)
#				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17)
				  	match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=TCP_PROTO)

				    	actions = [datapath.ofproto_parser.OFPActionGroup(gid)]
				    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
				    	mod = datapath.ofproto_parser.OFPFlowMod(
						datapath=datapath, match=match, cookie=0,
						command=cmd, idle_timeout=0, hard_timeout=0,
						priority=3, instructions=inst)
					datapath.send_msg(mod)
			

			else:

				self.src_to_groups[sid][ip_src] = len(self.src_to_groups[sid])+1
				gid = self.src_to_groups[sid][ip_src]
				cmd = ofproto.OFPFC_ADD
				self.src_to_buckets[sid][gid] = []
				self.src_to_buckets[sid][gid].append(bucket)
	
				req = parser.OFPGroupMod(datapath=datapath,
							command=cmd,
							type_=ofproto.OFPGT_ALL,
							group_id=gid,
							buckets=self.src_to_buckets[sid][gid])

				datapath.send_msg(req)
		

	
#			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ipv4_dst=ip_src, ip_proto=17, 	udp_dst=5555)
#			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17, udp_dst=5555)
#			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=17)
			  	match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src=ip_dst, ip_proto=TCP_PROTO)

			    	actions = [datapath.ofproto_parser.OFPActionGroup(gid)]
			    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			    	mod = datapath.ofproto_parser.OFPFlowMod(
				        datapath=datapath, match=match, cookie=0,
				        command=cmd, idle_timeout=0, hard_timeout=0,
				        priority=3, instructions=inst)
				datapath.send_msg(mod)

#        print "nodes"
#        print self.net.nodes()
#        print "edges"
#        print self.net.edges()
#	if src == '10.0.0.1' and dst == '10.0.0.4':
        
	if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port': in_port})
            self.net.add_edge(src,dpid)
       # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)

#	self.logger.info("Forward the packet out: "+str(actions))

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        print "**********List of switches"
        for switch in switch_list:
            # self.ls(switch)
            print switch
        # self.nodes[self.no_of_nodes] = switch
        # self.no_of_nodes += 1
        links_list = get_link(self.topology_api_app, None)
        # print links_list
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # print links
        self.net.add_edges_from(links)
        links = [(link.dst.dpid,link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        # print links
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()

# The MIT License (MIT)
# 
# Copyright (c) 2015 Sam Russell
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import switches, event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp, dhcp, arp
from ryu.lib import addrconv

import json


class Trekin(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(Trekin, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dhcp_leases = {}
        # add special case
        self.dhcp_leases['00:16:3e:f2:d9:d3'] = {'ipaddr':'10.1.1.1', 'port' : 3}
        # test data
        self.ips = set(['10.1.1.2', '10.1.1.3', '10.1.1.4', '10.1.1.5', '10.1.1.6'])

        # try to get leases and ips from file
        dump = None
        try:
            dump = open('/state/dump')
        except IOError:
            pass
        if dump:
            data = dump.read()
            datadict = json.loads(data)
            self.dhcp_leases = datadict['dhcp_leases']
            self.ips = set(datadict['ips'])
    
    def add_lease(self, mac, ipaddr, port):
        self.dhcp_leases[mac] = {'ipaddr' : ipaddr, 'port' : port}
        data = json.dumps({'dhcp_leases' : self.dhcp_leases, 'ips' : list(self.ips)})
        open('/state/dump', 'w').write(data)

    def insert_ip_rule(self, datapath, ofproto, parser, in_port, src, ipaddr):
        # add flow to match egress to this IP
        match = parser.OFPMatch(
                                  eth_type = 0x0800,  # IP
                                  eth_dst = "00:12:34:56:78:90",
                                  ipv4_dst = ipaddr 
                                  )
        actions = [parser.OFPActionSetField(eth_src="00:12:34:56:78:90"),
                    parser.OFPActionSetField(eth_dst=src),
                    parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 5, match, actions, table_id=2)
        # add flow to allow ingress from this IP
        match = parser.OFPMatch(
                                  eth_type = 0x0800,  # IP
                                  eth_dst = "00:12:34:56:78:90",
                                  ipv4_src = ipaddr 
                                  )
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_instruction(datapath, 5, match, inst, table_id=1)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter(self, ev):
        print "Switch entered"
        datapath = ev.switch.dp
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print "Datapath: %s" % datapath.id
        # if datapath = 1 then we're awesome
        if datapath.id == 1:
            print "datapath 1 - this is ours"
            # clear flows
            mod = parser.OFPFlowMod(datapath, 0, 0, ofproto.OFPTT_ALL, ofproto.OFPFC_DELETE,
                                    0, 0, 1, ofproto.OFPCML_NO_BUFFER,
                                    ofproto.OFPP_ANY, ofproto.OFPG_ANY, 0,
                                    parser.OFPMatch(), [])
            datapath.send_msg(mod)
            # punch out dhcp flow
            match = parser.OFPMatch(
                                      eth_type = 0x0800,  # IPv4
                                      ip_proto = 17,      # UDP
                                      udp_dst  = 67      # DHCP request
                                      )
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 10, match, actions)
            # punch out arp flow
            match = parser.OFPMatch(
                                      eth_type = 0x0806,  # ARP
                                      )
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 10, match, actions)
            # punch out EAPOL flow
            match = parser.OFPMatch(
                                      eth_type = 0x888e,  # EAPOL
                                      )
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 10, match, actions)
            # default flow
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_instruction(datapath, 0, match, inst, table_id=0)
            #match = parser.OFPMatch()
            #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
            #                                  ofproto.OFPCML_NO_BUFFER)]
            #self.add_flow(datapath, 0, match, actions, table_id=1)

            # replace ip flows
            for lease in self.dhcp_leases.iteritems():
                src = lease[0]
                ipaddr = lease[1]['ipaddr']
                in_port = lease[1]['port']
                self.insert_ip_rule(datapath, ofproto, parser, in_port, src, ipaddr)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                  ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, match, actions)

    def add_instruction(self, datapath, priority, match, inst, buffer_id=None, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    table_id=table_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                    priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_instruction(datapath, priority, match, inst, buffer_id, table_id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # custom packet handler

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            print "ipv4 packet"
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                print "udp packet"
                if udp_pkt.dst_port==67:
                    print "DHCP packet"
                    dhcp_pkt = dhcp.dhcp.parser(pkt.protocols[-1])[0]
                    #print dhcp_pkt
                    self.handle_dhcp(datapath, ofproto, parser, in_port, src, dhcp_pkt)
                    return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            print "arp packet"
            self.handle_arp(datapath, ofproto, parser, in_port, src, arp_pkt)
            return
        # do eapol the dirty way
        if eth.ethertype == 0x888e:
            print "EAPOL packet"


    # handle_dhcp(datapath, ofproto, parser, in_port, dhcp_pkt)
    def handle_dhcp(self, datapath, ofproto, parser, in_port, src, dhcp_pkt):
        # process packet
        dhcpoptions = [x for x in dhcp_pkt.options.option_list if x.tag == 53]
        if len(dhcpoptions) != 1:
            return
        if dhcpoptions[0].value == '\x01':
            # dhcp discover
            # find request list
            requests = [x for x in dhcp_pkt.options.option_list if x.tag == 55]
            if len(requests) == 1:
                pass
                #print "requesting options:"
                #print ", ".join([str(ord(x)) for x in requests[0].value])
            # look up MAC address in dhcp_leases
            ipaddr = None
            if src in self.dhcp_leases:
                ipaddr = self.dhcp_leases[src]['ipaddr']
            else:
                ipaddr = self.ips.pop()
                self.add_lease(src, ipaddr, in_port)
                #self.dhcp_leases[src] = {'ipaddr' : ipaddr, 'port' : in_port}
            print "Assigning IP %s to mac %s on port %s" % (ipaddr, src, in_port)
            print "Replying to DHCP discover"
            option_list = [
                            dhcp.option(tag=53, value='\x02'),
                            dhcp.option(tag=1, value=addrconv.ipv4.text_to_bin('255.255.255.0')),
                            dhcp.option(tag=51, value='\x00\x00\x21\xc0'),
                            dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin(ipaddr)),
                          ]
            self.dhcp_reply(datapath, ofproto, parser, in_port, src, dhcp_pkt, ipaddr, option_list)

            

        if dhcpoptions[0].value == '\x03':
            print "DHCP request"
            # dhcp request
            requests = [x for x in dhcp_pkt.options.option_list if x.tag == 50]
            if len(requests) != 1:
                print "no option 50"
                return
            if src not in self.dhcp_leases:
                print "no lease for mac %s" % src
                option_list = [
                                dhcp.option(tag=53, value='\x06'),
                              ]
                self.dhcp_reply(datapath, ofproto, parser, in_port, src, dhcp_pkt, '0.0.0.0', option_list)
                return
            reqipaddr = addrconv.ipv4.bin_to_text(requests[0].value)
            ipaddr = self.dhcp_leases[src]['ipaddr']
            if ipaddr != reqipaddr:
                print "client requesting wrong address: %s (should be %s)" % (reqipaddr, ipaddr)
                return
            print "Add flow for new IP %s" % ipaddr
            # you can force LAN traffic to go through a firewall if you want
            #if in_port != 3:
            #    match = parser.OFPMatch(
            #                            in_port = in_port
            #                              )
            #    actions = [parser.OFPActionSetField(eth_src="00:12:34:56:78:90"),
            #                parser.OFPActionSetField(eth_dst="00:16:3e:f2:d9:d3"),
            #                parser.OFPActionOutput(3)]
            #    self.add_flow(datapath, 6, match, actions)

            self.insert_ip_rule(datapath, ofproto, parser, in_port, src, ipaddr)


            print "Replying to DHCP request"
            option_list = [
                            dhcp.option(tag=53, value='\x05'),
                            dhcp.option(tag=1, value=addrconv.ipv4.text_to_bin('255.255.255.0')),
                            dhcp.option(tag=51, value='\x00\x00\x21\xc0'),
                            dhcp.option(tag=54, value=addrconv.ipv4.text_to_bin(ipaddr)),
                          ]

            self.dhcp_reply(datapath, ofproto, parser, in_port, src, dhcp_pkt, ipaddr, option_list)

    def dhcp_reply(self, datapath, ofproto, parser, in_port, src, dhcp_pkt, ipaddr, option_list):
        # create and send return packet
        options = dhcp.options(option_list)
        dhcp_offer = dhcp.dhcp(op = 2,
                               chaddr = dhcp_pkt.chaddr,
                               hlen = 6,
                               options = options,
                               yiaddr = ipaddr,
                               siaddr = '10.1.1.254',
                               xid = dhcp_pkt.xid)
        # send packet
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0800,
                                            dst=src,
                                            src=0x1234567890))
        pkt.add_protocol(ipv4.ipv4(src='10.1.1.254',
                                    dst='255.255.255.255',
                                    proto=17))
        pkt.add_protocol(udp.udp(src_port=67,
                                  dst_port=68))
        pkt.add_protocol(dhcp_offer)
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, ofproto, parser, in_port, src, arp_pkt):
        if arp_pkt.opcode == arp.ARP_REQUEST:
            print "ARP request"
            # reply on behalf of lease
            macs = [x[0] for x in self.dhcp_leases.iteritems() if x[1]['ipaddr'] == arp_pkt.dst_ip]
            if len(macs) != 1:
                print "Looking for IP %s... not found" % arp_pkt.dst_ip
                return
            mac = macs[0]
            print "Looking for IP %s... MAC is %s" % (arp_pkt.dst_ip, mac)
            print "Insert our MAC instead"

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=0x0806,
                                                dst=src,
                                                src="00:12:34:56:78:90")
                                                )
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                      src_mac="00:12:34:56:78:90",
                                      src_ip=arp_pkt.dst_ip,
                                      dst_mac=arp_pkt.src_mac,
                                      dst_ip=arp_pkt.src_ip)
                                      )
            self.send_packet(datapath, parser, ofproto, in_port, pkt)
            print "Sent ARP reply"

    
    def send_packet(self, datapath, parser, ofproto, port, pkt):
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


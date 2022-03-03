#-----------------------------------------------------------------------------
#   Copyright (c) 2020, networksecuritytoolkit.org (NST). All rights reserved.
#-----------------------------------------------------------------------------
"""A python3 library for performing an enhanced scapy Multi-Traceroute (MTR)"""
"""with resulting SVG visual.                                               """

##########################
# Required Imports       #
##########################
import ipaddress
import re
from scapy.all import *
import time


##########################
# Classes From Kamene    #
##########################
class RandStringTerm(RandString):
    def __init__(self, size, term = b''):
        RandString.__init__(self, size)
        self.term = term
    def _fix(self):
        return RandString._fix(self) + self.term


##########################
# Utilities From Kamene  #
##########################
@conf.commands.register
def is_private_addr(x):
    """Returns True if the IPv4 Address is an RFC 1918 private address."""
    paddrs = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    found = False
    for ipr in paddrs:
        try:
            if ipaddress.ip_address(x) in ipaddress.ip_network(ipr):
                found = True
                continue
        except:
            break
    return found


##########################
# Multi-Traceroute Class #
##########################
class MTR:
    #
    # Initialize Multi-Traceroute Object Vars...
    def __init__(self, nquery=1, target=''):
        self._nquery = nquery		# Number or traceroute queries
        self._ntraces = 1		# Number of trace runs
        self._iface = ''		# Interface to use for trace
        self._gw = ''			# Default Gateway IPv4 Address for trace
        self._netprotocol = 'TCP'       # MTR network protocol to use for trace
        self._target = target		# Session targets
        self._exptrg = []		# Expanded Session targets
        self._host2ip = {}		# Target Host Name to IP Address
        self._ip2host = {}		# Target IP Address to Host Name
        self._tcnt = 0			# Total Trace count
        self._tlblid = []		# Target Trace label IDs
        self._res = []			# Trace Send/Receive Response Packets
        self._ures = []			# Trace UnResponse Sent Packets
        self._ips = {}			# Trace Unique IPv4 Addresses
        self._hops = {}			# Traceroute Hop Ranges
        self._rt = []			# Individual Route Trace Summaries
        self._ports = {}		# Completed Targets & Ports
        self._portsdone = {}		# Completed Traceroutes & Ports
        self._rtt = {}			# Round Trip Times (msecs) for Trace Nodes
        self._unknownlabel = incremental_label('"Unk%i"')
        self._asres = conf.AS_resolver  # Initial ASN Resolver
        self._asns = {}			# Found AS Numbers for the MTR session
        self._asds = {}			# Associated AS Number descriptions
        self._unks = {}			# Unknown Hops ASN IP boundaries
        self._graphdef = None
        self._graphasres = 0
        self._graphpadding = 0
    #
    # Get the protocol name from protocol integer value.
    #
    #  proto - Protocol integer value.
    #
    #   Returns a string value representing the given integer protocol.
    def get_proto_name(self, proto):
        ps = str(proto)
        if ps == '6':
            pt = 'tcp'
        elif ps == '17':
            pt = 'udp'
        elif ps == '1':
            pt = 'icmp'
        else:
            pt = str(proto)
        return pt

    #
    # Compute Black Holes...
    def get_black_holes(self):
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                for n in range(min(k), max(k)):
                    if not n in trace:				# Fill in 'Unknown' hops
                        trace[n] = next(self._unknownlabel)
                if not rtk in self._portsdone:
                    if rtk[2] == 1:     # ICMP
                        bh = "%s %i/icmp" % (rtk[1], rtk[3])
                    elif rtk[2] == 6:   # TCP
                        bh = "{ip:s} {dp:d}/tcp".format(ip=rtk[1], dp=rtk[3])
                    elif rtk[2] == 17:  # UDP
                        bh = '%s %i/udp' % (rtk[1], rtk[3])
                    else:
                        bh = '%s %i/proto' % (rtk[1], rtk[2])
                    self._ips[rtk[1]] = None			# Add the Blackhole IP to list of unique IP Addresses
                    #
                    # Update trace with Blackhole info...
                    bh = '"{bh:s}"'.format(bh=bh)
                    trace[max(k) + 1] = bh
        #
        # Detection for Blackhole - Failed target not set as last Hop in trace...
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                if (' ' not in trace[max(k)]) and (':' not in trace[max(k)]):
                    if rtk[2] == 1:     # ICMP
                        bh = "%s %i/icmp" % (rtk[1], rtk[3])
                    elif rtk[2] == 6:   # TCP
                        bh = "{ip:s} {dp:d}/tcp".format(ip=rtk[1], dp=rtk[3])
                    elif rtk[2] == 17:  # UDP
                        bh = '%s %i/udp' % (rtk[1], rtk[3])
                    else:
                        bh = '%s %i/proto' % (rtk[1], rtk[2])
                    self._ips[rtk[1]] = None			# Add the Blackhole IP to list of unique IP Addresses
                    #
                    # Update trace with Blackhole info...
                    bh = '"{bh:s}"'.format(bh=bh)
                    trace[max(k) + 1] = bh

    #
    # Compute the Hop range for each trace...
    def compute_hop_ranges(self):
        n = 1
        for t in range(0, self._ntraces):
            for rtk in self._rt[t]:
                trace = self._rt[t][rtk]
                k = trace.keys()
                #
                # Detect Blackhole Endpoints...
                h = rtk[1]
                mt = max(k)
                if not ':' in trace[max(k)]:
                    h = trace[max(k)].replace('"', '')  # Add a Blackhole Endpoint (':' Char does not exist)
                    if max(k) == 1:
                        #
                        # Special case: Max TTL set to 1...
                        mt = 1
                    else:
                        mt = max(k) - 1			# Blackhole - remove Hop for Blackhole -> Host never reached
                hoplist = self._hops.get(h, [])     	# Get previous hop value
                hoplist.append([n, min(k), mt])		# Append trace hop range for this trace
                self._hops[h] = hoplist			# Update mtr Hop value
                n += 1

    #
    # Get AS Numbers...
    def get_asns(self, privaddr=0):
        """Obtain associated AS Numbers for IPv4 Addreses.
           privaddr: 0 - Normal display of AS numbers,
                     1 - Do not show an associated AS Number bound box (cluster) on graph for a private IPv4 Address."""
        ips = {}
        if privaddr:
            for k, v in self._ips.items():
                if not is_private_addr(k):
                    ips[k] = v
        else:
            ips = self._ips
        #
        # Special case for the loopback IP Address: 127.0.0.1 - Do not ASN resolve...
        if '127.0.0.1' in ips:
            del ips['127.0.0.1']
        #
        # ASN Lookup...
        asnquerylist = dict.fromkeys(map(lambda x: x.rsplit(" ", 1)[0], ips)).keys()
        if self._asres is None:
            asnlist = []
        else:
            try:
                asnlist = self._asres.resolve(*asnquerylist)
            except:
                pass
        for ip, asn, desc, in asnlist:
            if asn is None:
                continue
            #
            # If ASN is a string Convert to a number: (i.e., 'AS3257' => 3257)
            if type(asn) == str:
                asn = asn.upper()
                nasn = asn.replace('AS', '')
            else:
                nasn = asn
            try:                                    # Make sure a number
                nasn = int(nasn)
            except:
                continue
            iplist = self._asns.get(nasn, [])       # Get previous ASN value
            iplist.append(ip)                       # Append IP Address to previous ASN
            self._asns[nasn] = iplist               # Store updated IP list
            self._asds[nasn] = desc                 # Append AS description

    #
    #  Get the ASN for a given IP Address.
    #
    #    ip - IP Address to get the ASN for.
    #
    #   Return the ASN for a given IP Address if found.
    #   A -1 is returned if not found.
    def get_asn_ip(self, ip):
        for a in self._asns:
            for i in self._asns[a]:
                if ip == i:
                    return a
        return -1

    #
    # Guess Traceroute 'Unknown (Unkn) Hops' ASNs.
    #
    #   Technique: Method to guess ASNs for Traceroute 'Unknown Hops'.
    #              If the assign ASN for the known Ancestor IP is the
    #              same as the known Descendant IP then use this ASN
    #              for the 'Unknown Hop'.
    #              Special case guess: If the Descendant IP is a
    #              Endpoint Host Target the assign it to its
    #              associated ASN.
    def guess_unk_asns(self):
        t = 1
        for q in range(0, self._ntraces):
            for rtk in self._rt[q]:
                trace = self._rt[q][rtk]
                tk = trace.keys()
                begip = endip = ''
                unklist = []
                for n in range(min(tk), (max(tk) + 1)):
                    if trace[n].find('Unk') == -1:
                        #
                        # IP Address Hop found...
                        if len(unklist) == 0:
                            #
                            # No 'Unknown Hop' found yet...
                            begip = trace[n]
                        else:
                            #
                            # At least one Unknown Hop found - Store IP boundary...
                            endip = trace[n]
                            for u in unklist:
                                idx = begip.find(':')
                                if idx != -1:		# Remove Endpoint Trace port info: '"162.144.22.85":T443'
                                    begip = begip[:idx]
                                idx = endip.find(':')
                                if idx != -1:
                                    endip = endip[:idx]
                                #
                                # u[0] - Unknown Hop name...
                                # u[1] - Hop number...
                                self._unks[u[0]] = [begip, endip, '{t:d}:{h:d}'.format(t=t, h=u[1])]
                            #
                            # Init var for new Unknown Hop search...
                            begip = endip = ''
                            unklist = []
                    else:
                        #
                        # 'Unknown Hop' found...
                        unklist.append([trace[n], n])
                t += 1					# Inc next trace count
        #
        # Assign 'Unknown Hop' ASN...
        for u in self._unks:
            bip = self._unks[u][0]
            bip = bip.replace('"', '')			# Begin IP - Strip off surrounding double quotes (")
            basn = self.get_asn_ip(bip)
            if basn == -1:
                continue
            eip = self._unks[u][1]
            eip = eip.replace('"', '')
            easn = self.get_asn_ip(eip)
            if easn == -1:
                continue
            #
            # Append the 'Unknown Hop' to an ASN if
            # Ancestor/Descendant IP ASN match...
            if basn == easn:
                self._asns[basn].append(u.replace('"', ''))
            else:
                #
                # Special case guess: If the Descendant IP is
                # a Endpoint Host Target the assign it to its
                # associated ASN.
                for d in self._tlblid:
                    if eip in d:
                        self._asns[easn].append(u.replace('"', ''))
                        break
    #
    # Make the DOT graph...
    def make_dot_graph(self, ASres=None, padding=0, vspread=0.75, title="Multi-Traceroute (MTR) Probe", timestamp="", rtt=1):
        import datetime
        import html
        if ASres is None:
            self._asres = conf.AS_resolver
        self._graphasres = ASres
        self._graphpadding = padding
        #
        # ASN box color generator...
        backcolorlist = colgen("60", "86", "ba", "ff")
        #
        # Edge (trace arrows)  color generator...
        forecolorlist = colgen("a0", "70", "40", "20")
        #
        # Begin the DOT Digraph...
        s = "### Scapy Multi-Traceroute (MTR) DOT Graph Results ({t:s}) ###\n".format(t=datetime.datetime.now().isoformat(' '))
        s += "\ndigraph mtr {\n"
        #
        # Define the default graph attributes...
        s += '\tgraph [bgcolor=transparent,ranksep={vs:.2f}];\n'.format(vs=vspread)
        #
        # Define the default node shape and drawing color...
        s += '\tnode [shape="ellipse",fontname="Sans-Serif",fontsize=11,color="black",gradientangle=270,fillcolor="white:#a0a0a0",style="filled"];\n'
        #
        # Combine Trace Probe Begin Points...
        #
        #                   k0       k1   k2       v0   v1           k0         k1    k2       v0   v1
        # Ex: bp = {('192.168.43.48',5555,''): ['T1','T3'], ('192.168.43.48',443,'https'): ['T2','T4']}
        bp = {}				# ep -> A single services label for a given IP
        for d in self._tlblid:          #            k             v0          v1               v2       v3   v4    v5      v6   v7
            for k, v in d.items():  # Ex: k:  '162.144.22.87' v: ('T1', '192.168.43.48', '162.144.22.87', 6, 443, 'https', 'SA', '')
                p = bp.get((v[1], v[4], v[5]))
                if p == None:
                    bp[(v[1], v[4], v[5])] = [v[0]]  # Add new (TCP Flags / ICMP / Proto) and initial trace ID
                else:
                    bp[(v[1], v[4], v[5])].append(v[0])  # Append additional trace IDs
        #
        # Combine Begin Point services...
        #                   k                 sv0           sv1            sv0          sv1
        # Ex bpip = {'192.168.43.48': [('<BT2>T2|<BT4>T4', 'https(443)'), ('<BB1>T1|<BT3>T3', '5555')]}
        bpip = {}			# epip -> Combined Endpoint services label for a given IP
        for k, v in bp.items():
            tr = ''
            for t in range(0, len(v)):
                if tr == '':
                    tr += '<B{ts:s}>{ts:s}'.format(ts=v[t])
                else:
                    tr += '|<B{ts:s}>{ts:s}'.format(ts=v[t])
            p = k[2]
            if p == '':		            # Use port number not name if resolved
                p = str(k[1])
            else:
                p += '(' + str(k[1]) + ')'  # Use both name and port
            if k[0] in bpip:
                bpip[k[0]].append((tr, p))
            else:
                bpip[k[0]] = [(tr, p)]
        #
        # Create Endpoint Target Clusters...
        epc = {}			# Endpoint Target Cluster Dictionary
        epip = []			# Endpoint IPs array
        oip = []			# Only Endpoint IP array
        epprb = []			# Endpoint Target and Probe the same IP array
        for d in self._tlblid:		# Spin thru Target IDs
            for k, v in d.items():      # Get access to Target Endpoints
                h = k
                if v[6] == 'BH':        # Add a Blackhole Endpoint Target
                    h = '{bh:s} {bhp:d}/{bht:s}'.format(bh=k, bhp=v[4], bht=v[3])
                elif v[1] == v[2]:      # When the Target and host running the mtr session are
                    epprb.append(k)     # the same then append IP to list target and probe the same array
                epip.append(h)
                oip.append(k)
        #
        # Create unique arrays...
        uepip = set(epip)		# Get a unique set of Endpoint IPs
        uepipo = set(oip)		# Get a unique set of Only Endpoint IPs
        uepprb = set(epprb)		# Get a unique set of Only IPs: Endpoint Target and Probe that are the same
        #
        # Now create unique endpoint target clusters....
        for ep in uepip:
            #
            # Get Host only string...
            eph = ep
            f = ep.find(' ')
            if f >= 0:
                eph = ep[0:f]
            #
            # Build Traceroute Hop Range label...
            if ep in self._hops:        # Is Endpoint IP in the Hops dictionary
                hr = self._hops[ep]
            elif eph in self._hops:     # Is Host only endpoint in the Hops dictionary
                hr = self._hops[eph]
            else:
                continue		# Not found in the Hops dictionary

            l = len(hr)
            if l == 1:
                hrs = "Hop Range ("
            else:
                hrs = "Hop Ranges ("
            c = 0
            for r in hr:
                hrs += 'T{s1:d}: {s2:d} &rarr; {s3:d}'.format(s1=r[0], s2=r[1], s3=r[2])
                c += 1
                if c < l:
                    hrs += ', '
            hrs += ')'
            ecs = "\t\t### MTR Target Cluster ###\n"
            uep = ep.replace('.', '_')
            uep = uep.replace(' ', '_')
            uep = uep.replace('/', '_')
            gwl = ''
            if self._gw == eph:
                gwl = ' (Default Gateway)'
            ecs += '\t\tsubgraph cluster_{ep:s} {{\n'.format(ep=uep)
            ecs += '\t\t\ttooltip="MTR Target: {trg:s}{gwl:s}";\n'.format(trg=self._ip2host[eph], gwl=gwl)
            ecs += '\t\t\tcolor="darkgreen";\n'
            ecs += '\t\t\tfontsize=11;\n'
            ecs += '\t\t\tfontname="Sans-Serif";\n'
            ecs += '\t\t\tgradientangle=270;\n'
            ecs += '\t\t\tfillcolor="white:#a0a0a0";\n'
            ecs += '\t\t\tstyle="filled,rounded";\n'
            ecs += '\t\t\tpenwidth=2;\n'
            ecs += '\t\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B>Target: {h:s}{gwl:s}</B></TD></TR><TR><TD><FONT POINT-SIZE="9">{hr:s}</FONT></TD></TR></TABLE>>;\n'.format(h=html.escape(self._ip2host[eph]), gwl=html.escape(gwl), hr=hrs)
            ecs += '\t\t\tlabelloc="b";\n'
            pre = ''
            if ep in uepprb:		# Special Case: Separate Endpoint Target from Probe
                pre = '_'		# when they are the same -> Prepend an underscore char: '_'
            ecs += '\t\t\t"{pre:s}{ep:s}";\n'.format(pre=pre, ep=ep)
            ecs += "\t\t}\n"
            #
            # Store Endpoint Cluster...
            epc[ep] = ecs
        #
        # Create ASN Clusters (i.e. DOT subgraph and nodes)
        s += "\n\t### ASN Clusters ###\n"
        cipall = []			# Array of IPs consumed by all ASN Cluster
        cepipall = []			# Array of IP Endpoints (Targets) consumed by all ASN Cluster
        for asn in self._asns:
            cipcur = []
            s += '\tsubgraph cluster_{asn:d} {{\n'.format(asn=asn)
            s += '\t\ttooltip="AS: {asn:d} - [{asnd:s}]";\n'.format(asn=asn, asnd=self._asds[asn])
            col = next(backcolorlist)
            s += '\t\tcolor="#{s0:s}{s1:s}{s2:s}";\n'.format(s0=col[0], s1=col[1], s2=col[2])
            #
            # Fill in ASN Cluster the associated generated color using an 11.7% alpha channel value (30/256)...
            s += '\t\tfillcolor="#{s0:s}{s1:s}{s2:s}30";\n'.format(s0=col[0], s1=col[1], s2=col[2])
            s += '\t\tstyle="filled,rounded";\n'
            s += '\t\tnode [color="#{s0:s}{s1:s}{s2:s}",gradientangle=270,fillcolor="white:#{s0:s}{s1:s}{s2:s}",style="filled"];\n'.format(s0=col[0], s1=col[1], s2=col[2])
            s += '\t\tfontsize=10;\n'
            s += '\t\tfontname="Sans-Serif";\n'
            s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B><FONT POINT-SIZE="11">AS: {asn:d}</FONT></B></TD></TR><TR><TD>[{des:s}]</TD></TR></TABLE>>;\n'.format(asn=asn, des=html.escape(self._asds[asn]))
            s += '\t\tlabelloc="t";\n'
            s += '\t\tpenwidth=3;\n'
            for ip in self._asns[asn]:
                #
                # Only add IP if not an Endpoint Target...
                if not ip in uepipo:
                    #
                    # Spin thru all traces and only Add IP if not an ICMP Destination Unreachable node...
                    for tr in range(0, self._ntraces):
                        for rtk in self._rt[tr]:
                            trace = self._rt[tr][rtk]
                            k = trace.keys()
                            for n in range(min(k), (max(k) + 1)):
                                #
                                # Check for not already added...
                                if not ip in cipall:
                                    #
                                    # Add IP Hop - found in trace and not an ICMP Destination Unreachable node...
                                    if '"{ip:s}"'.format(ip=ip) == trace[n]:
                                        s += '\t\t"{ip:s}" [tooltip="Hop Host: {ip:s}"];\n'.format(ip=ip)
                                        cipall.append(ip)
                    #
                    # Special check for ICMP Destination Unreachable nodes...
                    if ip in self._ports:
                        for p in self._ports[ip]:
                            if p.find('ICMP dest-unreach') >= 0:
                                #
                                # Check for not already added...
                                uip = '{uip:s} 3/icmp'.format(uip=ip)
                                if uip not in cipall:
                                    s += '\t\t"{uip:s}";\n'.format(uip=uip)
                                    cipall.append(uip)
                else:
                    cipcur.append(ip)   # Current list of Endpoints consumed by this ASN Cluster
                    cepipall.append(ip) # Accumulated list of Endpoints consumed by all ASN Clusters
            #
            # Add Endpoint Cluster(s) if part of this ASN Cluster (Nested Clusters)...
            if len(cipcur) > 0:
                for ip in cipcur:
                    for e in epc:       # Loop thru each Endpoint Target Clusters
                        h = e
                        f = e.find(' ') # Strip off 'port/proto'
                        if f >= 0:
                            h = e[0:f]
                        if h == ip:
                            s += epc[e]
            s += "\t}\n"
        #
        # Add any Endpoint Target Clusters not consumed by an ASN Cluster (Stand-alone Cluster)
        # and not the same as the host running the mtr session...
        for ip in epc:
            h = ip
            f = h.find(' ')		# Strip off 'port/proto'
            if f >= 0:
                h = ip[0:f]
            if not h in cepipall:
                for k, v in bpip.items():   # Check for target = host running the mtr session - Try to Add
                    if k != h:		    # this Endpoint target to the Probe Target Cluster below.
                        s += epc[ip]	    # Finally add the Endpoint Cluster if Stand-alone and
                                            # not running the mtr session.
        #
        # Probe Target Cluster...
        s += "\n\t### Probe Target Cluster ###\n"
        s += '\tsubgraph cluster_probe_Title {\n'
        p = ''
        for k, v in bpip.items():
            p += ' {ip:s}'.format(ip=k)
        s += '\t\ttooltip="Multi-Traceroute (MTR) Probe: {ip:s}";\n'.format(ip=p)
        s += '\t\tcolor="darkorange";\n'
        s += '\t\tgradientangle=270;\n'
        s += '\t\tfillcolor="white:#a0a0a0";\n'
        s += '\t\tstyle="filled,rounded";\n'
        s += '\t\tpenwidth=3;\n'
        s += '\t\tfontsize=11;\n'
        s += '\t\tfontname="Sans-Serif";\n'
        #
        # Format Label including trace targets...
        tstr = ''
        for t in self._target:
            tstr += '<TR><TD ALIGN="center"><FONT POINT-SIZE="9">Target: {t:s} ('.format(t=t)
            #
            # Append resolve IP Addresses...
            l = len(self._host2ip[t])
            c = 0
            for ip in self._host2ip[t]:
                tstr += '{ip:s} &rarr; '.format(ip=ip)
                #
                # Append all associated Target IDs...
                ti = []
                for d in self._tlblid:		# Spin thru Target IDs
                    for k, v in d.items():      # Get access to Target ID (v[0])
                        if k == ip:
                            ti.append(v[0])
                lt = len(ti)
                ct = 0
                for i in ti:
                    tstr += '{i:s}'.format(i=i)
                    ct += 1
                    if ct < lt:
                        tstr += ', '
                c += 1
                if c < l:
                    tstr += ', '
            tstr += ')</FONT></TD></TR>'
        s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD ALIGN="center"><B>{s0:s}</B></TD></TR>'.format(s0=html.escape(title))
        if timestamp != "":
            s += '<TR><TD ALIGN="center"><FONT POINT-SIZE="9">{s0:s}</FONT></TD></TR>'.format(s0=timestamp)
        s += '{s0:s}</TABLE>>;\n'.format(s0=tstr)
        s += '\t\tlabelloc="t";\n'
        for k, v in bpip.items():
            s += '\t\t"{ip:s}";\n'.format(ip=k)
        #
        # Add in any Endpoint target that is the same as the host running the mtr session...
        for ip in epc:
            h = ip
            f = h.find(' ')		# Strip off 'port/proto'
            if f >= 0:
                h = ip[0:f]
            for k, v in bpip.items():   # Check for target = host running the mtr session - Try to Add
                if k == h:		# this Endpoint target to the Probe Target Cluster.
                    s += epc[ip]
        s += "\t}\n"
        #
        # Default Gateway Cluster...
        s += "\n\t### Default Gateway Cluster ###\n"
        if self._gw != '':
            if self._gw in self._ips:
                if not self._gw in self._exptrg:
                    s += '\tsubgraph cluster_default_gateway {\n'
                    s += '\t\ttooltip="Default Gateway Host: {gw:s}";\n'.format(gw=self._gw)
                    s += '\t\tcolor="goldenrod";\n'
                    s += '\t\tgradientangle=270;\n'
                    s += '\t\tfillcolor="white:#b8860b30";\n'
                    s += '\t\tstyle="filled,rounded";\n'
                    s += '\t\tpenwidth=3;\n'
                    s += '\t\tfontsize=11;\n'
                    s += '\t\tfontname="Sans-Serif";\n'
                    s += '\t\tlabel=<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" ALIGN="center"><TR><TD><B><FONT POINT-SIZE="9">Default Gateway</FONT></B></TD></TR></TABLE>>;\n'
                    s += '\t\t"{gw:s}" [shape="diamond",fontname="Sans-Serif",fontsize=11,color="black",gradientangle=270,fillcolor="white:goldenrod",style="rounded,filled",tooltip="Default Gateway Host: {gw:s}"];\n'.format(gw=self._gw)
                    s += "\t}\n"
        #
        # Build Begin Point strings...
        # Ex bps = '192.168.43.48" [shape="record",color="black",gradientangle=270,fillcolor="white:darkorange",style="filled",'
        #        + 'label="192.168.43.48\nProbe|{http|{<BT1>T1|<BT3>T3}}|{https:{<BT2>T4|<BT3>T4}}"];'
        s += "\n\t### Probe Begin Traces ###\n"
        for k, v in bpip.items():
            tr = ''
            for sv in v:
                if self._netprotocol == 'ICMP':
                    if sv[1].find('ICMP') >= 0:
                        ps = '{p:s} echo-request'.format(p=sv[1])
                    else:
                        ps = 'ICMP({p:s}) echo-request'.format(p=sv[1])
                else:
                    ps = '{pr:s}: {p:s}'.format(pr=self._netprotocol, p=sv[1])
                if tr == '':
                    tr += '{{{ps:s}|{{{t:s}}}}}'.format(ps=ps, t=sv[0])
                else:
                    tr += '|{{{ps:s}|{{{t:s}}}}}'.format(ps=ps, t=sv[0])
            bps1 = '\t"{ip:s}" [shape="record",color="black",gradientangle=270,fillcolor="white:darkorange",style="filled,rounded",'.format(ip=k)
            if self._iface != '':
                bps2 = 'label="Probe: {ip:s}\\nNetwork Interface: {ifc:s}|{tr:s}",tooltip="Begin Host Probe: {ip:s}"];\n'.format(ip=k, ifc=self._iface, tr=tr)
            else:
                bps2 = 'label="Probe: {ip:s}|{tr:s}",tooltip="Begin Host Probe: {ip:s}"];\n'.format(ip=k, tr=tr)
            s += bps1 + bps2
        #
        s += "\n\t### Target Endpoints ###\n"
        #
        # Combine Trace Target Endpoints...
        #
        #                   k0       k1   k2       v0   v1   v2           k0     k1     k2       v0   v1   v2
        # Ex: ep = {('162.144.22.87',80,'http'): ['SA','T1','T3'], ('10.14.22.8',443,'https'): ['SA','T2','T4']}
        ep = {}				# ep -> A single services label for a given IP
        for d in self._tlblid:  # k            v0          v1               v2       v3   v4    v5      v6  v7
            for k, v in d.items():  # Ex: k:  162.144.22.87 v: ('T1', '10.222.222.10', '162.144.22.87', 6, 443, 'https', 'SA', '')
                if not v[6] == 'BH':  # Blackhole detection - do not create Endpoint
                    p = ep.get((k, v[4], v[5]))
                    if p == None:
                        ep[(k, v[4], v[5])] = [v[6], v[0]]  # Add new (TCP Flags / ICMP type / Proto) and initial trace ID
                    else:
                        ep[(k, v[4], v[5])].append(v[0])  # Append additional trace IDs
        #
        # Combine Endpoint services...
        #                   k                                 v                                 v
        #                   k                 sv0            sv1     sv2          sv0          sv1    sv2
        # Ex epip = {'206.111.13.58': [('<ET8>T8|<ET10>T10', 'https', 'SA'), ('<ET7>T7|<ET6>T6', 'http', 'SA')]}
        epip = {}			# epip -> Combined Endpoint services label for a given IP
        for k, v in ep.items():
            tr = ''
            for t in range(1, len(v)):
                if tr == '':
                    tr += '<E{ts:s}>{ts:s}'.format(ts=v[t])
                else:
                    tr += '|<E{ts:s}>{ts:s}'.format(ts=v[t])
            p = k[2]
            if p == '':			# Use port number not name if resolved
                p = str(k[1])
            else:
                p += '(' + str(k[1]) + ')'  # Use both name and port
            if k[0] in epip:
                epip[k[0]].append((tr, p, v[0]))
            else:
                epip[k[0]] = [(tr, p, v[0])]
        #
        # Build Endpoint strings...
        # Ex eps = '162.144.22.87" [shape=record,color="black",gradientangle=270,fillcolor="darkgreen:green",style=i"filled,rounded",'
        #        + 'label="162.144.22.87\nTarget|{{<ET1>T1|<ET3>T3}|https SA}|{{<ET2>T4|<ET3>T4}|http SA}"];'
        for k, v in epip.items():
            tr = ''
            for sv in v:
                if self._netprotocol == 'ICMP':
                    ps = 'ICMP(0) echo-reply'
                else:
                    ps = '{p:s} {f:s}'.format(p=sv[1], f=sv[2])
                if tr == '':
                    tr += '{{{{{t:s}}}|{ps:s}}}'.format(t=sv[0], ps=ps)
                else:
                    tr += '|{{{{{t:s}}}|{ps:s}}}'.format(t=sv[0], ps=ps)
            pre = ''
            if k in uepprb:		# Special Case: Separate Endpoint Target from Probe
                pre = '_'			# when they are the same
            eps1 = '\t"{pre:s}{ip:s}" [shape="record",color="black",gradientangle=270,fillcolor="#00ff00:#005400",style="filled,rounded",'.format(pre=pre, ip=k)
            eps2 = 'label="Resolved Target\\n{ip:s}|{tr:s}",tooltip="MTR Resolved Target: {ip:s}"];\n'.format(ip=k, tr=tr)
            s += eps1 + eps2
        #
        # Blackholes...
        #
        # ***Note: Order matters: If a hop is both a Blackhole on one trace and
        #                         a ICMP destination unreachable hop on another,
        #                         it will appear in the dot file as two nodes in
        #                         both sections. The ICMP destination unreachable
        #                         hop node will take precedents and appear only
        #                         since it is defined last.
        s += "\n\t### Blackholes ###\n"
        bhhops = []
        for d in self._tlblid:  # k             v0         v1               v2           v3    v4   v5   v6    v7
            for k, v in d.items():  # Ex: k:  162.144.22.87 v: ('T1', '10.222.222.10', '162.144.22.87', 'tcp', 5555, '', 'BH', 'I3')
                if v[6] == 'BH':  # Blackhole detection
                    #
                    # If both a target blackhole and an ICMP packet hop, then skip creating this
                    # node we be created in the 'ICMP Destination Unreachable Hops' section.
                    if v[7] != 'I3':  # ICMP destination not reached detection
                        nd = '{b:s} {prt:d}/{pro:s}'.format(b=v[2], prt=v[4], pro=v[3])
                        if self._netprotocol == 'ICMP':
                            bhh = '{b:s}<BR/><FONT POINT-SIZE="9">ICMP(0) echo-reply</FONT>'.format(b=v[2])
                        else:
                            bhh = nd
                        #
                        # If not already added...
                        if bhh not in bhhops:
                            lb = 'label=<{lh:s}<BR/><FONT POINT-SIZE="8">Failed Target</FONT>>'.format(lh=bhh)
                            s += '\t"{bh:s}" [{l:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="white:red",style="filled,rounded",tooltip="Failed MTR Resolved Target: {b:s}"];\n'.format(bh=nd, l=lb, b=v[2])
                            bhhops.append(bhh)
        #
        # ICMP Destination Unreachable Hops...
        s += "\n\t### ICMP Destination Unreachable Hops ###\n"
        for d in self._ports:
            for p in self._ports[d]:
                if d in self._exptrg:
                    #
                    # Create Node: Target same as node that returns an ICMP packet...
                    if p.find('ICMP dest-unreach') >= 0:
                        unreach = 'ICMP(3): Destination'
                        #                   0    1        2             3          4  5
                        # Ex ICMP ports: '<I3> ICMP dest-unreach port-unreachable 17 53'
                        icmpparts = p.split(' ')
                        if icmpparts[3] == 'network-unreachable':
                            unreach += '/Network'
                        elif icmpparts[3] == 'host-unreachable':
                            unreach += '/Host'
                        elif icmpparts[3] == 'protocol-unreachable':
                            unreach += '/Protocol'
                        elif icmpparts[3] == 'port-unreachable':
                            unreach += '/Port'
                        protoname = self.get_proto_name(icmpparts[4])
                        protoport = '{pr:s}/{pt:s}'.format(pr=icmpparts[5], pt=protoname)
                        lb = 'label=<{lh:s} {pp:s}<BR/><FONT POINT-SIZE="8">{u:s} Unreachable</FONT><BR/><FONT POINT-SIZE="8">Failed Target</FONT>>'.format(lh=d, pp=protoport, u=unreach)
                        s += '\t"{lh:s} {pp:s}" [{lb:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="yellow:red",style="filled,rounded",tooltip="{u:s} Unreachable, Failed Resolved Target: {lh:s} {pp:s}"];\n'.format(lb=lb, pp=protoport, lh=d, u=unreach)
                else:
                    #
                    # Create Node: Target not same as node that returns an ICMP packet...
                    if p.find('ICMP dest-unreach') >= 0:
                        unreach = 'ICMP(3): Destination'
                        if p.find('network-unreachable') >= 0:
                            unreach += '/Network'
                        elif p.find('host-unreachable') >= 0:
                            unreach += '/Host'
                        elif p.find('protocol-unreachable') >= 0:
                            unreach += '/Protocol'
                        elif p.find('port-unreachable') >= 0:
                            unreach += '/Port'
                        lb = 'label=<{lh:s} 3/icmp<BR/><FONT POINT-SIZE="8">{u:s} Unreachable</FONT>>'.format(lh=d, u=unreach)
                        s += '\t"{lh:s} 3/icmp" [{lb:s},shape="doubleoctagon",color="black",gradientangle=270,fillcolor="white:yellow",style="filled,rounded",tooltip="{u:s} Unreachable, Hop Host: {lh:s}"];\n'.format(lb=lb, lh=d, u=unreach)
        #
        # Padding check...
        if self._graphpadding:
            s += "\n\t### Nodes With Padding ###\n"
            pad = {}
            for t in range(0, self._ntraces):
                for _, rcv in self._res[t]:
                    if rcv.src not in self._ports and rcv.haslayer(conf.padding_layer):
                        p = rcv.getlayer(conf.padding_layer).load
                        if p != "\x00" * len(p):
                            pad[rcv.src] = None
            for sr in pad:
                lb = 'label=<<BR/>{r:s}<BR/><FONT POINT-SIZE="8">Padding</FONT>>'.format(r=sr)
                s += '\t"{r:s}" [{l:s},shape="box3d",color="black",gradientangle=270,fillcolor="white:red",style="filled,rounded"];\n'.format(r=sr, l=lb)
        #
        # Draw each trace (i.e., DOT edge) for each number of queries...
        s += "\n\t### Traces ###\n"
        t = 0
        for q in range(0, self._ntraces):
            for rtk in self._rt[q]:
                s += "\t### T{tr:d} -> {r:s} ###\n".format(tr=(t + 1), r=repr(rtk))
                col = next(forecolorlist)
                s += '\tedge [color="#{s0:s}{s1:s}{s2:s}"];\n'.format(s0=col[0], s1=col[1], s2=col[2])
                #
                # Probe Begin Point (i.e., Begining of a trace)...
                for k, v in self._tlblid[t].items():
                    ptr = probe = v[1]
                    s += '\t"{bp:s}":B{tr:s}:s -> '.format(bp=ptr, tr=v[0])
                #
                # In between traces (i.e., Not at the begining or end of a trace)...
                trace = self._rt[q][rtk]
                tk = trace.keys()
                ntr = trace[min(tk)]
                #
                # Skip in between traces if there are none...
                if len(trace) > 1:
                    lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=min(tk), lbp=ptr, lbn=ntr.replace('"', ''))
                    if not 'Unk' in ntr:
                        lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][min(tk)])
                    if rtt:
                        if not 'Unk' in ntr:
                            llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=min(tk), prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][min(tk)])
                            s += '{ntr:s} [label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ntr=ntr, rtt=self._rtt[t + 1][min(tk)], lb=lb, llb=llb)
                        else:
                            s += '{ntr:s} [edgetooltip="{lb:s}"];\n'.format(ntr=ntr, lb=lb)
                    else:
                        s += '{ntr:s} [edgetooltip="{lb:s}"];\n'.format(ntr=ntr, lb=lb)
                    for n in range(min(tk) + 1, max(tk)):
                        ptr = ntr
                        ntr = trace[n]
                        lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=n, lbp=ptr.replace('"', ''), lbn=ntr.replace('"', ''))
                        if not 'Unk' in ntr:
                            lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][n])
                        if rtt:
                            if not 'Unk' in ntr:
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=n, prb=probe, lbn=ntr.replace('"', ''), rtt=self._rtt[t + 1][n])
                                #
                                # Special check to see if the next and previous nodes are the same.
                                # If yes use the DOT 'xlabel' attribute to spread out labels so that they
                                # do not clash and 'forcelabel' so that they are placed.
                                if ptr == ntr:
                                    s += '\t{ptr:s} -> {ntr:s} [xlabel=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,forcelabel=True,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ptr=ptr, ntr=ntr, rtt=self._rtt[t + 1][n], lb=lb, llb=llb)
                                else:
                                    s += '\t{ptr:s} -> {ntr:s} [label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(ptr=ptr, ntr=ntr, rtt=self._rtt[t + 1][n], lb=lb, llb=llb)
                            else:
                                s += '\t{ptr:s} -> {ntr:s} [edgetooltip="{lb:s}"];\n'.format(ptr=ptr, ntr=ntr, lb=lb)
                        else:
                            s += '\t{ptr:s} -> {ntr:s} [edgetooltip="{lb:s}"];\n'.format(ptr=ptr, ntr=ntr, lb=lb)
                #
                # Enhance target Endpoint (i.e., End of a trace) replacement...
                for k, v in self._tlblid[t].items():
                    #
                    # 01-12-2020: Limit test for max index (Fix for ISP Verizon FIOS TTL manipulation with ICMP packets)
                    maxtk = max(tk)
                    if maxtk not in self._rtt[t + 1]:
                        maxtk -= 1                  # Reduce max index by one
                    ###############
                    if v[6] == 'BH':		    # Blackhole detection - do not create Enhanced Endpoint
                        #
                        # Check for Last Hop / Backhole (Failed Target) match:
                        lh = trace[max(tk)]
                        lhicmp = False
                        if lh.find(':I3') >= 0:     # Is last hop and ICMP packet from target?
                            lhicmp = True
                        f = lh.find(' ')	    # Strip off 'port/proto' ''"100.41.207.244":I3'
                        if f >= 0:
                            lh = lh[0:f]
                        f = lh.find(':')	    # Strip off 'proto:port' -> '"100.41.207.244 801/tcp"'
                        if f >= 0:
                            lh = lh[0:f]
                        lh = lh.replace('"', '')    # Remove surrounding double quotes ("")
                        if k == lh:		    # Does Hop match final Target?
                            #
                            # Backhole last hop matched target:
                            #
                            # Check to skip in between traces...
                            if len(trace) > 1:
                                s += '\t{ptr:s} -> '.format(ptr=ntr)
                            if lhicmp:
                                #
                                # Last hop is an ICMP packet from target and was reached...
                                lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=k)
                                lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=lh, rtt=self._rtt[t + 1][maxtk])
                                if rtt:
                                    llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=k, rtt=self._rtt[t + 1][maxtk])
                                    s += '"{bh:s} {bhp:d}/{bht:s}" [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], rtt=self._rtt[t + 1][maxtk], lb=lb, llb=llb)
                                else:
                                    s += '"{bh:s} {bhp:d}/{bht:s}" [style="solid",edgetooltip="{lb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], lb=lb)
                            else:
                                #
                                # Last hop is not ICMP packet from target (Fake hop - never reached - use dashed trace)...
                                lb = 'Trace: {tr:d} - Failed MTR Resolved Target: {bh:s} {bhp:d}/{bht:s}'.format(tr=(t + 1), bh=k, bhp=v[4], bht=v[3])
                                s += '"{bh:s} {bhp:d}/{bht:s}" [style="dashed",label=<<FONT POINT-SIZE="8">&nbsp; T{tr:d}</FONT>>,edgetooltip="{lb:s}",labeltooltip="{lb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], tr=(t + 1), lb=lb)
                        else:
                            #
                            # Backhole not matched (Most likely: 'ICMP (3) destination-unreached'
                            # but last hop not equal to the target:
                            #
                            # Add this last Hop (This Hop is not the Target)...
                            #
                            # Check to skip in between traces...
                            if len(trace) > 1:
                                s += '\t{ptr:s} -> '.format(ptr=ntr)
                                lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=lh)
                                lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=lh, rtt=self._rtt[t + 1][maxtk])
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=lh, rtt=self._rtt[t + 1][maxtk])
                                if rtt:
                                    s += '"{lh:s} 3/icmp" [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(lh=lh, rtt=self._rtt[t + 1][maxtk], lb=lb, llb=llb)
                                else:
                                    s += '"{lh:s} 3/icmp" [style="solid",edgetooltip="{lb:s} 3/icmp",labeltooltip="{llb:s}"];\n'.format(lh=lh, lb=lb, llb=llb)
                                #
                                # Add the Failed Target (Blackhole - Fake hop - never reached - use dashed trace)...
                                s += '\t"{lh:s} 3/icmp" -> '.format(lh=lh)
                            lb = 'Trace: {tr:d} - Failed MTR Resolved Target: {bh:s} {bhp:d}/{bht:s}'.format(tr=(t + 1), bh=k, bhp=v[4], bht=v[3])
                            s += '"{bh:s} {bhp:d}/{bht:s}" [style="dashed",label=<<FONT POINT-SIZE="8">&nbsp; T{tr:d}</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(bh=k, bhp=v[4], bht=v[3], tr=(t + 1), lb=lb, llb=lb)

                    else:			# Enhanced Target Endpoint
                        #
                        # Check to skip in between traces...
                        if len(trace) > 1:
                            s += '\t{ptr:s} -> '.format(ptr=ntr)
                        lb = 'Trace: {tr:d}:{tn:d}, {lbp:s} -> {lbn:s}'.format(tr=(t + 1), tn=max(tk), lbp=ntr.replace('"', ''), lbn=k)
                        if not 'Unk' in k:
                            lb += ' (RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms))'.format(prb=v[1], lbn=k, rtt=self._rtt[t + 1][maxtk])
                        pre = ''
                        if k in uepprb:		# Special Case: Distinguish the Endpoint Target from Probe
                            pre = '_'		# when they are the same using the underscore char: '_'.
                        if rtt:
                            if not 'Unk' in k:
                                llb = 'Trace: {tr:d}:{tn:d}, RTT: {prb:s} <-> {lbn:s} ({rtt:s}ms)'.format(tr=(t + 1), tn=max(tk), prb=v[1], lbn=k, rtt=self._rtt[t + 1][maxtk])
                                #
                                # Check to remove label clashing...
                                ntrs = ntr.replace('"', '')		# Remove surrounding double quotes ("")
                                if ntrs == k:
                                    s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",xlabel=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,forcelabel=True,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], rtt=self._rtt[t + 1][maxtk], lb=lb, llb=llb)
                                else:
                                    s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",label=<<FONT POINT-SIZE="8">&nbsp; {rtt:s}ms</FONT>>,edgetooltip="{lb:s}",labeltooltip="{llb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], rtt=self._rtt[t + 1][maxtk], lb=lb, llb=llb)
                            else:
                                s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",edgetooltip="{lb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], lb=lb)
                        else:
                            s += '"{pre:s}{ep:s}":E{tr:s}:n [style="solid",edgetooltip="{lb:s}"];\n'.format(pre=pre, ep=k, tr=v[0], lb=lb)
                t += 1				# Next trace out of total traces
        #
        # Decorate Unknown ('Unkn') Nodes...
        s += "\n\t### Decoration For Unknown (Unkn) Node Hops ###\n"
        for u in self._unks:
            s += '\t{u:s} [tooltip="Trace: {t:s}, Unknown Hop: {u2:s}",shape="egg",fontname="Sans-Serif",fontsize=9,height=0.2,width=0.2,color="black",gradientangle=270,fillcolor="white:#d8d8d8",style="filled"];\n'.format(u=u, t=self._unks[u][2], u2=u.replace('"', ''))
        #
        # Create tooltip for standalone nodes...
        s += "\n\t### Tooltip for Standalone Node Hops ###\n"
        for k, v in self._ips.items():
            if not k in cipall:
                if k != self._gw:
                    if not k in cepipall:
                        if not k in self._ports:
                            found = False
                            for tid in self._tlblid:
                                if k in tid:
                                    found = True
                                    break
                            if not found:
                                s += '\t"{ip:s}" [tooltip="Hop Host: {ip:s}"];\n'.format(ip=k)
        #
        # End the DOT Digraph...
        s += "}\n"
        #
        # Store the DOT Digraph results...
        self._graphdef = s

    #
    # Graph the Multi-Traceroute...
    def graph(self, ASres=None, padding=0, vspread=0.75, title="Multi-Traceroute Probe (MTR)", timestamp="", rtt=1, **kargs):
        """x.graph(ASres=conf.AS_resolver, other args):
        ASres = None          : Use AS default resolver => 'conf.AS_resolver'
        ASres = AS_resolver() : default whois AS resolver (riswhois.ripe.net)
        ASres = AS_resolver_cymru(): use whois.cymru.com whois database
        ASres = AS_resolver(server="whois.ra.net")

          padding: Show packets with padding as a red 3D-Box.
          vspread: Vertical separation between nodes on graph.
            title: Title text for the rendering graphic.
        timestamp: Title Time Stamp text to appear below the Title text.
              rtt: Display Round-Trip Times (msec) for Hops along trace edges.
           format: Output type (svg, ps, gif, jpg, etc.), passed to dot's "-T" option.
          figsize: w,h tuple in inches. See matplotlib documentation.
           target: Filename or redirect.
             prog: Which graphviz program to use."""
        if self._asres is None:
            self._asres = conf.AS_resolver
        if (self._graphdef is None or		# Remake the graph if there are any changes
            self._graphasres != self._asres or
                self._graphpadding != padding):
            self.make_dot_graph(ASres, padding, vspread, title, timestamp, rtt)

        return do_graph(self._graphdef, **kargs)


##################################
# Multi-Traceroute Results Class #
##################################
class MTracerouteResult(SndRcvList):
    def __init__(self, res=None, name="MTraceroute", stats=None):
        SndRcvList.__init__(self, res, name, stats)

    def show(self, ntrace):
        return self.make_table(lambda s, r:
                               (s.sprintf("Trace: " + str(ntrace) + " - %IP.dst%:{TCP:tcp%ir,TCP.dport%}{UDP:udp%ir,UDP.dport%}{ICMP:ICMP}"),
                                s.ttl,
                                r.sprintf("%-15s,IP.src% {TCP:%TCP.flags%}{ICMP:%ir,ICMP.type%}")))
    #
    # Get trace components...
    #
    #   mtrc - Instance of a MTRC class
    #
    #     nq - Traceroute query number
    def get_trace_components(self, mtrc, nq):
        ips = {}
        rt = {}
        rtt = {}
        trtt = {}
        ports = {}
        portsdone = {}
        trgttl = {}
        if len(self.res) > 0:
            #
            # Responses found...
            for s, r in self.res:
                s = s.getlayer(IP) or (conf.ipv6_enabled and s[IPv6]) or s
                r = r.getlayer(IP) or (conf.ipv6_enabled and r[IPv6]) or r
                #
                # Make sure 'r.src' is an IP Address (e.g., Case where r.src = '24.97.150.188 80/tcp')
                rs = r.src.split()
                ips[rs[0]] = None
                if TCP in s:
                    trace_id = (s.src, s.dst, 6, s.dport)
                elif UDP in s:
                    trace_id = (s.src, s.dst, 17, s.dport)
                elif ICMP in s:
                    trace_id = (s.src, s.dst, 1, s.type)
                else:
                    trace_id = (s.src, s.dst, s.proto, 0)
                trace = rt.get(trace_id, {})
                ttl = conf.ipv6_enabled and IPv6 in s and s.hlim or s.ttl
                #
                # Check for packet response types:
                if not (ICMP in r and r[ICMP].type == 11) and not (conf.ipv6_enabled and IPv6 in r and ICMPv6TimeExceeded in r):
                    #
                    # Mostly: Process target reached or ICMP Unreachable...
                    if trace_id in portsdone:
                        #
                        # Special check for out or order response packets: If previous trace was determined
                        # done, but a ttl arrives with a lower value then process this response packet as the
                        # final ttl target packet.
                        if ttl >= trgttl[trace_id]:
                            continue			# Next Send/Receive packet
                        else:
                            #
                            # Out of order response packet - process this packet as the possible
                            # final ttl target packet.
                            try:
                                if trgttl[trace_id] in trace:
                                    del trace[trgttl[trace_id]]		# Remove previous ttl target
                            except:
                                pass
                    portsdone[trace_id] = None
                    trgttl[trace_id] = ttl		# Save potential target ttl packet
                    p = ports.get(r.src, [])
                    if TCP in r:
                        p.append(r.sprintf("<T%ir,TCP.sport%> %TCP.sport% %TCP.flags%"))
                        trace[ttl] = r.sprintf('"%r,src%":T%ir,TCP.sport%')
                    elif UDP in r:
                        p.append(r.sprintf("<U%ir,UDP.sport%> %UDP.sport%"))
                        trace[ttl] = r.sprintf('"%r,src%":U%ir,UDP.sport%')
                    elif ICMP in r:
                        if r[ICMP].type == 0:
                            #
                            # Process echo-reply...
                            p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type%"))
                            trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                        else:
                            #
                            # Format Ex: '<I3> ICMP dest-unreach port-unreachable 17 53'
                            p.append(r.sprintf("<I%ir,ICMP.type%> ICMP %ICMP.type% %ICMP.code% %ICMP.proto% %r,ICMP.dport%"))
                            trace[ttl] = r.sprintf('"%r,src%":I%ir,ICMP.type%')
                    else:
                        p.append(r.sprintf("{IP:<P%ir,proto%> IP %proto%}{IPv6:<P%ir,nh%> IPv6 %nh%}"))
                        trace[ttl] = r.sprintf('"%r,src%":{IP:P%ir,proto%}{IPv6:P%ir,nh%}')
                    ports[r.src] = p
                else:
                    #
                    # Most likely a ICMP Time-Exceeded packet - Save Hop Host IP Address...
                    trace[ttl] = r.sprintf('"%r,src%"')
                rt[trace_id] = trace
                #
                # Compute the Round Trip Time for this trace packet in (msec)...
                rtrace = rtt.get(trace_id, {})
                crtt = (r.time - s.sent_time) * 1000
                rtrace[ttl] = "{crtt:.3f}".format(crtt=crtt)
                rtt[trace_id] = rtrace
        else:
            #
            # No Responses found - Most likely target same as host running the mtr session...
            #
            # Create a 'fake' failed target (Blackhole) trace using the destination host
            # found in unanswered packets...
            for p in mtrc._ures[nq]:
                ips[p.dst] = None
                trace_id = (p.src, p.dst, p.proto, p.dport)
                portsdone[trace_id] = None
                if trace_id not in rt:
                    pt = mtrc.get_proto_name(p.proto)
                    #
                    # Set trace number to zero (0) (i.e., ttl = 0) for this special case:
                    # target = mtr session host - 'fake' failed target...
                    rt[trace_id] = {1: '"{ip:s} {pr:d}/{pt:s}"'.format(ip=p.dst, pr=p.dport, pt=pt)}
        #
        # Store each trace component...
        mtrc._ips.update(ips)			# Add unique IP Addresses
        mtrc._rt.append(rt)			# Append a new Traceroute
        mtrc._ports.update(ports)		# Append completed Traceroute target and port info
        mtrc._portsdone.update(portsdone)       # Append completed Traceroute with associated target and port
        #
        # Create Round Trip Times Trace lookup dictionary...
        tcnt = mtrc._tcnt
        for rttk in rtt:
            tcnt += 1
            trtt[tcnt] = rtt[rttk]
            mtrc._rtt.update(trtt)             # Update Round Trip Times for Trace Nodes
        #
        # Update the Target Trace Label IDs and Blackhole (Failed Target) detection...
        #
        #           rtk0               rtk1   rtk2  rtk3
        # Ex: {('10.222.222.10', '10.222.222.1', 6, 9980): {1: '"10.222.222.10":T9980'}}
        for rtk in rt:
            mtrc._tcnt += 1		# Compute the total trace count
            #
            # Derive flags from ports:
            # Ex: {'63.117.14.247': ['<T80> http SA', '<T443> https SA']}
            prtflgs = ports.get(rtk[1], [])
            found = False
            for pf in prtflgs:
                if mtrc._netprotocol == 'ICMP':
                    pat = '<I0>'			  # ICMP: Create reg exp pattern
                else:
                    pat = '<[TU]{p:d}>'.format(p=rtk[3])  # TCP/UDP: Create reg exp pattern
                match = re.search(pat, pf)		  # Search for port match
                if match:
                    found = True
                    s = pf.split(' ')
                    if len(s) == 3:
                        pn = s[1]  # Service Port name / ICMP
                        fl = s[2]  # TCP Flags / ICMP Type / Proto
                    elif len(s) == 2:
                        pn = s[1]  # Service Port name
                        fl = ''
                    else:
                        pn = ''
                        fl = ''
                    break
            ic = ''		# ICMP Destination not reachable flag
            if not found:	# Set Blackhole found - (fl -> 'BH')
                #
                # Set flag for last hop is a target and ICMP destination not reached flag set...
                trace = rt[rtk]
                tk = trace.keys()
                lh = trace[max(tk)]
                f = lh.find(':I3')	      # Is hop an ICMP destination not reached node?
                if f >= 0:
                    lh = lh[0:f] 	      # Strip off 'proto:port' -> '"100.41.207.244":I3'
                    lh = lh.replace('"', '')  # Remove surrounding double quotes ("")
                    if lh in mtrc._exptrg:    # Is last hop a target?
                        ic = 'I3'
                pn = ''
                fl = 'BH'
            #
            # Update the Target Trace Label ID:
            # Ex: {'63.117.14.247': ('T2', '10.222.222.10', '162.144.22.87', 6, 443, 'https', 'SA', '')}
            pt = mtrc.get_proto_name(rtk[2])
            tlid = {rtk[1]: ('T' + str(mtrc._tcnt), rtk[0], rtk[1], pt, rtk[3], pn, fl, ic)}
            mtrc._tlblid.append(tlid)


####################
# Multi-Traceroute #
####################
@conf.commands.register
def mtr(target, dport=80, minttl=1, maxttl=30, stype="Random", srcport=50000, iface=None, l4=None, filter=None, timeout=2, verbose=None, gw=None, netproto="TCP", nquery=1, ptype=None, payload=b'', privaddr=0, rasn=1, **kargs):
    """A Multi-Traceroute (mtr) command:
         mtr(target, [maxttl=30,] [dport=80,] [sport=80,] [minttl=1,] [maxttl=1,] [iface=None]
             [l4=None,] [filter=None,] [nquery=1,] [privaddr=0,] [rasn=1,] [verbose=conf.verb])

              stype: Source Port Type: "Random" or "Increment".
            srcport: Source Port. Default: 50000.
                 gw: IPv4 Address of the Default Gateway.
           netproto: Network Protocol (One of: "TCP", "UDP" or "ICMP").
             nquery: Number of Traceroute queries to perform.
              ptype: Payload Type: "Disable", "RandStr", "RandStrTerm" or "Custom".
            payload: A byte object for each packet payload (e.g., b'\x01A\x0f\xff\x00') for ptype: 'Custom'.
           privaddr: 0 - Default: Normal display of all resolved AS numbers.
                     1 - Do not show an associated AS Number bound box (cluster) on graph for a private IPv4 Address.
               rasn: 0 - Do not resolve AS Numbers - No graph clustering.
                     1 - Default: Resolve all AS numbers.
             retry: If positive, how many times to resend unanswered packets
                    if negative, how many times to retry when no more packets
                    are answered.
           timeout: How much time to wait after the last packet has been sent."""
    #
    # Initialize vars...
    trace = []			# Individual trace array
    #
    # Range check number of query traces
    if nquery < 1:
        nquery = 1
    #
    # Create instance of an MTR class...
    mtrc = MTR(nquery=nquery, target=target)
    #
    # Default to network protocol: "TCP" if not found in list...
    plist = ["TCP", "UDP", "ICMP"]
    netproto = netproto.upper()
    if netproto not in plist:
        netproto = "TCP"
    mtrc._netprotocol = netproto
    #
    # Default to source type: "Random" if not found in list...
    slist = ["Random", "Increment"]
    stype = stype.title()
    if stype not in slist:
        stype = "Random"
    if stype == "Random":
        sport = RandShort()  # Random
    elif stype == "Increment":
        if srcport != None:
            sport = IncrementalValue(start=(srcport - 1), step=1, restart=65535)  # Increment
    #
    # Default to payload type to it's default network protocol value if not found in list...
    pllist = ["Disabled", "RandStr", "RandStrTerm", "Custom"]
    if ptype is None or (not ptype in pllist):
        if netproto == "ICMP":
            ptype = "RandStr"	   # ICMP: A random string payload to fill out the minimum packet size
        elif netproto == "UDP":
            ptype = "RandStrTerm"  # UDP: A random string terminated payload to fill out the minimum packet size
        elif netproto == "TCP":
            ptype = "Disabled"	   # TCP: Disabled -> The minimum packet size satisfied - no payload required
    #
    # Set trace interface...
    if not iface is None:
        mtrc._iface = iface
    else:
        mtrc._iface = conf.iface
    #
    # Set Default Gateway...
    if not gw is None:
        mtrc._gw = gw
    #
    # Set default verbosity if no override...
    if verbose is None:
        verbose = conf.verb
    #
    # Only consider ICMP error packets and TCP packets with at
    # least the ACK flag set *and* either the SYN or the RST flag set...
    filterundefined = False
    if filter is None:
        filterundefined = True
        filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
    #
    # Resolve and expand each target...
    ntraces = 0		# Total trace count
    exptrg = []		# Expanded targets
    for t in target:
        #
        # Use scapy's 'Net' function to expand target...
        et = [ip for ip in iter(Net(t))]
        exptrg.extend(et)
        #
        # Map Host Names to IP Addresses and store...
        if t in mtrc._host2ip:
            mtrc._host2ip[t].extend(et)
        else:
            mtrc._host2ip[t] = et
        #
        # Map IP Addresses to Host Names and store...
        for a in et:
            mtrc._ip2host[a] = t
    #
    # Store resolved and expanded targets...
    mtrc._exptrg = exptrg
    #
    # Traceroute each expanded target value...
    if l4 is None:
        #
        # Standard Layer: 3 ('TCP', 'UDP' or 'ICMP') tracing...
        for n in range(0, nquery):                              # Iterate: Number of queries
            for t in exptrg:                                    # Iterate: Number of expanded targets
                #
                # Execute a traceroute based on network protocol setting...
                if netproto == "ICMP":
                    #
                    # MTR Network Protocol: 'ICMP'
                    tid = 8				        # Use a 'Type: 8 - Echo Request' packet for the trace:
                    id = 0x8888					# MTR ICMP identifier: '0x8888'
                    seq = IncrementalValue(start=(minttl - 2), step=1, restart=-10)  # Use a Sequence number in step with TTL value
                    if filterundefined:
                        #
                        # Update Filter -> Allow for ICMP echo-request (8) and ICMP echo-reply (0) packet to be processed...
                        filter = "(icmp and (icmp[0]=8 or icmp[0]=0 or icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        icmp = ICMP(type=tid, id=id, seq=seq)
                        ipicmp = ip / icmp
                        a, b = sr(ipicmp, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            #
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each ICMP packet:
                            # Length of 'IP()/ICMP()' = 28, Minimum Protocol Data Unit (PDU) is = 46 -> Therefore a
                            # payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # ICMP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        icmp = ICMP(type=tid, id=id, seq=seq)
                        raw = Raw(load=pload)
                        ipicmpraw = ip  / icmp / raw
                        a, b = sr(ipicmpraw, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                elif netproto == "UDP":
                    #
                    # MTR Network Protocol: 'UDP'
                    if filterundefined:
                        filter += " or udp"			# Update Filter -> Allow for processing UDP packets
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        udp = UDP(sport=sport, dport=dport)
                        ipudp = ip / udp
                        a, b = sr(ipudp, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            #
                            # Use a random payload string to full out a minimum size PDU of 46 bytes for each UDP packet:
                            # Length of 'IP()/UDP()' = 28, Minimum PDU is = 46 -> Therefore a payload of 18 octets is required.
                            pload = RandString(size=18)
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=17, term=b'\n')  # Random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # UDP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        udp = UDP(sport=sport, dport=dport)
                        raw = Raw(load=pload)
                        ipudpraw = ip  / udp / raw
                        a, b = sr(ipudpraw, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                else:
                    #
                    # Default MTR Network Protocol: 'TCP'
                    #
                    # Use some TCP options for the trace. Some firewalls will filter
                    # TCP/IP packets without the 'Timestamp' option set.
                    #
                    # Note: The minimum PDU size of 46 is statisfied with the use of TCP options.
                    #
                    # Use an integer encoded microsecond timestamp for the TCP option timestamp for each trace sequence.
                    uts = int(time.clock_gettime(time.CLOCK_REALTIME))
                    opts = [('MSS', 1460), ('NOP', None), ('Timestamp', (uts, 0)), ('WScale', 7)]
                    seq = RandInt()		# Use a start random TCP sequence number
                    #
                    # Check payload types:
                    if ptype == 'Disabled':
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        tcp = TCP(seq=seq, sport=sport, dport=dport, options=opts)
                        iptcp = ip  / tcp
                        a, b = sr(iptcp, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                    else:
                        if ptype == 'RandStr':
                            pload = RandString(size=32)	                 # Use a 32 byte random string
                        elif ptype == 'RandStrTerm':
                            pload = RandStringTerm(size=32, term=b'\n')  # Use a 32 byte random string terminated
                        elif ptype == 'Custom':
                            pload = payload
                        #
                        # TCP trace with payload...
                        ip = IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl))
                        tcp = TCP(seq=seq, sport=sport, dport=dport, options=opts)
                        raw = Raw(load=pload)
                        iptcpraw = ip  / tcp / raw
                        a, b = sr(iptcpraw, timeout=timeout, filter=filter, verbose=verbose, **kargs)
                #
                # Create an 'MTracerouteResult' instance for each result packets...
                trace.append(MTracerouteResult(res=a.res))
                mtrc._res.append(a)		# Store Response packets
                mtrc._ures.append(b)		# Store Unresponse packets
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    else:
        #
        # Custom Layer: 4 tracing...
        filter = "ip"
        for n in range(0, nquery):
            for t in exptrg:
                #
                # Run traceroute...
                a, b = sr(IP(dst=[t], id=RandShort(), ttl=(minttl, maxttl)) / l4,
                          timeout=timeout, filter=filter, verbose=verbose, **kargs)
                trace.append(MTracerouteResult(res=a.res))
                mtrc._res.append(a)
                mtrc._ures.append(b)
                if verbose:
                    trace[ntraces].show(ntrace=(ntraces + 1))
                    print()
                ntraces += 1
    #
    # Store total trace run count...
    mtrc._ntraces = ntraces
    #
    # Get the trace components...
    # for n in range(0, ntraces):
    for n in range(0, mtrc._ntraces):
        trace[n].get_trace_components(mtrc, n)
    #
    # Compute any Black Holes...
    mtrc.get_black_holes()
    #
    # Compute Trace Hop Ranges...
    mtrc.compute_hop_ranges()
    #
    # Resolve AS Numbers...
    if rasn:
        mtrc.get_asns(privaddr)
        #
        # Try to guess ASNs for Traceroute 'Unkown Hops'...
        mtrc.guess_unk_asns()
    #
    # Debug: Print object vars at verbose level 8...
    if verbose == 8:
        print("mtrc._target (User Target(s)):")
        print("=======================================================")
        print(mtrc._target)
        print("\nmtrc._exptrg (Resolved and Expanded Target(s)):")
        print("=======================================================")
        print(mtrc._exptrg)
        print("\nmtrc._host2ip (Target Host Name to IP Address):")
        print("=======================================================")
        print(mtrc._host2ip)
        print("\nmtrc._ip2host (Target IP Address to Host Name):")
        print("=======================================================")
        print(mtrc._ip2host)
        print("\nmtrc._res (Trace Response Packets):")
        print("=======================================================")
        print(mtrc._res)
        print("\nmtrc._ures (Trace Unresponse Packets):")
        print("=======================================================")
        print(mtrc._ures)
        print("\nmtrc._ips (Trace Unique IPv4 Addresses):")
        print("=======================================================")
        print(mtrc._ips)
        print("\nmtrc._rt (Individual Route Traces):")
        print("=======================================================")
        print(mtrc._rt)
        print("\nmtrc._rtt (Round Trip Times (msecs) for Trace Nodes):")
        print("=======================================================")
        print(mtrc._rtt)
        print("\nmtrc._hops (Traceroute Hop Ranges):")
        print("=======================================================")
        print(mtrc._hops)
        print("\nmtrc._tlblid (Target Trace Label IDs):")
        print("=======================================================")
        print(mtrc._tlblid)
        print("\nmtrc._ports (Completed Targets & Ports):")
        print("=======================================================")
        print(mtrc._ports)
        print("\nmtrc._portsdone (Completed Trace Routes & Ports):")
        print("=======================================================")
        print(mtrc._portsdone)
        print("\nconf.L3socket (Layer 3 Socket Method):")
        print("=======================================================")
        print(conf.L3socket)
        print("\nconf.AS_resolver Resolver (AS Resolver Method):")
        print("=======================================================")
        print(conf.AS_resolver)
        print("\nmtrc._asns (AS Numbers):")
        print("=======================================================")
        print(mtrc._asns)
        print("\nmtrc._asds (AS Descriptions):")
        print("=======================================================")
        print(mtrc._asds)
        print("\nmtrc._unks (Unknown Hops IP Boundary for AS Numbers):")
        print("=======================================================")
        print(mtrc._unks)
        print("\nmtrc._iface (Trace Interface):")
        print("=======================================================")
        print(mtrc._iface)
        print("\nmtrc._gw (Trace Default Gateway IPv4 Address):")
        print("=======================================================")
        print(mtrc._gw)

    return mtrc

#!/usr/bin/python3

#
# Script: mtr.py (Network Security Toolkit (NST) - Copyright: 2015, 2016, 2018, 2020)
#
# Description: Helper script to perform a scapy Multi-Traceroute (MTR) with resulting SVG visual.

import os, sys, subprocess, getopt
import binascii
import netifaces
from scapy.all import *
from mtraceroute import *

def usage():
  version = 1.30
  print('\n*** The mtraceroute.py script performs a Multi-Traceroute (MTR) using scapy - v{v:.2f} ***\n'.format(v = version))
  print('mtraceroute.py -t || --targets <Target Host List> [-r || --retry <Retry>] [--timeout <Fractional Seconds>]')
  print('             [--netproto <Network Protocol>] [--stype <Type> [--sport <Source Port>]]')
  print('             [-p || --dports <Destination Service Ports>]')
  print('             [--minttl <Min TTL>] [--maxttl <Max TTL>] [--gateway <IPv4 Address>]')
  print('             [-g || --graphic <Graphic Type>] [-s || --showpadding] [--privaddr] [--dotfile]')
  print('             [-f || --dirfile <SVG Directory File Name>] -i | --interface <Interface Name> [--l3rawsocket]')
  print('             [--ptype <Type> [--payload <Payload>]]')
  print('             [-q || --nquery <Query Trace Count>] [-w || --wrpcap <pcap Directory File Name>]')
  print('             [-a || --asnresolver <ASN Resolver>] [ --vspread <Vertical Node Separation>] [--rtt]')
  print('             [--title <Title Text>] [--ts <Title Time Stamp>] [-v || --verbose <level>] [-h || --help]\n')
  print('* Where <Target Host List> and <Destination Ports> are a comma separated string.')
  print('* Use the (--netproto) option to specify the MTR Network Protocol (Must be one of: "TCP" (Default), "UDP", or "ICMP").')
  print('* Use the (--stype) option to choose the source port type: "Random" (Default) or "Increment".')
  print('* Use the (--sport) option to specify a source port (Default: 50000) for source port type: "Increment".')
  print('  If the source port type: "--stype Increment" is used, then the source port will be increased by one (1) for')
  print('  each packet sent out during an MTR session.')
  print('* Use the (--ptype) option to choose the a packet payload type: "Disabled" (TCP Default) "RandStrTerm" (UDP Default),')
  print(' "RandStr" (ICMP Default), "ASCII" or "ASCII-Hex".')
  print("* Use the (--payload) option for a ASCII string value (e.g., \'Data1: 56\\n\') for ptype: \"ASCII\".")
  print("* Use the (--payload) option for a ASCII-Hex string value (e.g., \'01fe44fFEf\') for ptype: \"ASCII-Hex\".")
  print('  The "--payload ASCII-Hex" option must use 2 ASCII characters to represent one Hexadecimal byte: "f" => "0F" or "0f".')
  print('* To add additional TCP destination service ports for tracerouting: "80,443" (Default: "80").')
  print('* Use the (-s || --showpadding) to display packets with padding as red triangles.')
  print('* The (-a || --asnresolver) option can be: "Disabled", "All", "whois.cymru.com", "riswhois.ripe.net" or "whois.ra.net".')
  print('* Use the (--privaddr) option to disable showing an associated AS Number bound box (cluster)')
  print('  on the Multi-Traceroute graph for a private IPv4 Address.')
  print('* Use the (--timeout) option to limit the time waiting for a Hop packet response (Default: 2.0 seconds).')
  print('* Use the (-q || --nquery) count for the number of traces to perform per service target (Default: 1).')
  print('* The default graphic type is an SVG graphic: "svg".')
  print('* The default directory file name for the resulting mtr graphic: "/tmp/graph.svg".')
  print('* Use the (-f || --dirfile) option to change the resulting output directory:')
  print('  Example: "-f /var/nst/wuiout/scapy/graph.svg" - Output directory: "/var/nst/wuiout/scapy".')
  print('* The default Network Interface will be used to send out the traceroute unless the (-i || --interface) option is used.')
  print('* Use the (--gateway) option to override the detected gateway address.')
  print('* Increase the verbosity output with a level of 1 or more (Default: 0).')
  print('* Use the (--dotfile) option to dump the mtr DOT graph object to a file (.dot file) in the output directory.')
  print('* Use the (--vspread) option to set the Vertical Separation in inches between nodes (Default: 0.75in).')
  print('* Use the (--rtt) option to display Round-Trip Times (msec) on the graphic for each Hop along a Traceroute.')
  print('* Use the (--title) option to override the default Title value: "Multi-Traceroute (MTR) Probe".')
  print('* Use the (--ts) option to include the Title Time Stamp text below the Title Text.')
  print('* Include internal mtr object variables in output at verbosity level: 8.')
  print('* Include trace packet dump output at verbosity level: 9 (***Warning: A large text output may occur).\n')
  print('*** Example:')
  print('/usr/share/mtraceroute/mtr.py -t "www.google.com,www.networksecuritytoolkit.org" -r 0 --timeout 3.5 --netproto "TCP" -p "80,443" --minttl 1 --maxttl 20 -q 2 -a "All" --vspread 0.60 --rtt -v 1;\n')

def main(argv):
  targets = []
  retry = -2
  timeout = 2.0
  netprotocol = "TCP"
  srcporttype = "Random"
  srcport = 50000
  dstports = [80]
  minttl = 1
  maxttl = 20
  payloadtype = None
  payload = ""
  verboselvl = 0
  graphictype = 'svg'
  dirfilenamebase = "/tmp/graph."
  dirfilename = ""
  nic = ""
  gateway = ""
  showpadding = 0
  nquery = 1
  asnresolver = "All"
  rasn = 1
  privaddr = 0
  tmppcapfile = "/tmp/_mtr.cap"
  pcapdirfilename = ""
  nstpcapfilename = "/capture_file.cap"
  nstpcaplogname = "/capture_file.log"
  dotfile = 0
  vspread = 0.75
  title = "Multi-Traceroute (MTR) Probe"
  timestamp = ""
  rtt = 0

  try:
    opts, args = getopt.getopt(argv, "hv:t:r:p:g:sq:f:i:w:a:", ["help", "verbose=", "targets=", "retry=", "timeout=", "dports=", "minttl=", "maxttl=", "graphic=", "showpadding", "nquery=", "dirfile=", "interface=", "wrpcap=", "privaddr", "asnresolver=", "dotfile", "vspread=", "title=", "ts=", "rtt", "l3rawsocket", "netproto=", "gateway=", "stype=", "sport=", "ptype=", "payload="])
  except getopt.GetoptError:
    print('\n***ERROR*** An invalid command line argument was entered.')
    usage()
    sys.exit(1)
  for opt,arg in opts:
    if opt in ("-h", "--help"):
      usage()
      sys.exit(0)
    elif opt in ("-v", "--verbose"):
      verboselvl = int(arg)
    elif opt in ("-t", "--targets"):
      hl = arg
      targets = hl.split(',')
    elif opt in ("-r", "--retry"):
      rt = int(arg)
      retry = -rt			# Set to negative for how many times to retry when no more packets are answered
    elif opt in ("--timeout"):
      timeout = float(arg)
    elif opt in ("--netproto"):
      netprotocol = arg.upper()
    elif opt in ("--stype"):
      srcporttype = arg.title()
    elif opt in ("--sport"):
      srcport = int(arg)
      if ((srcport < 0) or (srcport >= 2**16)):
        srcport = 50000			# Set to a default value if out of range
    elif opt in ("-p", "--dports"):
      dp = arg
      dps = dp.split(',')
      dstports = [int(p) for p in dps] 	# Use a list comprehension to convert port value from string to integer
    elif opt in ("--ptype"):
      payloadtype = arg
    elif opt in ("--payload"):
      payload = arg
    elif opt in ("--minttl"):
      minttl = int(arg)
      if (minttl <= 0):
        minttl = 1
    elif opt in ("--maxttl"):
      maxttl = int(arg)
      if (maxttl <= 0):
        maxttl = 20
    elif opt in ("-g", "--graphic"):
      graphictype = arg
    elif opt in ("-s", "--showpadding"):
      showpadding = 1
    elif opt in ("--asnresolver"):
      asnresolver = arg
    elif opt in ("--privaddr"):
      privaddr = 1
    elif opt in ("-q", "--nquery"):
      nquery = int(arg)
      if (nquery < 1):
        nquery = 1
    elif opt in ("-f", "--dirfile"):
      dirfilename = arg
    elif opt in ("-i", "--interface"):
      nic = arg
    elif opt in ("--gateway"):
      gateway = arg
    elif opt in ("-w", "--wrpcap"):
      pcapdirfilename = arg
    elif opt in ("--dotfile"):
      dotfile = 1
    elif opt in ("--vspread"):
      vspread = float(arg)
    elif opt in ("--title"):
      title = arg
    elif opt in ("--ts"):
      timestamp = arg
    elif opt in ("--rtt"):
      rtt = 1
    elif opt in ("--l3rawsocket"):
      conf.L3socket = L3RawSocket
  #
  # Auto file name cration...
  if (dirfilename == ""):
    dirfilename = dirfilenamebase + graphictype
  #
  # Range check Min/Max TTl counts...
  if (minttl > maxttl):
    maxttl = minttl
  #
  # Validate the Network Protocol value...
  plist = ["TCP", "UDP", "ICMP"]
  if not netprotocol in plist:
    print('\n***ERROR*** Option: "--netproto" (Network Protocol) must be one of: "TCP", "UDP" or "ICMP".\n')
    usage()
    sys.exit(2)
  #
  # Validate the Source Port type...
  slist = ["Random", "Increment"]
  if not srcporttype in slist:
    print('\n***ERROR*** Option: "--stype" (Source Port Type) must be one of: "Random" or "Increment".\n')
    usage()
    sys.exit(2)
  #
  # Default to payload type to it's default network protocol value if not found in list...
  pllist = ["Disabled", "RandStr", "RandStrTerm", "ASCII", "ASCII-Hex"]
  if payloadtype is None or (not payloadtype in pllist):
    if (netprotocol == "ICMP"):
      payloadtype = "RandStr"		# ICMP: A random string payload to fill out the minimum packet size
    elif (netprotocol == "UDP"):
      payloadtype = "RandStrTerm"	# UDP: A random string terminated payload to fill out the minimum packet size
    elif (netprotocol == "TCP"):
      payloadtype = "Disabled"		# TCP: Disabled -> The minimum packet size satisfied - no payload required
  #
  # Create byte object for the payload...
  if (payloadtype == 'ASCII'):
    payload = bytes(payload, 'utf-8')
    payloadtype = "Custom"		# Set custom payload type for mtr
  elif (payloadtype == 'ASCII-Hex'):
    #
    # Convert ASCII-Hex to a byte object with 'binascii.unhexlify()':
    try:
      payload = binascii.unhexlify(payload)
      payloadtype = "Custom"
    except:
      print('\n***ERROR*** Option: ASCII-Hex Payload error: "Non-Hexadecimal" or "Odd-length" payload.\n', sys.exc_info()[0])
      usage()
      sys.exit(2)
  else:
    payload = b''			# Set empty byte object for non-custom payloads
  #
  # Determine the default Gateway IPv4 Address...
  #
  if (gateway == ''):
    gws = netifaces.gateways()
    defgw = gws['default'][netifaces.AF_INET]
    if (len(defgw) > 0):
      gateway = defgw[0]		# Set the default Gateway IPv4 Address 
  #
  # Check ASN resolver value...
  #
  # Set the Global config value: conf.AS_resolver to the desired ASN resolver...
  if asnresolver in ("Disabled"):
    rasn = 0					# Disable ASN resolving...
  elif asnresolver in ("All"):
    conf.AS_resolver = AS_resolver_multi()	# Use all AS resolvers...
    rasn = 1
  elif asnresolver in ("whois.cymru.com"):
    conf.AS_resolver = AS_resolver_cymru()
    rasn = 1
  elif asnresolver in ("riswhois.ripe.net"):
    conf.AS_resolver = AS_resolver_riswhois()
    rasn = 1
  elif asnresolver in ("whois.ra.net"):
    conf.AS_resolver = AS_resolver_radb()
    rasn = 1
  else:
    print('\n***ERROR*** Option (--asnresolver) must be one of: "Disabled", "All",')
    print('            "whois.cymru.com", "riswhois.ripe.net" or "whois.ra.net".\n')
    usage()
    sys.exit(2)
  #
  # Target Host list: A Manditory argument...
  if (len(targets) == 0):
    print('\n***ERROR*** A target host list (-t <Target Host List>) is required.')
    usage()
    sys.exit(2)

  if (verboselvl >= 1):
    sp = 'stype = "{t:s}", '.format(t = srcporttype)
    if (srcporttype != 'Random'):
      sp += 'srcport = {p:d}, '.format(p = srcport)
    if (nic == ''):
      print('\nmtrc = mtr({a1:s}, retry = {a2:d}, timeout = {a3:.2f}, netproto = "{a4:s}", {a5:s}dport = {a6:s}, minttl = {a7:d}, maxttl = {a8:d}, nquery = {a9:d}, privaddr = {a10:d}, rasn = {a11:d}, gw = "{a12:s}", ptype = "{a13:s}", payload = {a14:s}, verbose = {a15:d})'.format(a1 = str(targets), a2 = retry, a3 = timeout, a4 = netprotocol, a5 = sp, a6 = str(dstports), a7 = minttl, a8 = maxttl, a9 = nquery, a10 = privaddr, a11 = rasn, a12 = gateway, a13 = payloadtype, a14 = repr(payload), a15 = verboselvl))
    else: 
      print('\nmtrc = mtr({a1:s}, retry = {a2:d}, timeout = {a3:.2f}, netproto = "{a4:s}", {a5:s}dport = {a6:s}, minttl = {a7:d}, maxttl = {a8:d}, nquery = {a9:d}, privaddr = {a10:d}, rasn = {a11:d}, gw = "{a12:s}", ptype = "{a13:s}", payload = {a14:s}, iface = "{a15:s}", verbose = {a16:d})'.format(a1 = str(targets), a2 = retry, a3 = timeout, a4 = netprotocol, a5 = sp, a6 = str(dstports), a7 = minttl, a8 = maxttl, a9 = nquery, a10 = privaddr, a11 = rasn, a12 = gateway, a13 = payloadtype, a14 = repr(payload), a15 = nic, a16 = verboselvl))
  #
  # Run scapy mtr...
  try:
    if (nic == ''):
      mtrc = mtr(targets, retry = retry, timeout = timeout, netproto = netprotocol, stype = srcporttype, srcport = srcport, dport = dstports, minttl = minttl, maxttl = maxttl, nquery = nquery, privaddr = privaddr, rasn = rasn, gw = gateway, ptype = payloadtype, payload = payload, verbose = verboselvl)
    else:
      mtrc = mtr(targets, retry = retry, timeout = timeout, netproto = netprotocol, stype = srcporttype, srcport = srcport, dport = dstports, minttl = minttl, maxttl = maxttl, nquery = nquery, privaddr = privaddr, rasn = rasn, gw = gateway, ptype = payloadtype, payload = payload, iface = nic, verbose = verboselvl)
  except:
    print('\n**ERROR*** The scapy mtr (Multi-Traceroute) function failed. Use the verbose output option to help debug.')
    usage()
    sys.exit(3)

  if (verboselvl >= 1):
    tp = 0
    for ans in mtrc._res:
      tp += len(ans)
    tp *= 2
    print('\nTrace Send/Receive Packet Summary (Total: {p:d} pkts):'.format(p = tp))
    print('=======================================================')
    print(mtrc._res)
    utp = 0
    for uans in mtrc._ures:
      utp += len(uans)
    print('\nTrace Unresponse Packet Summary (Total: {p:d} pkts):'.format(p = utp))
    print('=======================================================')
    print(mtrc._ures)

  #
  # Dump packet details at verbosity level 9...
  if (verboselvl >= 9):
    for t in range(0, mtrc._nquery):
      rlen = len(mtrc._res[t])
      if (rlen > 0):
        print('\nTrace Send/Receive Packet Details:')
        print('=======================================================')
        for i in range(0, rlen):
          print('-------------------------------------------------------')
          print('Trace Sent: {x:d} - mtrc._res[{t:d}][{r:d}][0]:'.format(x = (i + 1), t = t, r = i))
          print('-------------------------------------------------------')
          mtrc._res[t][i][0].show()
          print('-------------------------------------------------------')
          print('Trace Received: {x:d} - mtrc._res[{t:d}][{r:d}][1]:'.format(x = (i + 1), t = t, r = i))
          print('-------------------------------------------------------')
          mtrc._res[t][i][1].show()
      ulen = len(mtrc._ures[t])
      if (ulen > 0):
        print('\nTrace Unresponse Packet Details:')
        print('=======================================================')
        for i in range(0, ulen):
          print('-------------------------------------------------------')
          print('Trace Sent: {x:d} - mtrc._ures[{t:d}][{u:d}]:'.format(x = (i + 1), t = t, u = i))
          print('-------------------------------------------------------')
          mtrc._ures[t][i].show()

  #
  # Create SVG Graphic...
  try:
    if (verboselvl >= 1):
      print('\nNow generating the resulting scapy mtr {gt:s} graphic: "{df:s}"'.format(gt = graphictype.upper(), df = dirfilename))
      print('\nmtrc.graph(format = "{gt:s}", target = "{tr:s}", padding = {pd:d}, vspread = {vs:.2f}, title = "{ti:s}", timestamp = "{ts:s}", rtt = {rtt:d})'.format(gt = graphictype, tr = dirfilename, pd = showpadding, vs = vspread, ti = title, ts = timestamp, rtt = rtt))
    mtrc.graph(format = graphictype, target = dirfilename, padding = showpadding, vspread = vspread, title = title, timestamp = timestamp, rtt = rtt)
  except:
    print('\n**ERROR*** scapy mtr failed to produce a {gt:s} graphic.'.format(gt = graphictype.upper()))
    usage()
    sys.exit(4)
  #
  # Check to dump the DOT Digraph to file...
  try:
    if dotfile:
      basedirfilename, basefilenameext = os.path.splitext(dirfilename)
      dotdirfile = basedirfilename + '.dot'
      if (verboselvl >= 1):
        print('\nNow dumping the scapy mtr DOT Digraph (mtrc._graphdef) to file: "{df:s}"'.format(df = dotdirfile))
      dg = open(dotdirfile, 'w')
      dg.write(mtrc._graphdef)
      dg.close()
  except:
    print('\n**ERROR*** scapy mtr failed to dump DOT file: "{df:s}"'.format(df = dotfile))
    sys.exit(5)
  #
  # Check to dump traces to a pcap file...
  try:
    if (pcapdirfilename != ''):
      #
      # Get directory and file name components...
      basedirname = os.path.dirname(pcapdirfilename)
      nstcapturefile = basedirname + nstpcapfilename
      nstcapturelog = basedirname + nstpcaplogname
      basedirfilename, basefilenameext = os.path.splitext(pcapdirfilename)
      pcaplog = basedirfilename + '.plog'
      #
      # Remove any previous capture file, log and links...
      rmfiles = [nstcapturefile, nstcapturelog, pcapdirfilename, pcaplog]
      for f in rmfiles:
        try:
          os.unlink(f)
        except OSError:
          pass
      #
      # Dump a scapy create pcap file...
      if (verboselvl >= 1):
        print('\nNow dumping and time sorting the traces to pcap file: "{pc:s}"'.format(pc = pcapdirfilename))
      pkts = []
      for ans in mtrc._res:					# Dump all completed send/received packets
        pkts += [t[0] for t in ans] + [t[1] for t in ans]
      for uans in mtrc._ures:					# Dump all unanswered packets
        pkts += [t[0] for t in uans]
      wrpcap(tmppcapfile, pkts)
      #
      # Order packets by their timestamp...
      vf = "&> /dev/null"
      if (verboselvl >= 8):
        vf = ""
        print("Time sorting pcap file: \"{rc:s}\"".format(rc = pcapdirfilename))
      results = subprocess.check_output("/usr/sbin/reordercap \"{oc:s}\" \"{rc:s}\" {vf:s};".format(oc = tmppcapfile, rc = pcapdirfilename, vf = vf), stderr=subprocess.STDOUT, shell=True)
      print("{r:s}".format(r = results.decode("utf-8")))
      if (verboselvl >= 8):
        vf = "-v"
        print("Removing temp pcap file: \"{oc:s}\"".format(oc = tmppcapfile))
      results = subprocess.check_output("/usr/bin/rm -f {vf:s} \"{oc:s}\";".format(vf = vf, oc = tmppcapfile), stderr=subprocess.STDOUT, shell=True)
      print("{r:s}".format(r = results.decode("utf-8")))
      #
      # Produce a pcap log file for Single-Tap Packet Capture...
      #
      # Get the Default IPv4 Address for Host...
      defaddr = subprocess.check_output("/usr/bin/getipaddr --default-address", shell=True)
      defaddr = defaddr.decode("utf-8")
      defaddr = defaddr.rstrip("\n")
      #
      # Get the default Interface if not provided...
      if (nic == ''):
        nic = subprocess.check_output("/usr/bin/getipaddr --default-netint", shell=True)
        nic = nic.decode("utf-8")
        nic = nic.rstrip("\n")
      pl = open(pcaplog, 'wt', encoding='utf-8')
      log = 'CAPHOST={ch:s}\n'.format(ch = defaddr)
      log += 'NETINT={ni:s}\n'.format(ni = nic)
      log += 'CAPAPPVER=mtraceroute (v:s)\n'.format(v = conf.version)
      log += 'CAPTURETERMINATION=MTR Terminated\n'
      log += 'Note: Generated from a Scapy Multi-Traceroute (MTR) session.\n'
      pl.write(log)
      pl.close()
      #
      # Create links files for NST Single-Tap capture access...
      pcapbasename = os.path.basename(pcapdirfilename)
      logbasename = os.path.basename(pcaplog)
      #
      #             s              l               s            l
      links = {pcapbasename: nstcapturefile, logbasename: nstcapturelog}
      for s,l in links.items():
        try:
          os.symlink(s, l)
          if (verboselvl >= 8):
            print("Creating symbolic link: {l:s} -> {s:s}".format(l = l, s = s))
        except:
          print('\n**ERROR*** Cannot create symbolic link: {l:s} -> {s:s}'.format(l = l, s = s))
  except:
    print('\n**ERROR*** scapy mtr failed to dump traces to pcap file: "{pc:s}"'.format(pc = pcapdirfilename))
    sys.exit(7)
  #
  # Clean exit...
  sys.exit(0)
#
# Run this script by the interpreter if not being imported...
if __name__ == "__main__":
  main(sys.argv[1:])

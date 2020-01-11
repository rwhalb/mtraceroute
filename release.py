#-----------------------------------------------------------------------------
#   Copyright (c) 2020, networksecuritytoolkit.org. All rights reserved.
#-----------------------------------------------------------------------------

import mtraceroute

name = 'mtraceroute'

version = '1.30'

description = 'A python3 library for performing an enhanced scapy Multi-Traceroute (MTR) with resulting SVG visual'

keywords = [
  'Networking', 'Systems Administration', 'Traceroute'
]

download_url = 'https://github.com/rwhalb/mtraceroute'

author = 'Ronald W. Henderson'

author_email = 'rwhalb@verizon.net'

url = 'http://www.networksecuritytoolkit.org/'

packages = [
  'mtraceroute'
]

package_data = {
  'mtraceroute': [
  ],
}

license = 'GPLv2 License'

long_description = """
A python3 library for performing an enhanced scapy Multi-Traceroute (MTR)
with resulting SVG visual.

Features include running multiple queries with each target, display of
Round Trip Time (RTT) calculations, selection of using
Network Protocols: TCP, UDP and ICMP and with enhanced scapy
SVG visual results and session packet capture output.

The library is used by the Network Security Toolkit (NST WUI)
that provides key enhancements including a GUI options interface,
an interactive MTR SVG graphic, NST IPv4 Address Tools integration,
IPv4 Address Geolocation, MTR session Packet Capture, ASN lookup,
MTR historical session selection and management,
MTR SVG graphic editing, MTR session console output access
and SVG Graphic image conversion.

See: http://wiki.networksecuritytoolkit.org/nstwiki/index.php/HowTo_Use_The_Scapy:_Multi-Traceroute_(MTR)
"""

platforms = 'OS Independent'

scripts = ['mtrrt']

classifiers = [
  'Development Status :: 5 - Production/Stable',
  'Environment :: Console',
  'Environment :: Plugins',
  'Intended Audience :: Developers',
  'Intended Audience :: Education',
  'Intended Audience :: Information Technology',
  'Intended Audience :: Science/Research',
  'Intended Audience :: Network Administrators',
  'Intended Audience :: Telecommunications Industry',
  'License :: OSI Approved :: GPLv2 License',
  'Natural Language :: English',
  'Operating System :: OS Independent',
  'Programming Language :: Python3',
  'Topic :: Education :: Testing',
  'Topic :: Internet',
  'Topic :: Internet :: Log Analysis',
  'Topic :: Software Development',
  'Topic :: Software Development :: Libraries :: Python3 Modules',
  'Topic :: System :: Networking',
  'Topic :: System :: Operating System',
  'Topic :: System :: Shells',
  'Topic :: System :: Network Administration',
  'Topic :: Utilities',
]

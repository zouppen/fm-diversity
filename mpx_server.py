#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import sys
from optparse import OptionParser
from gnuradio.eng_option import eng_option
import struct
import hmac
import hashlib
from array import array
from pprint import pprint

def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "-k", "--key", dest="key", type="string", default='kissa13',
        help="Set HMAC key [default=%default]")
    parser.add_option(
        "-p", "--port", dest="port", type="intx", default=15400,
        help="Set UDP port [default=%default]")
    parser.add_option(
        "-f", "--file", dest="filename", type="string", default=None,
        help="Write data to file [default=%default]")
    return parser

def main():
    options, _ = argument_parser().parse_args()
    little = sys.byteorder == 'little'

    # Open outfile
    if options.filename:
        f = open(options.filename, 'w')
    else:
        f = None
    
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    # Bind the socket to the port
    server_address = ('::', options.port)
    print >>sys.stderr, 'starting up on %s port %s' % server_address
    sock.bind(server_address)

    while True:
        data, address = sock.recvfrom(4096)
        hmac_theirs = data[-32:]
        hmac_ours = hmac.new(options.key, data[:-32], digestmod=hashlib.sha256).digest()
        
        if hmac.compare_digest(hmac_theirs, hmac_ours):
            print >>sys.stderr, 'Packet with invalid HMAC received from %s' % (address,)
            continue

        # HMAC is correct. TODO replay attack check, stream_id check and reorder the stream
        (stream_id, stream_index) = struct.unpack('>QQ', data[:16])
        payload = array('h',data[16:-32])
        if little:
            payload.byteswap()

        if f:
            payload.tofile(f)
        else:
            print >>sys.stderr, 'Valid %s bytes from %s' % (len(data), address)
    
if __name__ == '__main__':
    main()

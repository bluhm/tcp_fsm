#!/usr/local/bin/python2.7

import os
from addr import *
from scapy.all import *

ip=IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)

ans=sniff(iface=LOCAL_IF, timeout=20, count=1, filter=
    "ip and src %s and dst %s and tcp port %u \
    and tcp[tcpflags] & tcp-syn != 0" %
    (ip.dst, ip.src, 4711))

if len(ans) == 0:
	print "ERROR: no initial syn from remote machine received"
	exit(1)
syninit=ans[0]

print "Send SYN packet, receive SYN+ACK."
syn=TCP(sport=4711, dport=syninit.sport, seq=1, flags='S', window=(2**16)-1)
synack=sr1(ip/syn, iface=LOCAL_IF, timeout=5)

if synack is None:
	print "ERROR: no SYN+ACK from remote machine received"
	exit(1)

print "Send ACK packet, receive remote data."
ack=TCP(sport=synack.dport, dport=synack.sport, seq=2, flags='A',
    ack=synack.seq+1, window=(2**16)-1)
data=sr1(ip/ack, iface=LOCAL_IF, timeout=5)

if data is None:
	print "ERROR: no data from remote machine received"
	exit(1)

print "Cleanup the other's socket with a reset packet."
rst=TCP(sport=synack.dport, dport=synack.sport, seq=2, flags='AR',
    ack=synack.seq+1)
send(ip/rst, iface=LOCAL_IF)

exit(0)

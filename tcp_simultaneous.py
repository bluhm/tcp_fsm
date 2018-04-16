#!/usr/local/bin/python2.7

import os
from addr import *
from scapy.all import *

# from draft-gont-tcpm-tcp-seq-validation-03.txt
# 3.1.  TCP simultaneous open

#       TCP A                                                TCP B
#    REMOTE_ADDR                                         FAKE_NET_ADDR
# network stack of remote machine                 scapy script on local machine

ipB=IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)
portB=4711
seqB=300

#   1. CLOSED                                               CLOSED

ans=sniff(iface=LOCAL_IF, timeout=20, count=1, filter=
    "ip and src %s and dst %s and tcp port %u \
    and tcp[tcpflags] & tcp-syn == tcp-syn" %
    (ipB.dst, ipB.src, portB))

#   2. SYN-SENT     --> <SEQ=100><CTL=SYN>              ...

if len(ans) == 0:
	print "ERROR: no initial SYN from remote machine received"
	exit(1)
synA=ans[0]
portA=synA.sport
seqA=synA.seq

#   4.              ... <SEQ=100><CTL=SYN>              --> SYN-RECEIVED
#   3. SYN-RECEIVED <-- <SEQ=300><CTL=SYN>              <-- SYN-SENT

print "Send SYN packet, receive SYN+ACK."
synB=TCP(sport=portB, dport=portA, seq=seqB, flags='S', window=(2**16)-1)
synackA=sr1(ipB/synB, iface=LOCAL_IF, timeout=5)

#   5.              --> <SEQ=100><ACK=301><CTL=SYN,ACK> ...

if synackA is None:
	print "ERROR: no SYN+ACK from remote machine received"
	exit(1)

#   7.              ... <SEQ=100><ACK=301><CTL=SYN,ACK> -->
#   6.              <-- <SEQ=300><ACK=101><CTL=SYN,ACK> <--

print "Send SYN+ACK packet, receive RST."
synackB=TCP(sport=portB, dport=portA, seq=seqB, flags='SA', ack=seqA+1,
    window=(2**16)-1)
# XXX patch scapy to recognize a TCP reset answer
rstA=sr1(ipB/synackB, iface=LOCAL_IF, timeout=1)

# OpenBSD sends a RST packet here
#   8.              --> <SEQ=101><CTL=RST>              ...

if rstA is None:
	print "ERROR: no RST from remote machine received"
	exit(1)

#   10.             ... <SEQ=101><CTL=RST>              -->
# As this was a reset packet, acknowledge packet received at 7. instead
#   9.              <-- <SEQ=301><ACK=101><CTL=ACK>     <--

print "Send ACK packet, receive remote data."
ack=TCP(sport=portB, dport=portA, seq=seqB+1, flags='A', ack=synackA.seq+1,
    window=(2**16)-1)
data=sr1(ipB/ack, iface=LOCAL_IF, timeout=5)

if data is None:
	print "ERROR: no data from remote machine received"
	exit(1)

print "Cleanup the other's socket with a reset packet."
rstB=TCP(sport=synackA.dport, dport=synackA.sport, seq=301, flags='AR',
    ack=synackA.seq+1)
send(ipB/rstB, iface=LOCAL_IF)

exit(0)

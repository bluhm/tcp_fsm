#	$OpenBSD: Makefile,v 1.11 2017/07/07 23:15:27 bluhm Exp $

# The following ports must be installed:
#
# python-2.7          interpreted object-oriented programming language
# py-libdnet          python interface to libdnet
# scapy               powerful interactive packet manipulation in python

.if ! (make(clean) || make(cleandir) || make(obj))
# Check wether all required python packages are installed.  If some
# are missing print a warning and skip the tests, but do not fail.
PYTHON_IMPORT != python2.7 -c 'from scapy.all import *' 2>&1 || true
.endif
.if ! empty(PYTHON_IMPORT)
regress:
	@echo '${PYTHON_IMPORT}'
	@echo install python and the scapy module for additional tests
	@echo SKIPPED
.endif

# This test needs a manual setup of two machines
# Set up machines: LOCAL REMOTE
# LOCAL is the machine where this makefile is running.
# REMOTE is running OpenBSD with echo and chargen server to test PMTU
# FAKE is an non existing machine in a non existing network.
# REMOTE_SSH is the hostname to log in on the REMOTE machine.

# Configure Addresses on the machines.
# Adapt interface and addresse variables to your local setup.
#
LOCAL_IF ?=
LOCAL_MAC ?=
REMOTE_MAC ?=
REMOTE_SSH ?=

LOCAL_ADDR ?=
REMOTE_ADDR ?=
FAKE_NET ?=
FAKE_NET_ADDR ?=

LOCAL_ADDR6 ?=
REMOTE_ADDR6 ?=
FAKE_NET6 ?=
FAKE_NET_ADDR6 ?=

.if empty (LOCAL_IF) || empty (REMOTE_SSH) || \
    empty (LOCAL_MAC) || empty (REMOTE_MAC) || \
    empty (LOCAL_ADDR) || empty (LOCAL_ADDR6) || \
    empty (REMOTE_ADDR) || empty (REMOTE_ADDR6) || \
    empty (FAKE_NET) || empty (FAKE_NET6) || \
    empty (FAKE_NET_ADDR) || empty (FAKE_NET_ADDR6)
regress:
	@echo This tests needs a remote machine to operate on
	@echo LOCAL_IF REMOTE_SSH LOCAL_MAC REMOTE_MAC LOCAL_ADDR LOCAL_ADDR6
	@echo REMOTE_ADDR REMOTE_ADDR6 FAKE_NET FAKE_NET6 FAKE_NET_ADDR
	@echo FAKE_NET_ADDR6
	@echo are empty.  Fill out these variables for additional tests.
	@echo SKIPPED

.elif make (regress) || make (all)
.BEGIN: pf.conf addr.py
	@echo
	${SUDO} true
	ssh -t ${REMOTE_SSH} ${SUDO} true
.endif

# Create python include file containing the addresses.
addr.py: Makefile
	rm -f $@ $@.tmp
	echo 'LOCAL_IF = "${LOCAL_IF}"' >>$@.tmp
	echo 'LOCAL_MAC = "${LOCAL_MAC}"' >>$@.tmp
	echo 'REMOTE_MAC = "${REMOTE_MAC}"' >>$@.tmp
.for var in LOCAL REMOTE FAKE_NET
	echo '${var}_ADDR = "${${var}_ADDR}"' >>$@.tmp
	echo '${var}_ADDR6 = "${${var}_ADDR6}"' >>$@.tmp
.endfor
	echo 'FAKE_NET = "${FAKE_NET}"' >>$@.tmp
	echo 'FAKE_NET6 = "${FAKE_NET6}"' >>$@.tmp
	mv $@.tmp $@

# Set variables so that make runs with and without obj directory.
# Only do that if necessary to keep visible output short.
.if ${.CURDIR} == ${.OBJDIR}
PYTHON =	python2.7 -u ./
.else
PYTHON =	PYTHONPATH=${.OBJDIR} python2.7 -u ${.CURDIR}/
.endif

TARGETS +=	simultaneous
run-regress-simultaneous: addr.py
	@echo '\n======== $@ ========'
	ssh ${REMOTE_SSH} nc -D ${FAKE_NET_ADDR} 4711 </dev/zero &
	${SUDO} ${PYTHON}tcp_simultaneous.py

REGRESS_TARGETS =	${TARGETS:S/^/run-regress-/}

CLEANFILES +=		addr.py *.pyc *.log

.PHONY: check-setup check-setup-local check-setup-remote

# Check wether the address, route and remote setup is correct
check-setup: check-setup-local check-setup-remote

check-setup-local:
	@echo '\n======== $@ ========'
	ping -n -c 1 ${LOCAL_ADDR}  # LOCAL_ADDR
	route -n get -inet ${LOCAL_ADDR} | grep -q 'flags: .*LOCAL'  # LOCAL_ADDR
	arp -na | grep -q '^${LOCAL_ADDR} * ${LOCAL_MAC} * ${LOCAL_IF} permanent'  # LOCAL_ADDR LOCAL_MAC LOCAL_IF
	ping -n -c 1 ${REMOTE_ADDR}  # REMOTE_ADDR
	route -n get -inet ${REMOTE_ADDR} | fgrep -q 'interface: ${LOCAL_IF}'  # REMOTE_ADDR LOCAL_IF
	! ping -n -c 1 -w 1 ${FAKE_NET_ADDR}  # FAKE_NET_ADDR
	route -n get -inet ${FAKE_NET_ADDR} | grep -q 'flags: .*BLACKHOLE'  # FAKE_NET_ADDR
	route -n get -inet -net ${FAKE_NET} | grep -q 'flags: .*BLACKHOLE'  # FAKE_NET
	ping6 -n -c 1 ${LOCAL_ADDR6}  # LOCAL_ADDR6
	route -n get -inet6 ${LOCAL_ADDR6} | grep -q 'flags: .*LOCAL'  # LOCAL_ADDR6
	ndp -na | grep -q '^${LOCAL_ADDR6} * ${LOCAL_MAC} * ${LOCAL_IF} permanent'  # LOCAL_ADDR6 LOCAL_MAC LOCAL_IF
	ping6 -n -c 1 ${REMOTE_ADDR6}  # REMOTE_ADDR6
	route -n get -inet6 ${REMOTE_ADDR6} | fgrep -q 'interface: ${LOCAL_IF}'  # REMOTE_ADDR6 LOCAL_IF
	! ping -n -c 1 -w 1 ${FAKE_NET_ADDR6}  # FAKE_NET_ADDR6
	route -n get -inet6 ${FAKE_NET_ADDR6} | grep -q 'flags: .*BLACKHOLE'  # FAKE_NET_ADDR6
	route -n get -inet6 -net ${FAKE_NET6} | grep -q 'flags: .*BLACKHOLE'  # FAKE_NET6

check-setup-remote:
	@echo '\n======== $@ ========'
	ssh ${REMOTE_SSH} ping -n -c 1 ${REMOTE_ADDR}  # REMOTE_ADDR
	ssh ${REMOTE_SSH} route -n get -inet ${REMOTE_ADDR} | grep -q 'flags: .*LOCAL'  # REMOTE_ADDR
	ssh ${REMOTE_SSH} arp -na | grep -q '^${REMOTE_ADDR} * ${REMOTE_MAC} * .* permanent'  # REMOTE_ADDR REMOTE_MAC
	ssh ${REMOTE_SSH} ping -n -c 1 ${LOCAL_ADDR}  # LOCAL_ADDR
.for ip in FAKE_NET FAKE_NET_ADDR
	ssh ${REMOTE_SSH} route -n get -inet ${${ip}} | fgrep -q 'gateway: ${LOCAL_ADDR}'  # ${ip} LOCAL_ADDR
.endfor
	ssh ${REMOTE_SSH} ping6 -n -c 1 ${REMOTE_ADDR6}  # REMOTE_ADDR6
	ssh ${REMOTE_SSH} route -n get -inet6 ${REMOTE_ADDR6} | grep -q 'flags: .*LOCAL'  # REMOTE_ADDR6
	ssh ${REMOTE_SSH} ndp -na | grep -q '^${REMOTE_ADDR6} * ${REMOTE_MAC} * .* permanent'  # REMOTE_ADDR6 REMOTE_MAC
	ssh ${REMOTE_SSH} ping6 -n -c 1 ${LOCAL_ADDR6}  # LOCAL_ADDR6
.for ip in FAKE_NET6 FAKE_NET_ADDR6
	ssh ${REMOTE_SSH} route -n get -inet6 ${${ip}} | fgrep -q 'gateway: ${LOCAL_ADDR6}'  # ${ip} LOCAL_ADDR6
.endfor
.for af in inet inet6
	ssh ${REMOTE_SSH} netstat -na -f ${af} -p tcp | fgrep ' *.19 '
.endfor
	ssh ${REMOTE_SSH} netstat -na -f inet6 -p udp | fgrep ' *.7 '
	ssh ${REMOTE_SSH} ${SUDO} pfctl -sr | grep '^anchor "regress" all$$'
	ssh ${REMOTE_SSH} ${SUDO} pfctl -si | grep '^Status: Enabled '

.include <bsd.regress.mk>

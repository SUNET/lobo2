__author__ = 'leifj'

from flask import request
import socket
import struct


def get_peer_address():
    port = int(request.args.get('port'))
    ip = request.args.get('ipv6', request.args.get('ip', request.remote_addr))
    return ip.encode('ascii'), port


def pi_dict(pi):
    return {'ip': pi.get('ip', None).encode('ascii'), 'port': pi.get('port', None)}


def pi_pack_peer(pi, buf4, buf6, offset):
    family = socket.AF_INET
    fmt = "!4sH"
    alen = 6
    buf = buf4
    if ':' in pi.get('ip', None):
        family = socket.AF_INET6
        fmt = "!16sH"
        alen = 18
        buf = buf6

    struct.pack_into(fmt, buf, offset, socket.inet_pton(family, pi.get('ip', None)), int(pi.get('port', None)))
    return alen


def get_peers(rc, info_hash, numwant=0):
    peers = []
    if numwant > 0:
        ntot = rc.scard("peers|%s" % info_hash)
        nleft = min(numwant, ntot)
        seen = dict()
        nseen = 0
        # print "start ntot=%d,nleft=%d,nseen=%d,sz=%d" % (ntot, nleft, nseen, len(peers))
        while nleft > 0 and ntot > nseen:
            #print "ntot=%d,nleft=%d,nseen=%d,sz=%d" % (ntot, nleft, nseen, len(peers))
            for pid in rc.srandmember("peers|%s" % info_hash, nleft):
                if not pid in seen:
                    seen[pid] = True
                    nseen += 1
                    pi = rc.hgetall(pid)
                    if pi is not None and len(pi) > 0:
                        peers.append(pi)
                        nleft -= 1
                    else:
                        rc.srem("peers|%s" % info_hash, pid)
    else:
        for pid in rc.smembers("peers|%s" % info_hash):
            pi = rc.hgetall(pid)
            if pi is not None:
                peers.append(pi)
            else:  # probably expired
                rc.srem("peers|%s" % info_hash, pid)
    return peers


def scrape_info(rc, info_hash, interval):
    scrape_data = rc.hgetall("scrape|%s" % info_hash)
    if scrape_data is None or not len(scrape_data):
        count = 0
        downloaded = 0
        seeding = 0
        for pi in get_peers(rc, info_hash):
            print pi
            if pi.get('state', None) == 'started' or pi.get('state', None) == 'completed':
                count += 1
                if pi.get('left', None) == 0:
                    seeding += 1

                if pi.get('state', None) == 'completed':
                    downloaded += 1

        scrape_data = {'complete': seeding, 'downloaded': downloaded, 'incomplete': count - seeding}
        with rc.pipeline() as p:
            p.hmset("scrape|%s" % info_hash, scrape_data).expire("scrape|%s" % info_hash, interval).execute()

    return scrape_data
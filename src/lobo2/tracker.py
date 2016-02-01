__author__ = 'leifj'

from flask import request, abort, jsonify, Response
import socket
import struct
import time
from utils import get_from_qs, async
from urllib import unquote
from ctypes import create_string_buffer
from torrenttools import bencode
import db

INTERVAL = 30
DEFNUMWANT = 50
MAXNUMWANT = 20


def get_peer_address():
    port = int(request.args.get('port'))
    ip = request.args.get('ipv6', request.args.get('ip', request.remote_addr))
    return ip.encode('ascii'), port


def pi_dict(pi):
    return {
        'ip': pi.get('ip', None).encode('ascii'), 'port': pi.get('port', None)
    }


def pi_pack_peer_ipv6(addr, port, buf, offset):
    family = socket.AF_INET6
    fmt = "!16sH"
    struct.pack_into(fmt, buf, offset, socket.inet_pton(family, addr), port)
    return 18


def pi_pack_peer_ipv4(addr, port, buf, offset):
    family = socket.AF_INET
    fmt = "!4sH"
    struct.pack_into(fmt, buf, offset, socket.inet_pton(family, addr), port)
    return 6


def pi_ints(pi):
    for key in ['left', 'downloaded', 'uploaded']:
        if pi.get(key, None):
            pi[key] = int(pi[key])
    return(pi)


def get_peers(rc, info_hash, numwant=0):
    peers = []
    if numwant > 0:
        ntot = rc.scard("peers|%s" % info_hash)
        nleft = min(numwant, ntot)
        seen = dict()
        nseen = 0

        # print "start ntot=%d,nleft=%d,nseen=%d,sz=%d" % (ntot, nleft, nseen, len(peers))
        while nleft > 0 and ntot > nseen:
            # print "ntot=%d,nleft=%d,nseen=%d,sz=%d" % (ntot, nleft, nseen, len(peers))
            for pid in rc.srandmember("peers|%s" % info_hash, nleft):
                if pid not in seen:
                    seen[pid] = True
                    nseen += 1
                    pi = rc.hgetall(pid)
                    if pi is not None and len(pi) > 0:
                        pi = pi_ints(pi)
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


def json_scrape(rc, info_hash):
    return jsonify(scrape_info(rc, info_hash, INTERVAL))


def scrape_info(rc, info_hash, interval):
    scrape_data = rc.hgetall("scrape|%s" % info_hash)
    if scrape_data is None or not len(scrape_data):
        count = 0
        downloaded = 0
        seeding = 0
        for pi in get_peers(rc, info_hash):
            pi = pi_ints(pi)
            if pi.get('state', None) in ['started', 'completed']:
                count += 1
                if pi.get('left', None) == 0:
                    seeding += 1

                if pi.get('state', None) == 'completed':
                    downloaded += 1
        scrape_data = {
            'complete': seeding,
            'downloaded': downloaded,
            'incomplete': count - seeding
        }
        with rc.pipeline() as p:
            p.hmset(
                "scrape|%s" % info_hash, scrape_data
            ).expire("scrape|%s" % info_hash, interval).execute()

    return scrape_data


def scrape(rc):
    """
    The tracker scrape endpoint:
    https://wiki.theory.org/BitTorrentSpecification.
    """
    info_hash = get_from_qs(request.query_string, 'info_hash=')
    if info_hash is None:
        abort(400)

    info_hash = unquote(info_hash).encode('hex')

    if rc.zscore("torrents", info_hash) is None:
        abort(403)

    return jsonify(
        {'files': {info_hash: scrape_info(rc, info_hash, INTERVAL)}}
    )


@async
def _update_stats(pi, info_hash, my_pid, now):
    with db.connection().pipeline() as p:
        pi = pi_ints(pi)
        if pi.get('left', None) == 0:
            p.zadd("torrent|%s|seeders" % info_hash, my_pid, now)
            p.zrem("torrent|%s|leechers" % info_hash, my_pid)
            p.zadd("torrents|seeding", info_hash, now)
        else:
            p.zrem("torrent|%s|seeders" % info_hash, my_pid)
            p.zadd("torrent|%s|leechers" % info_hash, my_pid, now)
            p.zadd("torrents|leeching", info_hash, now)

        p.zadd("torrents|seen", info_hash, now)


def announce(rc):
    """
    The tracker announce endpoint:
    https://wiki.theory.org/BitTorrentSpecification
    """
    info_hash = get_from_qs(request.query_string, 'info_hash=')
    if info_hash is None:
        abort(400)

    info_hash = unquote(info_hash).encode('hex')

    event = request.args.get('event', None)
    if rc.zscore("torrents", info_hash) is None:
        abort(403)

    now = time.time()

    ip, port = get_peer_address()
    my_pid = "peer|%s|%s|%d" % (info_hash, ip, port)
    pi = rc.hgetall(my_pid)
    if pi is None:
        pi = dict()

    numwant = int(request.args.get('numwant', DEFNUMWANT))
    if numwant > MAXNUMWANT:
        numwant = MAXNUMWANT
    if numwant < 0:
        numwant = DEFNUMWANT

    for key in ('uploaded', 'downloaded', 'left', 'corrupt'):
        v = request.args.get(key, None)
        if v is not None:
            pi[key] = v
    pi['port'] = port
    pi['ip'] = ip
    if event is not None:
        pi['state'] = event

    _update_stats(pi, info_hash, my_pid, now)

    rc.hmset(my_pid, pi)
    rc.expire(my_pid, 2 * INTERVAL)
    if event == 'stopped':
        rc.srem("peers|%s" % info_hash, my_pid)
    else:
        rc.sadd("peers|%s" % info_hash, my_pid)

    compact = bool(request.args.get('compact', False))

    # peers = dict()
    seeding = 0
    downloaded = 0
    count = 0
    p4str = create_string_buffer(numwant * 6 + 1)
    p6str = create_string_buffer(numwant * 18 + 1)
    offset_4 = 0
    offset_6 = 0
    resp = dict()

    if not compact:
        resp['peers'] = []

    for ppi in get_peers(rc, info_hash, numwant):
        if ppi.get('state', None) in ['started', 'completed']:
            count += 1
            if ppi.get('left', None) == 0:
                seeding += 1

            if ppi.get('state', None) == 'completed':
                downloaded += 1

            if compact:
                addr = ppi.get('ip', None)
                port = ppi.get('port', None)
                if addr is not None and port is not None:
                    port = int(port)
                    if ':' in addr:
                        offset_6 += pi_pack_peer_ipv6(
                            addr, port, p6str, offset_6
                        )
                    else:
                        offset_4 += pi_pack_peer_ipv4(
                            addr, port, p4str, offset_4
                        )
            else:
                resp['peers'].append(pi_dict(ppi))
    resp['complete'] = seeding
    resp['downloaded'] = downloaded
    resp['incomplete'] = count - seeding
    resp['interval'] = INTERVAL
    print("Ruturning data: %s" % resp)
    if compact:
        if p4str.value:
            resp['peers'] = p4str.raw[:offset_4]
        if p6str.value:
            resp['peers6'] = p6str.raw[:offset_6]

    return Response(response=bencode(resp),
                    status=200,
                    mimetype="text/plain")

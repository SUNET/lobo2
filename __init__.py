import StringIO
import hashlib
import json
import traceback
from PIL import Image
import PyRSS2Gen
from babel.dates import format_datetime
from flask import Flask, Response, request, session, render_template, redirect, abort, jsonify, url_for
from flask.ext.autodoc import Autodoc
from flask.ext.negotiate import produces
from flask.ext.oauthlib.provider import OAuth2Provider
from redis import Redis
import os
import random
import string
import mimetypes
from werkzeug.contrib.atom import AtomFeed
from werkzeug.routing import BaseConverter
import auth
from torrenttools import bencode, bdecode
from ctypes import create_string_buffer
from binascii import hexlify
from urllib import unquote
from datetime import datetime
import time
from redis_session import RedisSessionInterface
from tracker import get_peers, get_peer_address, pi_dict, pi_pack_peer, scrape_info
from utils import request_wants_json, random_string, async

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config.get("SECRET")
app.session_interface = RedisSessionInterface()
docs = Autodoc(app)
oauth = OAuth2Provider(app)

mimetypes.add_type('application/x-bittorrent', '.torrent')

rc = Redis()

DEFNUMWANT = 50
MAXNUMWANT = 20
INTERVAL = 30
PAGECOUNT = 10
NLAST = 99


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter


@app.route('/docs/api')
def apidocs():
    return docs.html('docs.html', group='api')

@app.route('/docs/tracker')
def trackerdocs():
    return docs.html('docs.html', group='tracker')

@app.route("/me")
def profile():
    return render_template("profile.html")

@app.route("/scrape/<info_hash>")
@docs.doc("api")
@produces("application/json")
def json_scrape(info_hash):
    """
    Returns a json-dict with 3 integer items: completed, downloaded and incomplete representing the same information
    that is available in the BT scrape protocol.
    """
    return jsonify(scrape_info(rc, info_hash, INTERVAL))

@app.route("/dataset/new", methods=['GET', 'POST'])
@auth.requires_auth
@produces('text/html')
def _new_torrent_html():
    return new_torrent()

@app.route("/api/dataset", methods=['POST'])
@oauth.require_oauth("dataset:create")
@docs.doc("api")
@produces('application/json')
def _new_torrent_json():
    """
    Creates a new dataset by POST:ing (multipart/form-data) a form with a single argument 'torrent' containing a
    BitTorrent metadata file describing the dataset. The 'announce' item in the torrent file must point to the tracker
    in the service.
    """
    return new_torrent()


def new_torrent():
    tracker_url = "%s/announce" % app.config.get('BASE_URL')
    if request.method == 'POST':
        errors = dict()
        torrent_data = request.form.get('torrent', None)
        if torrent_data is None or not torrent_data:
            f = request.files.get('torrent', None)
            if f is not None and f:
                try:
                    torrent_enc = f.read()
                    torrent_data = bdecode(torrent_enc)
                    #print torrent_data
                    if not 'info' in torrent_data:
                        raise ValueError("No info in hash")

                    if not torrent_data.get('announce', None) == tracker_url:
                        raise ValueError("Bad tracker url: '%s'" % (torrent_data.get('announce'), tracker_url))
                    info_hash = hashlib.sha1(bencode(torrent_data['info'])).hexdigest()
                    with rc.pipeline() as p:
                        p.set(info_hash, torrent_enc)
                        p.hmset("info|%s" % info_hash, {'user': session['user'], 'info_hash': info_hash})
                        p.sadd("perm|%s" % info_hash,
                               'user:%s:w' % session['user'],
                               'user:%s:d' % session['user'],
                               'user:%s:a' % session['user'])
                        p.zadd("torrents", info_hash, 1)
                        p.zadd("torrents|seen", info_hash, time.time())
                        p.lpush("torrents|last", info_hash)
                        p.ltrim("torrents|last", 0, NLAST)
                        p.execute()
                    if request_wants_json():
                        return jsonify(info_hash)
                    else:
                        return redirect("/dataset/%s" % info_hash)
                except Exception, ex:
                    traceback.print_exc()
                    errors['torrent_error'] = "Does not appear to be a valid torrent file: %s" % ex.message

        if torrent_data is None or not torrent_data:
            errors['_error'] = "Please provide a torrent metadata file"

        if errors:
            errors.update({'tracker_url': tracker_url})
            return render_template('new_torrent.html', **errors)
    elif request.method == 'GET':
        if request_wants_json():
            abort(400)
        else:
            return render_template("new_torrent.html", tracker_url=tracker_url)
    else:
        abort(400)

@app.route("/")
@produces("text/html")
def welcome():
    return render_template("index.html")

@app.route("/about")
@produces("text/html")
def about():
    return render_template("about.html")

@app.route("/api")
def _api_redirect():
    return redirect("/docs/api", 301)

@app.route("/datasets")
def _first_torrents():
    return redirect("/datasets/0")

@app.route("/datasets/<int:start>", methods=['GET'])
@produces("text/html")
def _torrents_html(start=0):
    return torrents(start)

@app.route("/api/datasets/<int:start>", methods=['GET'])
@docs.doc("api")
@produces("application/json")
def _torrents_json(start=0):
    """
    Return a summary of COUNT (10) datasets starting from start. The summary includes basic information
    about the dataset. The info_hash parameter is the hex encoding of the dataset (torrent) id and is
    thought to be reasonably globally unique.
    """
    return torrents(start)


def torrents(start=0):
    count = request.args.get('count', PAGECOUNT)
    tsummary = []
    total = rc.zcard("torrents")
    for info_hash in rc.zrange("torrents", start, start + count):
        user = rc.hget("info|%s" % info_hash, 'user')
        tsummary.append((info_hash, user))

    if request_wants_json():
        return jsonify(tsummary)
    else:
        return render_template("torrents.html", torrents=tsummary, start=start, count=count, total=total)

@app.route('/dataset/<regex("[a-f0-9]+"):info_hash>/delete', methods=['GET'])
@auth.requires_auth
@produces("text/html")
def _del_torrent_html(info_hash):
    return del_torrent()

@app.route('/api/dataset/<regex("[a-f0-9]+"):info_hash>/delete', methods=['GET'])
@docs.doc("api")
@oauth.require_oauth("dataset:delete")
@produces("application/json")
def _del_torrent_json(info_hash):
    """
    Permanently remove the dataset identified by the info_hash parameter. Note that this does not mean that
    the data is removed as it is stored locally on all peers that provide the dataset.
    """
    return del_torrent()


def del_torrent(info_hash):
    if has_perm(info_hash, 'd'):
        try:
            if rc.exists("perm|%s" % info_hash):
                rc.delete("perm|%s" % info_hash)
            if rc.exists("info|%s" % info_hash):
                rc.delete("info|%s" % info_hash)
            if rc.exists(info_hash):
                rc.delete(info_hash)
            rc.zrem("torrents", info_hash)
        except Exception, ex:
            traceback.print_exc()
        if request_wants_json():
            return jsonify(info_hash)
        else:
            return redirect("/datasets")
    else:
        abort(401)

@app.route('/api/dataset/<regex("[a-f0-9]+"):info_hash>/permissions', methods=['GET'])
@docs.doc("api")
@oauth.require_oauth("dataset:permission:list")
@produces("application/json")
def _get_permissions_api(info_hash):
    """
    Return a list of permission for the dataset identified by info_hash. The permissions are strings on the
    form <subject type>:<subject identifier>:<permission>. Subject type is 'user' currently. For the user subject type
    the subject identifier is the username. Finally permission is either 'w' for write, 'd' for delete and 'a' for
    admin access. Write access gives right to modify a dataset - eg to add/remove tags, delete access only gives right
    to remove a dataset and admin gives right to modify dataset permissions.
    """
    return get_permissions(info_hash)

@app.route('/dataset/<regex("[a-f0-9]+"):info_hash>/permissions', methods=['GET'])
@auth.requires_auth
@produces("application/json")
def _get_permissions_internal(info_hash):
    return get_permissions(info_hash)


def get_permissions(info_hash):
    return Response(response=json.dumps([x.split(':') for x in rc.smembers("perm|%s" % info_hash)]),
                    status=200,
                    content_type="application/json")

@app.route('/api/dataset/<regex("[a-f0-9]+"):info_hash>/permission/remove/<perm>', methods=['GET'])
@docs.doc("api")
@oauth.require_oauth("dataset:permission:remove")
@produces("application/json")
def _remove_permission_api(info_hash, perm):
    """
    Remove a permission for the dataset identified by info_hash.
    """
    return remove_permission(info_hash, perm)

@app.route('/dataset/<regex("[a-f0-9]+"):info_hash>/permission/remove/<perm>', methods=['GET'])
@auth.requires_auth
@produces("application/json")
def _remove_permission_internal(info_hash, perm):
    return remove_permission(info_hash, perm)


def remove_permission(info_hash, perm):
    if not has_perm(info_hash, 'a'):
        abort(401)

    rc.srem("perm|%s" % info_hash, perm)

    return Response(response=json.dumps([x.split(':') for x in rc.smembers("perm|%s" % info_hash)]),
                    status=200,
                    content_type="application/json")

@app.route('/api/dataset/<regex("[a-f0-9]+"):info_hash>/permission/add/<perms>', methods=['GET'])
@docs.doc("api")
@oauth.require_oauth("dataset:permission:add")
@produces("application/json")
def _add_permisson_api(info_hash, perms):
    """
    Adds permissions for the dataset identified by info_hash. The perms parameter must be a
    '+'-separated list of permissions in the format described above.
    """
    return add_permission(info_hash, perms)

@app.route('/dataset/<regex("[a-f0-9]+"):info_hash>/permission/add/<perms>', methods=['GET'])
@auth.requires_auth
@produces("application/json")
def _add_permisson_internal(info_hash, perms):
    return add_permission(info_hash, perms)


def add_permission(info_hash, perms):
    if not has_perm(info_hash, 'a'):
        abort(401)

    perms = [x.encode('ascii') for x in perms.split('+')]

    rc.sadd("perm|%s" % info_hash, *perms)

    return Response(response=json.dumps([x.split(':') for x in rc.smembers("perm|%s" % info_hash)]),
                    status=200,
                    content_type="application/json")


@app.route("/api/dataset/<regex('[a-f0-9A-F]+'):info_hash>", methods=['GET'])
@docs.doc("api")
@produces("application/json")
def _torrent_info_api(info_hash):
    """
    Returns a json-representation of the dataset torrent metadata.
    """
    return torrent_info(info_hash)

@app.route("/dataset/<regex('[a-f0-9A-F]+'):info_hash>", methods=['GET'])
@produces("text/html")
def _torrent_info_internal(info_hash):
    return torrent_info(info_hash)


def torrent_info(info_hash):
    if rc.zrank("torrents", info_hash) is None:
        abort(404)

    tm = rc.hgetall("info|%s" % info_hash)
    torrent_enc = rc.get(info_hash)
    torrent_data = bdecode(torrent_enc)
    torrent_data.update(tm)
    torrent_data['creation_time'] = datetime.fromtimestamp(torrent_data.get('creation date', 0))
    if request_wants_json():
        del torrent_data['pieces']
        return jsonify(torrent_data)
    else:
        return render_template("torrent.html", **torrent_data)


@app.route('/api/dataset/<regex("[a-f0-9]+"):info_hash>.torrent', methods=['GET'])
@docs.doc("api")
def torrent(info_hash):
    """
    Return the torrent metadata file for the datase identified by info_hash.
    """
    info_hash, ext = os.path.splitext(info_hash)
    if rc.zrank("torrents", info_hash) is None:
        abort(404)

    torrent_enc = rc.get(info_hash)
    if torrent is None:
        rc.zrem("torrents", info_hash)
        abort(404)

    rc.zincrby("torrents", info_hash)
    return Response(response=torrent_enc,
                    status=200,
                    mimetype="application/x-bittorrent")

@docs.doc("tracker")
@app.route("/scrape", methods=['GET'])
def scrape():
    """
    The tracker scrape endpoint: https://wiki.theory.org/BitTorrentSpecification.
    """
    info_hash = request.args.get('info_hash', None)
    if info_hash is None:
        abort(400)

    info_hash = hexlify(unquote(info_hash.encode('utf8')))

    return jsonify({'files': {info_hash: scrape_info(rc, info_hash, INTERVAL)}})

@async
def _update_stats(pi, info_hash, my_pid, now):
    with Redis().pipeline() as p:
        if pi.get('left', None) == 0:
            p.zadd("torrent|%s|seeders" % info_hash, my_pid, now)
            p.zrem("torrent|%s|leechers" % info_hash, my_pid)
            p.zadd("torrents|seeding", info_hash, now)
        else:
            p.zrem("torrent|%s|seeders" % info_hash, my_pid)
            p.zadd("torrent|%s|leechers" % info_hash, my_pid, now)
            p.zadd("torrents|leeching", info_hash, now)

        p.zadd("torrents|seen", info_hash, now)

@docs.doc("tracker")
@app.route("/announce", methods=['GET'])
def announce():
    """
    The tracker announce endpoint: https://wiki.theory.org/BitTorrentSpecification
    """
    info_hash = request.args.get('info_hash', None)
    if info_hash is None:
        abort(400)

    info_hash = hexlify(unquote(info_hash.encode('utf8')))

    event = request.args.get('event', None)
    if rc.zrank("torrents", info_hash) is not None:
        abort(403)

    now = time.time()

    ip, port = get_peer_address()
    my_pid = "peer|%s|%s|%d" % (info_hash, ip, port)
    print my_pid
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

    compact = not bool(request.args.get('compact', True))

    peers = dict()
    seeding = 0
    downloaded = 0
    count = 0
    p4str = create_string_buffer(numwant * 6 + 1)
    p6str = create_string_buffer(numwant * 18 + 1)
    offset = 0
    resp = dict()

    if not compact:
        resp['peers'] = []

    for ppi in get_peers(rc, info_hash, numwant):
        print ppi
        if ppi.get('state', None) == 'started' or ppi.get('state', None) == 'completed':
            count += 1
            if ppi.get('left', None) == 0:
                seeding += 1

            if ppi.get('state', None) == 'completed':
                downloaded += 1

            if compact:
                offset = offset + pi_pack_peer(ppi, p4str, p6str, offset)
            else:
                resp['peers'].append(pi_dict(ppi))

    resp['complete'] = seeding
    resp['downloaded'] = downloaded
    resp['incomplete'] = count - seeding
    resp['interval'] = INTERVAL

    if compact:
        if p4str.value:
            resp['peers'] = p4str.raw[:offset]
        if p6str.value:
            resp['peers6'] = p6str.raw[:offset]

    return Response(response=bencode(resp),
                    status=200,
                    mimetype="text/plain")


## Infrastructure

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = ''.join(random.choice(string.lowercase) for i in range(50))
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.tests['authenticated'] = auth.is_authenticated


def has_perm(info_hash, perm):
    if not auth.is_authenticated(session):
        return False
    if not rc.exists("perm|%s" % info_hash):
        return False

    return rc.sismember("perm|%s" % info_hash, "user:%s:%s" % (session['user'], perm))

app.jinja_env.tests['permission'] = has_perm

@app.route("/login")
def login():
    redirect_to = request.args.get('next', "/")
    user = request.remote_user
    if app.config.get('AUTH_TEST') is not None:
        user = app.config.get('AUTH_TEST')  # test login - just for debugging

    if user is not None:
        rc.sadd("users", user)
        session['user'] = user
        return redirect(redirect_to)

    abort(401)

@app.route("/logout")
def logout():
    if 'user' in session:
        del session['user']
    return redirect("/")

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(401)
def error(e):
    return render_template("401.html"), 401

@app.errorhandler(500)
def error(e):
    return render_template("500.html"), 500

@app.template_filter("strftime")
def _format_datetime(value, fmt='medium'):
    if fmt == 'full':
        fmt = "EEEE, d. MMMM y 'at' HH:mm"
    elif fmt == 'medium':
        fmt = "EE dd.MM.y HH:mm"
    return format_datetime(value, fmt)

@app.template_filter("path_to_file")
def _path_to_file(value):
    return os.path.join(*value).decode("utf-8")

## RSS & ATOM Feeds

@app.route('/feeds/recent.rss')
def _feed_recent_rss():
    rss = PyRSS2Gen.RSS2(
        title="Recently added datasets",
        description="Recent datasets added to %s" % request.base_url,
        docs="",
        link=request.url,
        lastBuildDate=datetime.now(),
        items=[PyRSS2Gen.RSSItem(
            title=info_hash,
            link=url_for("torrent", info_hash=info_hash, _external=True),
            guid=PyRSS2Gen.Guid(url_for("torrent", info_hash=info_hash, _external=True)),
            pubDate=datetime.now()) for info_hash in set(rc.lrange("torrents|last", 0, NLAST+1))])
    return Response(rss.to_xml(encoding="UTF8"), mimetype="application/rss+xml")

@app.route('/feeds/recent.atom')
def _feed_recent_atom():
    feed = AtomFeed("Recently added datasets",
                    feed_url=request.url, url=request.url_root)

    for info_hash in rc.lrange("torrents|last", 0, NLAST+1):
        feed.add(info_hash,
                 content_type="application/x-bittorrent",
                 updated=datetime.now(),
                 url=url_for("torrent", info_hash=info_hash, _external=True),
                 published=datetime.now())

    return feed.get_response()
## OAUTH2

@app.route("/oauth/token/new", methods=['GET', 'POST'])
@auth.requires_auth
def create_token(*args, **kwargs):
    if request.method == 'GET':
        return render_template("new_token.html")

    errors = dict()
    data = dict(client_type='public')

    if not 'name' in request.form:
        errors['name_error'] = "Name is required"

    if not 'scopes' in request.form:
        errors['scopes_error'] = 'Select at least one scope'

    if errors:
        return render_template("new_token.html",errors=errors)

    client = auth.Client.from_dict(dict(name=request.form.get('name'),
                                        user_id=session['user'],
                                        client_type='public',
                                        redirect_uris='http://localhost',
                                        client_id="%s@datasets.sunet.se" % random_string(32),
                                        client_secret=random_string(32))).save()
    rc.sadd("user|%s|clients" % session['user'], client.client_id)
    token = auth.Token.from_dict(dict(client_id=client.client_id,
                                      user_id=client.user_id,
                                      token_type='bearer',
                                      personal=True,
                                      access_token=random_string(64),
                                      scopes=" ".join([x.encode('ascii') for x in request.form.getlist('scopes')]))).save()
    print "saved token %s" % repr(token)
    rc.sadd("user|%s|tokens" % session['user'], token.token_id)
    return redirect("/oauth/tokens")


@app.route('/oauth/client/new', methods=['GET', 'POST'])
@auth.requires_auth
def create_client(*args, **kwargs):
    if request.method == 'GET':
        return render_template("new_client.html")

    errors = dict()
    data = dict(client_type='public')

    if not 'name' in request.form:
        errors['name_error'] = "Name is required"

    if not 'redirect_uris' in request.form:
        errors['redirect_uri_error'] = "Redirect URI is required"

    if 'description' in request.form:
        data['description'] = request.form.get('description')

    if 'client_type' in request.form:
        data['client_type'] = request.form.get('client_type')

    f = request.files.get('file', None)
    if f is not None and f:
        try:
            img = Image.open(f, f.content_type)
            buf = StringIO.StringIO()
            img.save(buf, "PNG")
            image_b64 = buf.read().encode('base64')
            data['icon'] = image_b64
        except Exception, ex:
            traceback.print_exc()
            errors['file_error'] = "Unknown file format: %s" % ex

    if errors:
        return render_template('new_client.html', **errors)

    data.update(dict(name=request.form.get('name'),
                     user_id=session['user'],
                     redirect_uris=" ".join([x.encode('ascii') for x in request.form.getlist('request_uris')]),
                     client_id="%s@datasets.sunet.se" % random_string(32),
                     client_secret=random_string(32)))

    client = auth.Client.from_dict(data).save()
    rc.sadd("user|%s|clients" % session['user'], client.client_id)

    return redirect("/oauth/clients")

@app.route('/oauth/clients', methods=['GET'])
@auth.requires_auth
def list_client():
    clients = [auth.get_client(client_id) for client_id in rc.smembers("user|%s|clients" % session['user']) if client_id is not None]
    return render_template("clients.html", clients=clients)

@app.route('/oauth/tokens', methods=['GET'])
@auth.requires_auth
def list_tokens():
    tokens = [auth.get_token(token_id) for token_id in rc.smembers("user|%s|tokens" % session['user']) if token_id is not None]
    return render_template("tokens.html", tokens=tokens)

@app.route('/oauth/client/<client_id>/remove', methods=['GET'])
@auth.requires_auth
def remove_client(client_id):
    if client_id is None:
        abort(400)
    rc.srem("user|%s|clients" % session['user'], client_id)
    client = auth.get_client(client_id)
    if client is not None:
        client.delete()
    return redirect("/oauth/clients")

@app.route('/oauth/token/<token_id>/remove', methods=['GET'])
@auth.requires_auth
def remove_token(token_id):
    if token_id is None:
        abort(400)
    rc.srem("user|%s|tokens" % session['user'], token_id)
    token = auth.get_token(token_id)
    if token is not None:
        token.delete()
    return redirect("/oauth/tokens")

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@auth.requires_auth
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = auth.get_client(client_id)
        kwargs['client'] = client
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return None

@oauth.clientgetter
def load_client(client_id):
    return auth.get_client(client_id)

@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    return auth.load_token(access_token, refresh_token)

@oauth.tokensetter
def save_token(token, r, *args, **kwargs):
    return auth.save_token(token, r, args, kwargs)

@oauth.grantgetter
def load_grant(client_id, code):
    return auth.load_grant(client_id, code)

@oauth.grantsetter
def save_grant(client_id, code, r, *args, **kwargs):
    if not auth.is_authenticated(session):
        abort(400)
    return auth.save_grant(session['user'], client_id, code, r, args, kwargs)

if __name__ == "__main__":
    app.run()
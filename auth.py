from functools import wraps
from flask import redirect, request, session
from hashlib import sha1
from datetime import datetime, timedelta
from utils import totimestamp, AuthException
from redis import Redis

__author__ = 'leifj'


def is_authenticated(s=session):
    return 'user' in s


def requires_auth(f, login_url="/login"):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not 'user' in session:
            return redirect("%s?next=%s" % (login_url, request.url))
        return f(*args, **kwargs)
    return decorated


def _totimestamp(ts):
    if not ts or ts is None:
        return ''
    return totimestamp(ts)


def _fromtimestamp(ts):
    if ts:
        return datetime.fromtimestamp(float(ts))
    return None


def current_user():
    if 'user' in session:
        return session['user']
    if hasattr(request, 'oauth'):
        return request.oauth.user
    raise AuthException("not authenticated")

# OAUTH2 model


rc = Redis()


class Client():

    @staticmethod
    def from_dict(data):
        if not data:
            return None

        if 'default_scopes' in data:
            data['default_scopes'] = data.pop('default_scopes').split()
        if 'redirect_uris' in data:
            data['redirect_uris'] = data.pop('redirect_uris').split()
        return Client(**data)

    def __init__(self, user_id, name, client_id, client_secret, client_type='public', icon='', description='', default_scopes=[], redirect_uris=[]):
        self.user_id = user_id
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_type = client_type
        self.description = description
        self.icon = icon
        self.default_scopes = default_scopes
        self.redirect_uris = redirect_uris

    def save(self):
        rc.hmset(self.client_name, self.to_dict())
        return self

    def delete(self, delete_tokens=True):
        if delete_tokens:
            for token in self.tokens:
                token.delete(delete_client=False)

        rc.srem("user|%s|clients" % self.user_id, self.client_id)
        rc.delete("%s|tokens" % self.client_name)
        rc.delete(self.client_name)

    def to_dict(self):
        return dict(name=self.name,
                    user_id=self.user_id,
                    client_type=self.client_type,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    icon=self.icon,
                    description=self.description,
                    default_scopes=" ".join(self.default_scopes),
                    redirect_uris=" ".join(self.redirect_uris))

    @property
    def user(self):
        return self.user_id

    @property
    def client_name(self):
        return _client_name(self.client_id)

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def ntokens(self):
        return rc.scard("%s|tokens" % self.client_name)

    @property
    def tokens(self):
        for tid in rc.smembers("%s|tokens" % self.client_name):
            if tid is not None:
                yield Token.from_dict(rc.hgetall("oauth2|token|%s" % tid))


def _client_name(cid):
    return "oauth2|client|%s" % cid


def get_client(client_id):
    return Client.from_dict(rc.hgetall(_client_name(client_id)))

## GRANT


class Grant(object):  ## TODO - make sure grants are cascaded with Clients

    @staticmethod
    def from_dict(data):
        if not data:
            return None

        if 'scopes' in data:
            data['scopes'] = data.pop('scopes').split()
        if 'expires' in data:
            data['expires'] = _fromtimestamp(data.pop('expires'))
        return Grant(**data)

    def __init__(self, user_id, client_id, code, redirect_uri, expires, scopes):
        self.user_id = user_id
        self.client_id = client_id
        self.code = code
        self.redirect_uri = redirect_uri
        self.expires = expires
        self.scopes = scopes

    def to_dict(self):
        return dict(user_id=self.user_id,
                    client_id=self.client_id,
                    code=self.code,
                    redirect_uri=self.redirect_uri,
                    expires=_totimestamp(self.expires),
                    scopes=" ".join(self.scopes))

    def save(self):
        rc.hmset(self.grant_name, self.to_dict())
        return self

    def delete(self):
        rc.delete(self.grant_name)

    @property
    def user(self):
        return self.user_id

    @property
    def grant_name(self):
        return _grant_id(self.client_id, self.code)


def _grant_id(client_id, code):
    d = sha1()
    d.update(client_id)
    d.update(code)
    return "oauth2|grant|%s" % d.hexdigest()


def load_grant(client_id, code):
    return Grant.from_dict(rc.hgetall(_grant_id(client_id, code)))


def save_grant(current_user, client_id, code, req, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    gdata = dict(client_id=client_id,
                 code=code['code'],
                 redirect_uri=req.redirect_uri,
                 scopes=req.scopes,
                 user_id=current_user,
                 expires=expires)
    return Grant.from_dict(gdata).save()


class Token(object):

    @staticmethod
    def from_dict(data):
        if not data:
            return None

        if 'scopes' in data:
            data['scopes'] = data.pop('scopes').split()
        if 'expires' in data:
            data['expires'] = _fromtimestamp(data.pop('expires'))
        if 'personal' in data:
            data['personal'] = bool(data.pop('personal'))
        else:
            data['personal'] = False

        return Token(**data)

    def __init__(self, client_id, user_id, token_type='bearer', access_token='', refresh_token='', expires=None, scopes=[], personal=False):
        if expires is None:
            expires = datetime.utcnow() + timedelta(days=30)

        self.client_id = client_id
        self.user_id = user_id
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires = expires
        self.scopes = scopes
        self.personal = personal

    def to_dict(self):
        return dict(client_id=self.client_id,
                    user_id=self.user_id,
                    token_type=self.token_type,
                    access_token=self.access_token,
                    refresh_token=self.refresh_token,
                    expires=_totimestamp(self.expires),
                    scopes=" ".join(self.scopes),
                    personal=self.personal)

    def save(self):
        rc.hmset(self.token_name, self.to_dict())   # TODO: expire this!
        if not self.access_token:
            raise ValueError("tried to save a token wo an access token...")
        rc.set("oauth2|token|access|%s" % self.access_token, self.token_name)
        if self.refresh_token:
            rc.set("oauth2|token|refresh|%s" % self.refresh_token, self.token_name)
        rc.sadd("%s|tokens" % self.client.client_name, self.token_id)
        return self

    def delete(self, delete_client=True):
        if self.access_token:
            rc.delete("oauth2|token|access|%s" % self.access_token)
        if self.refresh_token:
            rc.delete("oauth2|token|refresh|%s" % self.refresh_token)
        if self.personal or delete_client:
            client = self.client
            if client is not None:
                client.delete(delete_tokens=False)
        rc.srem("user|%s|tokens" % self.user_id, self.token_id)
        rc.delete(self.token_name)

    @property
    def token_name(self):
        return "oauth2|token|%s" % _token_id(self.client_id, self.user_id)

    @property
    def token_id(self):
        return _token_id(self.client_id, self.user_id)

    @property
    def client(self):
        return get_client(self.client_id)

    @property
    def user(self):
        return self.user_id


def get_token(tid):
    return Token.from_dict(rc.hgetall("oauth2|token|%s" % tid))


def load_token(access_token=None, refresh_token=None):
    print "loading access token %s" % access_token
    if access_token is not None:
        return Token.from_dict(rc.hgetall(rc.get("oauth2|token|access|%s" % access_token)))
    if refresh_token is not None:
        return Token.from_dict(rc.hgetall(rc.get("oauth2|token|refresh|%s" % refresh_token)))


def save_token(token, req, *args, **kwargs):
    if 'expires_in' in token:
        expires_in = token.pop('expires_in')
        expires = datetime.utcnow() + timedelta(seconds=expires_in)
        token['expires'] = expires
    rc.sadd("user|%s|tokens" % token.user, token.token_id)
    return Token.from_dict(token).save()


def _token_id(client_id, user_id):
    d = sha1()
    d.update(client_id)
    d.update(user_id)
    return d.hexdigest()
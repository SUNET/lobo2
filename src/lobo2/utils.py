import random
import string
from threading import Thread

__author__ = 'leifj'

from flask import request
from datetime import datetime, timedelta


def totimestamp(dt, epoch=datetime(1970, 1, 1)):
    td = dt - epoch
    # return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6


def request_wants_json():
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def random_string(slen):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(slen)])


def async(f):
    def wrapper(*args, **kwargs):
        thr = Thread(target=f, args=args, kwargs=kwargs)
        thr.start()
    return wrapper


def get_from_qs(qs, key):
    for q in qs.split('&'):
        if q.startswith(key):
            return q[len(key):]


class AppException(Exception):

    def default_status_code(self):
        return 400

    def default_message(self):
        return "An error occured"

    def __init__(self, message=None, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = self.default_message()
        if status_code is None:
            self.status_code = self.default_status_code()
        else:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


class APIException(AppException):
    pass


class AuthException(AppException):
    def default_status_code(self):
        return 403


class PermissionDenied(AuthException):
    def default_message(self):
        return "Permission denied"

    def default_status_code(self):
        return 403



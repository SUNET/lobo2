# -*- coding: utf-8 -*-

# The contents of this file are subject to the Python Software Foundation
# License Version 2.3 (the License).  You may not copy or use this file, in
# either source code or executable form, except in compliance with the License.
# You may obtain a copy of the License at http://www.python.org/license.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

"""
Created on Thu Mar 17 11:06:27 2011

@author: lundberg@nordu.net

Torrenttools where made for Lobber to remove dependance on bigger torrent libs 
like Deluge and Bittorrent. 

Bencode and bdecode stuff is written by Petru Paler and taken from Deluge 
(1.3.1) bencode.py. Minor modifications made by Andrew Resch to replace the 
BTFailure errors with Exceptions.

Make_meta_file stuff is written by Bram Cohen and taken from Deluge (1.3.1) 
metafile.py. Modifications for use in Deluge by Andrew Resch 2008.
"""

import os
import os.path
import time
import sys
from hashlib import sha1 as sha


def decode_int(x, f):
    f += 1
    newf = x.index('e', f)
    n = int(x[f:newf])
    if x[f] == '-':
        if x[f + 1] == '0':
            raise ValueError
    elif x[f] == '0' and newf != f + 1:
        raise ValueError
    return (n, newf + 1)


def decode_string(x, f):
    colon = x.index(':', f)
    n = int(x[f:colon])
    if x[f] == '0' and colon != f + 1:
        raise ValueError
    colon += 1
    return (x[colon:colon + n], colon + n)


def decode_list(x, f):
    r, f = [], f + 1
    while x[f] != 'e':
        v, f = decode_func[x[f]](x, f)
        r.append(v)
    return (r, f + 1)


def decode_dict(x, f):
    r, f = {}, f + 1
    while x[f] != 'e':
        k, f = decode_string(x, f)
        r[k], f = decode_func[x[f]](x, f)
    return (r, f + 1)


decode_func = {}
decode_func['l'] = decode_list
decode_func['d'] = decode_dict
decode_func['i'] = decode_int
decode_func['0'] = decode_string
decode_func['1'] = decode_string
decode_func['2'] = decode_string
decode_func['3'] = decode_string
decode_func['4'] = decode_string
decode_func['5'] = decode_string
decode_func['6'] = decode_string
decode_func['7'] = decode_string
decode_func['8'] = decode_string
decode_func['9'] = decode_string


def bdecode(x):
    try:
        r, l = decode_func[x[0]](x, 0)
    except (IndexError, KeyError, ValueError):
        raise Exception("not a valid bencoded string")

    return r


from types import StringType, IntType, LongType, DictType, ListType, TupleType


class Bencached(object):
    __slots__ = ['bencoded']

    def __init__(self, s):
        self.bencoded = s


def encode_bencached(x, r):
    r.append(x.bencoded)


def encode_int(x, r):
    r.extend(('i', str(x), 'e'))


def encode_bool(x, r):
    if x:
        encode_int(1, r)
    else:
        encode_int(0, r)


def encode_string(x, r):
    r.extend((str(len(x)), ':', x))


def encode_list(x, r):
    r.append('l')
    for i in x:
        encode_func[type(i)](i, r)
    r.append('e')


def encode_dict(x, r):
    r.append('d')
    ilist = x.items()
    ilist.sort()
    for k, v in ilist:
        r.extend((str(len(k)), ':', k))
        encode_func[type(v)](v, r)
    r.append('e')


encode_func = {}
encode_func[Bencached] = encode_bencached
encode_func[IntType] = encode_int
encode_func[LongType] = encode_int
encode_func[StringType] = encode_string
encode_func[ListType] = encode_list
encode_func[TupleType] = encode_list
encode_func[DictType] = encode_dict

try:
    from types import BooleanType

    encode_func[BooleanType] = encode_bool
except ImportError:
    pass


def bencode(x):
    r = []
    encode_func[type(x)](x, r)
    return ''.join(r)


def dummy(*v):
    pass


def make_meta_file(path, url, piece_length, progress=dummy,
                   title=None, comment=None, safe=None, content_type=None,
                   target=None, webseeds=None, name=None, private=False,
                   created_by=None, trackers=None):
    data = {'creation date': int(gmtime())}
    if url:
        data['announce'] = url.strip()
    a, b = os.path.split(path)
    if not target:
        if b == '':
            f = a + '.torrent'
        else:
            f = os.path.join(a, b + '.torrent')
    else:
        f = target
    info = makeinfo(path, piece_length, progress, name, content_type, private)

    # check_info(info)
    h = file(f, 'wb')

    data['info'] = info
    if title:
        data['title'] = title.encode("utf8")
    if comment:
        data['comment'] = comment.encode("utf8")
    if safe:
        data['safe'] = safe.encode("utf8")

    httpseeds = []
    url_list = []

    if webseeds:
        for webseed in webseeds:
            if webseed.endswith(".php"):
                httpseeds.append(webseed)
            else:
                url_list.append(webseed)

    if url_list:
        data['url-list'] = url_list
    if httpseeds:
        data['httpseeds'] = httpseeds
    if created_by:
        data['created by'] = created_by.encode("utf8")

    if trackers and (len(trackers[0]) > 1 or len(trackers) > 1):
        data['announce-list'] = trackers

    data["encoding"] = "UTF-8"

    h.write(bencode(data))
    h.close()


def makeinfo(path, piece_length, progress, name=None,
             content_type=None, private=False):  # HEREDAVE. If path is directory,
    # how do we assign content type?
    def to_utf8(name):
        if isinstance(name, unicode):
            u = name
        else:
            try:
                u = decode_from_filesystem(name)
            except Exception:
                raise Exception('Could not convert file/directory name %r to '
                                'Unicode. Either the assumed filesystem '
                                'encoding "%s" is wrong or the filename contains '
                                'illegal bytes.' % (name, get_filesystem_encoding()))

        if u.translate(noncharacter_translate) != u:
            raise Exception('File/directory name "%s" contains reserved '
                            'unicode values that do not correspond to '
                            'characters.' % name)
        return u.encode('utf-8')

    path = os.path.abspath(path)
    piece_count = 0
    if os.path.isdir(path):
        subs = subfiles(path)
        subs.sort()
        pieces = []
        sh = sha()
        done = 0
        fs = []
        totalsize = 0.0
        totalhashed = 0
        for p, f in subs:
            totalsize += os.path.getsize(f)
        if totalsize >= piece_length:
            import math

            num_pieces = math.ceil(float(totalsize) / float(piece_length))
        else:
            num_pieces = 1

        for p, f in subs:
            pos = 0
            size = os.path.getsize(f)
            p2 = [to_utf8(n) for n in p]
            if content_type:
                fs.append({'length': size, 'path': p2,
                           'content_type': content_type})  # HEREDAVE. bad for batch!
            else:
                fs.append({'length': size, 'path': p2})
            h = file(f, 'rb')
            while pos < size:
                a = min(size - pos, piece_length - done)
                sh.update(h.read(a))
                done += a
                pos += a
                totalhashed += a

                if done == piece_length:
                    pieces.append(sh.digest())
                    piece_count += 1
                    done = 0
                    sh = sha()
                    progress(piece_count, num_pieces)
            h.close()
        if done > 0:
            pieces.append(sh.digest())
            progress(piece_count, num_pieces)

        if name is not None:
            assert isinstance(name, unicode)
            name = to_utf8(name)
        else:
            name = to_utf8(os.path.split(path)[1])

        return {'pieces': ''.join(pieces),
                'piece length': piece_length, 'files': fs,
                'name': name,
                'private': private}
    else:
        size = os.path.getsize(path)
        if size >= piece_length:
            num_pieces = size / piece_length
        else:
            num_pieces = 1

        pieces = []
        p = 0
        h = file(path, 'rb')
        while p < size:
            x = h.read(min(piece_length, size - p))
            pieces.append(sha(x).digest())
            piece_count += 1
            p += piece_length
            if p > size:
                p = size
            progress(piece_count, num_pieces)
        h.close()
        if content_type is not None:
            return {'pieces': ''.join(pieces),
                    'piece length': piece_length, 'length': size,
                    'name': to_utf8(os.path.split(path)[1]),
                    'content_type': content_type,
                    'private': private}
        return {'pieces': ''.join(pieces),
                'piece length': piece_length, 'length': size,
                'name': to_utf8(os.path.split(path)[1]),
                'private': private}


ignore = ['core', 'CVS', 'Thumbs.db', 'desktop.ini']


def subfiles(d):
    r = []
    stack = [([], d)]
    while stack:
        p, n = stack.pop()
        if os.path.isdir(n):
            for s in os.listdir(n):
                if s not in ignore and not s.startswith('.'):
                    stack.append((p + [s], os.path.join(n, s)))
        else:
            r.append((p, n))
    return r


noncharacter_translate = {}
for i in xrange(0xD800, 0xE000):
    noncharacter_translate[i] = ord('-')
for i in xrange(0xFDD0, 0xFDF0):
    noncharacter_translate[i] = ord('-')
for i in (0xFFFE, 0xFFFF):
    noncharacter_translate[i] = ord('-')


def gmtime():
    return time.mktime(time.gmtime())


def get_filesystem_encoding():
    return sys.getfilesystemencoding()


def decode_from_filesystem(path):
    encoding = get_filesystem_encoding()
    if encoding == None:
        assert isinstance(path, unicode), "Path should be unicode not %s" % type(path)
        decoded_path = path
    else:
        assert isinstance(path, str), "Path should be str not %s" % type(path)
        decoded_path = path.decode(encoding)

    return decoded_path
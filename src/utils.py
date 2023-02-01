# -*- coding: utf-8 -*-

import os
import time
import json
import re
import tarfile
import redis
import smtplib
import requests

try:
    from httplib import OK
except:
    from http.client import OK

try:
    from secrets import token_urlsafe
except:
    from base64 import b64encode
    from hashlib import sha256
    from random import choice, getrandbits

from math import cos, asin, sqrt
from functools import wraps
from inspect import stack
from traceback import print_exc

try:
    from cStringIO import StringIO
except ImportError:
    from io import BytesIO

from git import Repo, Git
from git.exc import GitCommandError
from multiprocessing_on_dill import Process
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import *


def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, cdata=None):
    '''Retry calling the decorated function using an exponential backoff.
    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry
    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    '''
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    print(
                        '{}, retrying in {} seconds (mtries={}): {}'.format(
                            repr(e),
                            mdelay,
                            mtries,
                            str(cdata)
                        )
                    )
                    if DEBUG: print_exc()
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry  # true decorator
    return deco_retry


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def generate_hash_key():
    try:
        return token_urlsafe(32)
    except:
        return b64encode(
            sha256(str(getrandbits(256))).digest(),
            choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])
        ).rstrip('==')


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
class dotdict(dict):
    '''dot.notation access to dictionary attributes'''
    def __getattr__(self, attr):
        return self.get(attr)
    
    __setattr__= dict.__setitem__
    __delattr__= dict.__delitem__
    
    def __getstate__(self):
        return self
        
    def __setstate__(self, state):
        self.update(state)
        self.__dict__ = self


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def map_countries():
    data = open(COUNTRY_DATA, 'rt', encoding='utf-8').read()
    countries = json.loads(data)
    d = dict()
    for country in countries:
        d[country['name']] = country['alpha-2']
    return d


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def raw_countries():
    data = open(COUNTRY_DATA, 'rt', encoding='utf-8').read()
    return json.loads(data)


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def load_blackbox_data():
    data = open(BLACKBOX_DATA, 'rt', encoding='utf-8').read()
    return json.loads(data)


@retry(Exception, cdata='method=%s()' % stack()[0][3])
def stream_tar_gz(dir=DDWRT_GIT_DIR, app=DDWRT_APP):

    def set_root(tarinfo):
        tarinfo.uid = 0
        tarinfo.gid = 0
        tarinfo.uname = 'root'
        tarinfo.gname = 'root'
        return tarinfo
    
    try:
        buffer = StringIO()
    except NameError:
        buffer = BytesIO()
    with tarfile.open('{}.tar.gz'.format(app), 'w:gz', buffer) as tar:
        tar.add(
            '{}/{}'.format(dir, app),
            arcname=app,
            filter=set_root
        )
    tar.close()
    yield buffer.getvalue()


@retry(Exception, cdata='method=%s()' % stack()[0][3])
def fetch_git_repo(dir=DDWRT_GIT_DIR, url=DDWRT_GIT_URL, tag=DDWRT_GIT_TAG):
    try:
       repo = Repo.clone_from(url, dir)
    except:
        repo = Repo(dir)

    try:
        origin = repo.remotes.origin
        origin.fetch()
        origin.pull()
    except:
        pass

    Git(dir).checkout(tag)
    return repo


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_pipe_set(cmds=list()):
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    pipe = cache.pipeline()
    for cmd in cmds:
        pipe.set(cmd['key'], cmd['value'])
        ttl = None
        if 'ttl' in cmd.keys():
            ttl = cmd['ttl']
            pipe.expire(name=cmd['key'], time=ttl)
        if DEBUG: print(
            'cache_pipe_set({}): value={} ttl={}'.format(
                cmd['key'],
                type(cmd['value']),
                ttl
            )
        )
    return pipe.execute()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_set(key=None, value=None, ttl=None):
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    result = cache.set(key, value)
    if ttl: cache.expire(name=key, time=ttl)
    if DEBUG: print(
        'cache_set({}): value={} result={} ttl={}'.format(
            key, type(value),
            result, ttl
        )
    )
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_get(key=None):
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    result = cache.get(key)
    if DEBUG: print(
        'cache_get({}): result={}'.format(
            key,
            type(result)
        )
    )
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_remove(key=None):
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    result = cache.delete(key)
    if DEBUG: print(
        'cache_remove({}): records={}'.format(
            key, result
        )
    )


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_clear(prefix='*'):
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    pipe = cache.pipeline()
    for key in cache.scan_iter('%s' % prefix):
        pipe.delete(key)
        if DEBUG: print('cache_clear({})'.format(key))
    return pipe.execute()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def cache_flush():
    if not CACHE_HOST and CACHE_PORT: return
    cache = redis.StrictRedis(host=CACHE_HOST, port=CACHE_PORT, db=0)
    return cache.flushall()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def background_smtp_send(subject=None, body=None, preamble='API alert'):
    
    def smtp_send(subject, preamble, body):
        if not SMTP_FROM and not SMTP_RCPT_TO: return False
        msg = MIMEMultipart('mixed')
        msg['From'] = SMTP_FROM
        msg['To'] = SMTP_RCPT_TO
        if subject: msg['Subject'] = subject
        if body: msg.attach(MIMEText(body, 'plain'))        
        msg.preamble = preamble
        if DEBUG: print('msg={}'.format(msg))
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        print('smtp={} ehlo={} login={} sendmail={} quit={}'.format(
            smtp, smtp.ehlo(),
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD),
            smtp.sendmail(
                SMTP_FROM,
                SMTP_RCPT_TO.split(','),
                msg.as_string()
            ),
            smtp.quit()
        ))
        return True
    
    if subject and body:
        p = Process(target=smtp_send, args=(subject, preamble, body))
        p.daemon = True
        p.start()

    return p


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def distance(lat1, lon1, lat2, lon2):
    p = 0.017453292519943295
    a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p)*cos(lat2*p) \
        * (1-cos((lon2-lon1)*p)) / 2
    return 12742 * asin(sqrt(a))


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_geoip(ip='127.0.0.1'):
    try:
        return json.loads(
            cache_get(
                key='geoip:1:{}'.format(ip)
            )
        )
    except:
        print(
            '{}: cache-miss'.format(
                stack()[0][3]
            )
        )

    print('URL: {}/{}'.format(GEOIP_URL, ip))

    res = requests.get(
        '{}/{}?access_key={}&format=json'.format(
            GEOIP_URL,
            ip,
            GEOIP_API_KEY
        )
    )
    if DEBUG: print(
        '{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        )
    )
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))

    try:
        content = json.loads(res.content.decode('utf-8'))
    except TypeError:
        content = json.loads(res.content)

    if DEBUG: print('{}: type={}'.format(stack()[0][3], type(content)))

    try:
        cache_set(
            key='geoip:1:{}'.format(ip),
            value=json.dumps(content),
            ttl=86400
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()

    return content


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_closest_node(nodes=None, client_ip='127.0.0.1'):
    if client_ip == '127.0.0.1': return nodes[0]
    try:
        client_geo = get_geoip(ip=client_ip)
    except:
        client_geo = {
            'latitude': 0,
            'longitude': 0
        }

    try:
        ipaddrs = list()
        for ip in nodes:
            try:
                server_geo = get_geoip(ip=ip)
            except:
                server_geo = {
                    'latitude': 0,
                    'longitude': 0
                }

            ipaddrs.append(
                [
                    ip,
                    client_geo['latitude'], client_geo['longitude'],
                    server_geo['latitude'], server_geo['longitude'],
                    geo_distance(
                        client_geo['latitude'], client_geo['longitude'],
                        server_geo['latitude'], server_geo['longitude']
                    )
                ]
            )

        if DEBUG: print('ipaddrs={}'.format(ipaddrs))
        
        sorted_by_geo = list()
        loc = [l for l in sorted(
            ipaddrs, key = lambda el: float(el[5])
        )]
        for l in loc: sorted_by_geo.append(l)

        if DEBUG: print('sorted_by_geo={}'.format(sorted_by_geo))
    except:
        return None
    return sorted_by_geo[0][0]


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_last_commit():
    repo = fetch_git_repo()
    return repo.head.object.hexsha

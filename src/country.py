# -*- coding: utf-8 -*-

import inspect

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

from sqlalchemy.sql import text

from model import *
from utils import *
from config import *


ISO_MAP = map_countries()
COUNTRIES = raw_countries()

country_flags_repo = fetch_git_repo(
    dir=COUNTRY_FLAGS_DIR,
    url=COUNTRY_FLAGS_REPO,
    tag=COUNTRY_FLAGS_TAG
)


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def get_country_alpha2(name=None):
    if not name: return None
    try:
        alpha2 = [
            country['alpha-2'].lower()
            for country in COUNTRIES if name in country['name']
        ][0]
    except:
        alpha2 = None
    return alpha2


@retry(Exception, cdata='method={}'.format(inspect.stack()[0][3]))
def get_countries(mask='all'):
    if mask.lower() not in ['all', 'available']: return None
    if mask.lower() == 'all': return ISO_MAP
    if mask.lower() == 'available':
        available_countries = list()
        try:
            sql = '''
                SELECT DISTINCT country
                FROM device
                WHERE (type=1 OR type=3)
                AND status >= 1
                AND dt >= DATE_SUB(NOW(), INTERVAL {} second)
            '''.format(STALE_NODE_THSHLD)
            results = session.execute(text(sql))
            if results.rowcount > 0:
                available_countries = [dict(row._mapping) for row in results]
                for country in available_countries:
                    country['alpha2'] = get_country_alpha2(name=country['country'])
                    country['quoted'] = quote(country['country'])
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()

        return available_countries

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import json
import requests
import locale

try:
    from httplib import OK
except ImportError:
    from http.client import OK

from unicodedata import normalize

from utils import distance


locale.setlocale(locale.LC_ALL, '')


class Provider():
    base_url = 'https://www.ipvanish.com'
    api_url = '{}/api/servers.geojson'.format(base_url)
    ca_cert = '{}/software/configs/ca.ipvanish.com.crt'.format(base_url)
    zip_file = '{}/software/configs/configs.zip'.format(base_url)

    limit = 1 # number of load/geo entries to return


    def get_locations(self, group=None, sort=None, lat=None, lon=None):
        if sort not in ['load', 'geo']: return None
        if sort == 'geo' and (not lat or not lon): return None
        
        headers = {'Accept': 'application/json'}
        res = requests.get('{0}'.format(self.api_url), headers=headers)
        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        payload = json.loads(res.content)
        countries = set([c['properties']['country'] for c in payload])
        
        if sort == 'load':
            locs = [
                [
                    l['properties']['country'], l['properties']['hostname'],
                    l['properties']['capacity'], l['properties']['countryCode'],
                    normalize('NFKD', l['properties']['city']).encode('ascii', 'ignore')
                ]
                for l in payload
                if l['properties']['online'] == True
                and l['properties']['visible'] == True
            ]

            sorted_by_load = list()
            for country in countries:
                loc = [
                    l for l in sorted(locs, key = lambda el: int(el[2]))
                    if l[0] == country
                ][:self.limit]
                for l in loc: sorted_by_load.append(l)

            sorted_by_name = sorted(sorted_by_load, key = lambda el: el[0])

            locations = [
                dict(
                    zip(
                        [
                            'name',
                            'value'
                        ],
                        [
                            '{} - {} - {} (load: {}%)'.format(
                                l[3],
                                l[0],
                                l[4].decode('utf-8'),
                                l[2]
                            ),
                            'ipvanish-{}-{}-{}.ovpn'.format(
                                l[3].replace(' ', '-'),
                                l[4].decode('utf-8').replace(' ', '-'),
                                l[1].split('.')[0].replace(' ', '-')
                            )
                        ]
                    )
                )
                for l in sorted_by_name
            ]

        if sort == 'geo':
            location = {'lat': float(lat), 'lon': float(lon)}
            locs = [
                [
                    l['properties']['country'], l['properties']['hostname'],
                    l['properties']['capacity'], l['properties']['countryCode'],
                    normalize('NFKD', l['properties']['city']).encode('ascii', 'ignore'),
                    distance(
                        float(location['lat']),
                        float(location['lon']),
                        float(l['properties']['latitude']),
                        float(l['properties']['longitude'])
                    )
                ]
                for l in payload
                if l['properties']['online'] == True
                and l['properties']['visible'] == True
            ]

            sorted_by_geo = list()
            for country in countries:
                loc = [l for l in sorted(locs, key = lambda el: float(el[5]))
                       if l[0] == country][:self.limit]
                for l in loc: sorted_by_geo.append(l)

            sorted_by_name = sorted(sorted_by_geo, key = lambda el: el[0])

            locations = [
                dict(
                    zip(
                        [
                            'name',
                            'value'
                        ],
                        [
                            '{} - {} - {} (distance: {}km)'.format(
                                l[3],
                                l[0],
                                l[4].decode('utf-8'),
                                locale.format_string(
                                    '%.0f',
                                    l[5],
                                    grouping=True
                                )
                            ),
                            'ipvanish-{}-{}-{}.ovpn'.format(
                                l[3].replace(' ', '-'),
                                l[4].decode('utf-8').replace(' ', '-'),
                                l[1].split('.')[0].replace(' ', '-')
                            )
                        ]
                    )
                )
                for l in sorted_by_name
            ]

        return locations


if __name__ == '__main__':
    cls = Provider()
    print(cls.get_locations(sort=sys.argv[1], lon='-1', lat='-1'))

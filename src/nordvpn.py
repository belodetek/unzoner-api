#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import json
import requests
import locale

try:
    from httplib import OK
except ImportError:
    from http.client import OK

from utils import distance


locale.setlocale(locale.LC_ALL, '')


class Provider():
    base_url = 'https://api.nordvpn.com'
    api_url = '{}/server'.format(base_url)
    ca_cert = None
    zip_file = 'http://downloads.nordcdn.com/configs/archives/servers/ovpn.zip'

    limit = 1 # number of entries to return
    ovpn_protos = [
        {'proto': 'tcp', 'feature': 'openvpn_tcp'},
        {'proto': 'udp', 'feature': 'openvpn_udp'}
    ]


    def get_locations(self, group=None, sort=None, lat=None, lon=None):
        if sort not in ['load', 'geo']: return None
        if sort == 'geo' and (not lat or not lon): return None
        
        headers = {'Accept': 'application/json'}
        res = requests.get('{0}'.format(self.api_url), headers=headers)
        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        payload = json.loads(res.content)
        countries = set([c['country'] for c in payload])
                
        if sort == 'load':
            locs = list()
            for proto in self.ovpn_protos:
                loc = [[l['country'], l['domain'], proto['proto'],
                        l['load'], l['flag']]
                       for l in payload
                       if l['features'][proto['feature']] == True]
                for l in loc: locs.append(l)
            
            sorted_by_load = list()
            for country in countries:
                loc = [l for l in sorted(locs, key = lambda el: int(el[3]))
                       if l[0] == country][:self.limit]
                for l in loc: sorted_by_load.append(l)
                
            sorted_by_name = sorted(sorted_by_load, key = lambda el: el[0])

            locations = [
                dict(zip(['name', 'value'],
                         ['{} - {} (load: {}%)'.format(l[4], l[0],l[3]),
                          '{}.{}.ovpn'.format(l[1], l[2])]))
                for l in sorted_by_name]

        if sort == 'geo':
            location = {'lat': float(lat), 'lon': float(lon)}
            locs = list()
            for proto in self.ovpn_protos:
                loc = [[l['country'], l['domain'], proto['proto'],
                        l['load'], l['flag'],
                        distance(
                            float(location['lat']),
                            float(location['lon']),
                            float(l['location']['lat']),
                            float(l['location']['long']))]
                       for l in payload
                       if l['features'][proto['feature']] == True]
                for l in loc: locs.append(l)
            
            sorted_by_geo = list()
            for country in countries:
                loc = [l for l in sorted(
                    locs, key = lambda el: float(el[5]))
                       if l[0] == country][:self.limit]
                for l in loc: sorted_by_geo.append(l)
                
            sorted_by_name = sorted(sorted_by_geo, key = lambda el: el[0])

            locations = [
                dict(zip(['name', 'value'],
                         ['{} - {} (distance: {}km)'.format(
                             l[4], l[0],
                             locale.format('%.0f', l[5], grouping=True)),
                          '{}.{}.ovpn'.format(
                              l[1], l[2])]))
                for l in sorted_by_name]

        return locations


if __name__ == '__main__':
    cls = Provider()
    print(cls.get_locations(sort='load'))

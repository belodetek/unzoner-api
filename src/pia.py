#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import json
import requests
import locale
import re
import sys

try:
    from httplib import OK
except ImportError:
    from http.client import OK

from traceback import print_exc


locale.setlocale(locale.LC_ALL, '')


class Provider():
    __disabled__ = True
    base_url = 'https://www.privateinternetaccess.com'
    api_url = '{}/vpninfo/servers?version=82'.format(base_url)
    regex = '{.*}}'

    # https://www.privateinternetaccess.com/helpdesk/kb/articles/which-encryption-auth-settings-should-i-use-for-ports-on-your-gateways-2
    ovpn_protos = [
        {
            'name': 'openvpn_tcp',
            'proto': 'tcp',
            'ciphers': {
                'AES-128-CBC': {
                    'extra': '#REMOVE=1 #CERT=ca.rsa.2048.crt #CRLVERIFY=crl.rsa.2048.pem',
                    'port': '502',
                    'ca_cert': '{}/openvpn/ca.rsa.2048.crt'.format(base_url),
                    'crl': '{}/openvpn/crl.rsa.2048.pem'.format(base_url)
                },
                'AES-256-CBC': {
                    'extra': '#REMOVE=2 #CERT=ca.rsa.4096.crt #CRLVERIFY=crl.rsa.4096.pem',
                    'port': '501',
                    'ca_cert': '{}/openvpn/ca.rsa.4096.crt'.format(base_url),
                    'crl': '{}/openvpn/crl.rsa.4096.pem'.format(base_url)
                }
            }
        },
        {
            'name': 'openvpn_udp',
            'proto': 'udp',
            'ciphers': {
                'AES-128-CBC': {
                    'extra': '#REMOVE=1 #CERT=ca.rsa.2048.crt #CRLVERIFY=crl.rsa.2048.pem',
                    'port': '1198',
                    'ca_cert': '{}/openvpn/ca.rsa.2048.crt'.format(base_url),
                    'crl': '{}/openvpn/crl.rsa.2048.pem'.format(base_url)
                },
                'AES-256-CBC': {
                    'extra': '#REMOVE=2 #CERT=ca.rsa.4096.crt #CRLVERIFY=crl.rsa.4096.pem',
                    'port': '1197',
                    'ca_cert': '{}/openvpn/ca.rsa.4096.crt'.format(base_url),
                    'crl': '{}/openvpn/crl.rsa.4096.pem'.format(base_url)
                }
            }
         }
    ]


    def get_location_groups(self):
        return list(set(
            [
                cipher for ciphers in [
                    list(prov['ciphers'].keys()) for prov in self.ovpn_protos
                ]
                for cipher in ciphers
            ]
        ))


    def get_locations(self, group=None, sort=None, lat=None, lon=None):
        headers = {'Accept': 'application/json'}
        res = requests.get('{0}'.format(self.api_url), headers=headers)
        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        try:
            p = re.compile(self.regex)
            data = p.search(res.content.decode()).group(0)
        except:
            print_exc()
            data = res.content.decode()

        payload = json.loads(data)

        locs = list()
        for proto in self.ovpn_protos:
            loc = [
                [
                    payload[k]['name'],
                    payload[k]['country'],
                    payload[k][proto['name']]['best'].split(':')[0],
                    ''.join([
                        p['proto'] for p in self.ovpn_protos
                        if p['name'] == proto['name']
                    ]),
                    ''.join([
                        p['ciphers'][group]['port'] for p in self.ovpn_protos
                        if p['name'] == proto['name']
                    ]),
                    ''.join([
                        p['ciphers'][group]['extra'] for p in self.ovpn_protos
                        if p['name'] == proto['name']
                    ])
                ]
                for k, v in payload.items()
                if 'name' in payload[k] and 'country' in payload[k]
            ]
            for l in loc: locs.append(l)

        locations = [
            dict(zip(
                ['name', 'value', 'ipaddr', 'proto', 'port', 'extra'],
                [
                    '{} - {} ({})'.format(
                        loc[1].upper(),
                        loc[0],
                        loc[3].upper()
                    ),
                    '{} - {} ({})'.format(
                        loc[1].upper(),
                        loc[0],
                        loc[3].upper()
                    ),
                    loc[2],
                    loc[3],
                    loc[4],
                    loc[5]
                ]
            ))
            for loc in locs
        ]

        return sorted(locations, key = lambda el: el['name'])


if __name__ == '__main__':
    cls = Provider()
    print(cls.get_locations(group=sys.argv[1]))

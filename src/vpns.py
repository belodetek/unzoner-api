# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import re
import json

from importlib import import_module
from inspect import stack
from traceback import print_exc
from urllib.parse import unquote

from utils import *
from config import *


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def provider_metadata(metafile='metadata.json'):
    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )
    try:
        metadata = json.loads(
            open(
                '{}/{}'.format(
                    VPN_PROFILES,
                    metafile
                )
            ).read()
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        metadata = dict()
    return metadata


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def load_provider_groups():
    try:
        groups = provider_metadata()['provider_groups']
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        groups = ['default']
    return groups


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def load_affiliate_links():
    try:
        links = provider_metadata()['affiliate_links']
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        links = []
    return links


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def affiliate_link(provider=None):
    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )
    links = load_affiliate_links()
    try:
        link = [
            el['link']
            for el in links
            if el['provider'].lower() == provider.lower()
        ][0]
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        link = 'https://flashrouters.com'
    return link


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def provider_groups():
    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )
    try:
        groups = [
            pg['name']
            for pg in load_provider_groups()
        ]
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
    groups.sort()
    return groups


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def providers_by_group(group='default'):
    group = unquote(group)

    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )
    default_providers = [
        d for d in next(os.walk(VPN_PROFILES))[1]
        if d not in ['.git']
    ]
    try:
        providers = [
            pg['value']
            for pg in load_provider_groups()
            if group == pg['name']
        ][0]
        if '*' in providers: providers = default_providers
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        providers = default_providers
        pass
    providers.sort()
    return providers


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def location_groups_by_provider(provider='VPNArea', metafile='METADATA.txt'):
    provider = unquote(provider)

    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )

    try:
        mod = import_module(provider.lower())
        p = mod.Provider()
        if '__disabled__' in dir(p): assert p.__disabled__ == False
        assert mod and 'Provider' in dir(mod) and 'get_location_groups' in dir(mod.Provider)
        location_groups = p.get_location_groups()
        assert location_groups
        return location_groups
    except:
        try:
            metadata = open(
                '{}/{}/{}'.format(
                    VPN_PROFILES,
                    provider,
                    metafile
                )
            ).read()
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()
        try:
            location_groups = [
                ' '.join(x.split('.')[0].split()[1:])
                for x in metadata.split('\n')
                if x.startswith('LOCATIONS')
            ]
            assert ''.join(location_groups)
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()
            location_groups = ['default']
        location_groups.sort()
        return location_groups


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def locations_by_provider(
    provider='VPNArea',
    group='default',
    sort=None,
    lat=None,
    lon=None
):
    provider = unquote(provider)
    group = unquote(group)

    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )

    try:
        mod = import_module(provider.lower())
        p = mod.Provider()
        if '__disabled__' in dir(p): assert p.__disabled__ == False
        assert mod and 'Provider' in dir(mod) and 'get_locations' in dir(mod.Provider)
        locations = p.get_locations(group=group, sort=sort, lat=lat, lon=lon)
        assert locations
        if DEBUG: print("'locations='{}'".format(locations))
        return locations
    except Exception as e:
        if DEBUG: print_exc()
        if group == 'default':
            locfile = 'LOCATIONS.txt'
        else:
            locfile = 'LOCATIONS {}.txt'.format(group)

        try:
            locdata = open(
                '{}/{}/{}'.format(
                    VPN_PROFILES,
                    provider,
                    locfile
                )
            ).read()
            locations = [
                dict(
                    zip(
                        [
                            'name',
                            'ipaddr',
                            'proto',
                            'port',
                            'extra'
                        ],
                        l.strip().split(',')
                    )
                ) for l in locdata.split('\n') if l
            ]
            for loc in locations:
                loc['value'] = loc['name']
        except:
            locations = [
                dict(zip(['name', 'value'], [f, f]))
                for f in next(
                    os.walk(
                        '{}/{}'.format(
                            VPN_PROFILES,
                            provider
                        )
                    )
                )[2]
                if f.split('.')[-1] == 'ovpn']
        locations = sorted(locations, key=lambda k: k['name'])
        return locations


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def client_cert_required(
    provider='VPNArea',
    metafile='METADATA.txt',
    tmplfile='TEMPLATE.txt'
):
    provider = unquote(provider)

    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )
    regex = re.compile('USERCERT|USERKEY')
    required = False
    try:
        metadata = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                metafile
            )
        ).read()
        tmplfile = [
            x for x in metadata.split('\n')
            if x.startswith('TEMPLATE')
        ][0]
        tmpl = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                tmplfile
            )
        ).read()
        cert = get_user_cert_contents(
            metadata=metadata,
            provider=provider
        )
        key = get_user_key_contents(
            metadata=metadata,
            provider=provider
        )
        assert (not cert or not key) and bool(regex.search(tmpl))
        required = True
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
    return required


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_user_cert_contents(metadata=None, provider=None):
    try:
        provider = unquote(provider)

        certfile = [
            x for x in metadata.split('\n')
            if x.startswith('user')
            and x.endswith('crt')
        ][0]
        cert = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                certfile
            )
        ).read()
    except:
        cert = None
    return cert


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_user_key_contents(metadata=None, provider=None):
    key = None
    try:
        provider = unquote(provider)

        keyfile = [
            x for x in metadata.split('\n')
            if x.startswith('user')
            and x.endswith('key')
        ][0]
        key = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                keyfile
            )
        ).read()
    except:
        key = None
    return key


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def generate_ovpn_profile(
    provider='VPNArea',
    metafile='METADATA.txt',
    tmplfile='TEMPLATE.txt',
    group='default',
    name='USA - Los Angeles (UDP)'
):
    provider = unquote(provider)
    group = unquote(group)
    name = unquote(name)

    if DEBUG: print("provider='{}' group='{}' name='{}'".format(
        provider,
        group,
        name
    ))

    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )

    try:
        metadata = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                metafile
            )
        ).read()
    except:
        metadata = None

    try:
        tmplfile = [
            x for x in metadata.split('\n') if x.startswith('TEMPLATE')
        ][0]
        tmpl = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                tmplfile
            )
        ).read()
    except:
        tmpl = None

    try:
        cafile = [
            x for x in metadata.split('\n')
            if x.startswith('ca') and x.endswith('crt')
        ][0]
        ca = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                cafile
            )
        ).read()
    except:
        ca = None

    try:
        cert = get_user_cert_contents(
            metadata=metadata,
            provider=provider
        )
    except:
        cert = None

    try:
        key = get_user_key_contents(
            metadata=metadata,
            provider=provider
        )
    except:
        key = None

    try:
        tafile = [
            x for x in metadata.split('\n') if x.startswith('ta') and x.endswith('key')
        ][0]
        ta = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                tafile
            )
        ).read()
    except:
        ta = None

    try:
        crlfile = [
            x for x in metadata.split('\n') if x.startswith('crl') and x.endswith('pem')
        ][0]
        crl = open(
            '{}/{}/{}'.format(
                VPN_PROFILES,
                provider,
                crlfile
            )
        ).read()
    except:
        crl = None

    try:
        location = [
            loc for loc in locations_by_provider(
                group=group,
                provider=provider
            )
            if loc['name'] == name
        ][0]
        ipaddr = location['ipaddr'].strip()
        proto = location['proto'].strip()
        port = location['port'].strip()
        try:
            extras = [
                dict(
                    zip(
                        ['key', 'value'],
                        l
                    )
                ) for l in [
                    el.split('=') for el in location['extra'].split()
                ]
            ]
            if DEBUG: print('extras: {}'.format(extras))
        except:
            extras = None
    except:
        if DEBUG: print_exc()

    # provider with .ovpn profiles (e.g. NordVPN and LimeVPN)
    if 'ipaddr' not in location.keys():
        try:
            tmpl = open(
                '{}/{}/{}'.format(
                    VPN_PROFILES,
                    provider,
                    location['name']
                )
            ).read()
        except:
            if DEBUG: print_exc()

    try:
        tmpl = tmpl.replace('#PROTO', proto)
        tmpl = tmpl.replace('#SERVPROT', proto)
        tmpl = tmpl.replace('#SERVER', ipaddr)
        tmpl = tmpl.replace('#PORT', port)
    except:
        if DEBUG: print_exc()

    # remove directives
    tmpl = tmpl.splitlines()
    try:
        for extra in extras:
            if extra['key'] == '#REMOVE':
                for val in [i for i in extra['value']]:
                    tmpl = [
                        line for line in tmpl if not bool(
                            re.search('^#REMOVE{}'.format(val), line)
                    )]
                extras.remove(extra)

        for extra in extras:
            tmpl = [line.replace(extra['key'], extra['value']) for line in tmpl]
    except:
        if DEBUG: print_exc()

    tmpl = '\n'.join(tmpl)
    tmpl = tmpl.replace('#PATHuser.crt', '#USERCERT')
    tmpl = tmpl.replace('#PATHuser.key', '#USERKEY')
    tmpl = tmpl.replace('#PASS', '')

    if cert: tmpl = tmpl.replace(
        'cert #USERCERT', '<cert>\n{}\n</cert>\n'.format(
            cert
        )
    )
    if key: tmpl = tmpl.replace(
        'key #USERKEY', '<key>\n{}\n</key>\n'.format(
            key
        )
    )
    tmpl = tmpl.splitlines()

    # remove remaining tags
    regex = re.compile('^(#REMOVE\d{1})(.*)$')
    temp = list()
    for line in tmpl:
        if regex.search(line):
            temp.append(regex.search(line).groups()[1])
        else:
            temp.append(line)
    tmpl = temp

    # de-compress tls-auth and key-direction
    regex = re.compile('^tls-auth #TLSKEY (\d{1})$')
    temp = list()
    for line in tmpl:
        if regex.search(line):
            temp.append('<tls-auth>\n{}\n</tls-auth>\n'.format(ta))
            temp.append(
                'key-direction {}\n'.format(
                    regex.search(line).groups()[0]
                )
            )
        else:
            temp.append(line)
    tmpl = temp

    # in-line tls-key
    regex = re.compile('^tls-auth #TLSKEY$')
    temp = list()
    for line in tmpl:
        if regex.search(line):
            temp.append('<tls-auth>\n{}\n</tls-auth>\n'.format(ta))
        else:
            temp.append(line)
    tmpl = temp

    # in-line all other keys
    temp = list()
    for line in tmpl:
        if line.split(' ')[0] in [
            'ca',
            'crl-verify',
            'tls-auth',
            'key',
            'cert'
        ]:
            fdata = None
            try:
                fdata = open(
                    '{}/{}/{}'.format(
                        VPN_PROFILES,
                        provider,
                        line.split(' ')[1].replace('"', '').replace("'", '')
                    )
                ).read()
            except Exception as e:
                if DEBUG: print_exc()
                temp.append(line)

            if fdata:
                temp.append(
                    '<{}>\n{}\n</{}>\n'.format(
                        line.split(' ')[0],
                        fdata,
                        line.split(' ')[0]
                    )
                )
        else:
            temp.append(line)

    # remove superfluous directives
    for regex in ['^dev tun[\d]+']:
        tmpl = [line for line in tmpl if not bool(re.search(regex, line))]

    tmpl = '\n'.join(temp)

    # final sweep for providers with only one ca cert
    if ca: tmpl = tmpl.replace(
        'ca #CERT', '<ca>\n{}\n</ca>\n'.format(
            ca
        )
    )
    if crl: tmpl = tmpl.replace(
        'crl-verify #CRLVERIFY',
        '<crl-verify>\n{}\n</crl-verify>\n'.format(crl))

    return '{}\n'.format(
        os.linesep.join(
            [
                s for s in tmpl.splitlines() if s
            ]
        )
    )

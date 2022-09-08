# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import json
import requests

from inspect import stack
from traceback import print_exc
from datetime import datetime, timedelta

try:
    from httplib import (
        UNAUTHORIZED,
        OK,
        FORBIDDEN
    )
except ImportError:
    from http.client import (
        UNAUTHORIZED,
        OK,
        FORBIDDEN
    )

import bitcoin_payments # prevent circular imports

from utils import *
from config import *


RESN_API_TOKEN = None


####################
# resin.io methods #
####################
@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def init_cache():
    try:
        res = get_resin_devices()
        try:
            devices = json.loads(res.content.decode('utf-8'))
        except:
            devices = json.loads(res.content)
        cmds = list()
        for device in devices['d']:
            res = get_resin_device_env(device['id'])
            try:
                evs = json.loads(res.content.decode('utf-8'))
            except:
                evs = json.loads(res.content)
            for ev in evs['d']:
                if ev['env_var_name'] in ['BITCOIN_PAYMENT_ADDRESS']:
                    cmds.append({'key': ev['value'], 'value': device['uuid']})
                if ev['env_var_name'] in ['PAYPAL_BILLING_AGREEMENT']:
                    paypal_baid = ev['value']
                if ev['env_var_name'] in ['PAYPAL_PAYER_EMAIL']:
                    paypal_email = ev['value']
            try:
                cmds.append({'key': paypal_email, 'value': paypal_baid})
            except Exception:
                print(repr(e))
                if DEBUG: print_exc()

        return cache_pipe_set(cmds=cmds)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_token():
    credentials = {'username': RESN_USERNAME, 'password': RESN_PASSWORD}

    headers = {
        'Content-Type': 'application/json'
    }

    res = requests.post(
        '{}/login_'.format(
            RESN_API_HOST
        ),
        headers=headers,
        data=json.dumps(credentials),
        timeout=DEFAULT_TIMEOUT
    )

    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    try:
        return res.content.decode('utf-8')
    except:
        return res.content


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_devices(app_id=RESIN_APP_ID):
    res = None
    try:
        res = dotdict(json.loads(cache_get(key='cache_resin_devices')))
    except:
        print('{}: cache-miss'.format(stack()[0][3]))

    if not res:
        global RESN_API_TOKEN

        headers = {
            'Authorization': 'Bearer {}'.format(
                RESN_API_TOKEN
            ),
            'Content-Type': 'application/json'
        }

        endpoint = '{}/v6/device?$filter=belongs_to__application%20in%20({})&$expand=is_of__device_type($select=slug,name)&$select=uuid,id,belongs_to__application,location,status,is_online,ip_address,supervisor_version,os_version,os_variant'.format(
            RESN_API_HOST,
            app_id
        )

        res = requests.get(endpoint, headers=headers)

        content_length = None
        try:
            content_length = len(json.loads(res.content.decode('utf-8'))['d'])
        except:
            try:
                content_length = len(json.loads(res.content)['d'])
            except ValueError:
                pass

        if content_length == 0 or res.status_code in [UNAUTHORIZED, FORBIDDEN]:
            RESN_API_TOKEN = get_resin_token()

        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        dd = dotdict(res.__dict__)
        try:
            payload = json.loads(res.content.decode('utf-8'))
        except:
            payload = json.loads(res.content)

        dd._content = json.dumps(payload)

        cached_dd = dotdict()
        cached_dd.status_code = dd.status_code
        try:
            cached_dd.content = dd._content.decode('utf-8')
        except:
            cached_dd.content = dd._content

        try:
            cache_set(
                key='cache_resin_devices',
                value=json.dumps(cached_dd),
                ttl=10
            )
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()

        return cached_dd
    else:
        return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def resin_device_action(guid=None, action='restart'):
    global RESN_API_TOKEN

    try:
        guid = guid.decode('utf-8')
    except:
        pass

    headers = {
        'Authorization': 'Bearer {}'.format(
            RESN_API_TOKEN
        ),
        'Content-Type': 'application/json'
    }

    device_id = get_resin_device_id_by(guid)
    app_id = get_resin_app_id_by(guid)
    cache_remove(key='cache_resin_devices')
    cache_remove(key='cache_resin_device_env:1:{}'.format(device_id))
    data = {'deviceId': device_id, 'appId': app_id}
    if action in 'restart': data['data'] = {'appId': app_id}

    res = requests.post(
        '{}/supervisor/v1/{}'.format(
            RESN_API_HOST,
            action
        ),
        headers=headers,
        data=json.dumps(data)
    )

    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
        AssertionError((res.status_code, ))
    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device_env(device_id):
    res = None
    try:
        res = dotdict(json.loads(cache_get(
            key='cache_resin_device_env:1:{}'.format(device_id)
        )))
    except:
        print(
            '{}({}): cache-miss'.format(
                stack()[0][3],
                device_id
            )
        )

    if not res:
        global RESN_API_TOKEN

        headers = {
            'Authorization': 'Bearer {}'.format(
                RESN_API_TOKEN
            ),
            'Content-Type': 'application/json'
        }

        res = requests.get(
            '{}/v1/device_environment_variable?$filter=device eq {}'.format(
                RESN_API_HOST,
                device_id
            ),
            headers=headers
        )

        content_length = None
        try:
            content_length = len(json.loads(res.content.decode('utf-8'))['d'])
        except:
            try:
                content_length = len(json.loads(res.content)['d'])
            except ValueError:
                pass

        if content_length == 0 or res.status_code in [UNAUTHORIZED, FORBIDDEN]:
            RESN_API_TOKEN = get_resin_token()

        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        dd = dotdict(res.__dict__)
        cached_dd = dotdict()
        cached_dd.status_code = dd.status_code
        try:
            cached_dd.content = dd._content.decode('utf-8')
        except:
            cached_dd.content = dd._content

        try:
            cache_set(
                key='cache_resin_device_env:1:{}'.format(
                    device_id
                ),
                value=json.dumps(cached_dd),
                ttl=DEFAULT_CACHE_TTL
            )
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()
    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_app_env(app_id):
    res = None
    try:
        res = dotdict(json.loads(cache_get(
            key='cache_resin_app_env:1:{}'.format(app_id)
        )))
    except Exception:
        print(
            '{}({}): cache-miss'.format(
                stack()[0][3],
                app_id
            )
        )

    if not res:
        global RESN_API_TOKEN
        headers = {
            'Authorization': 'Bearer {}'.format(
                RESN_API_TOKEN
            ),
            'Content-Type': 'application/json'
        }

        res = requests.get(
            '{}/v1/environment_variable?$filter=application eq {}'.format(
                RESN_API_HOST,
                app_id
            ),
            headers=headers
        )

        content_length = None
        try:
            content_length = len(json.loads(res.content.decode('utf-8'))['d'])
        except:
            try:
                content_length = len(json.loads(res.content)['d'])
            except ValueError:
                pass

        if content_length == 0 or res.status_code in [UNAUTHORIZED, FORBIDDEN]:
            RESN_API_TOKEN = get_resin_token()

        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))

        dd = dotdict(res.__dict__)
        cached_dd = dotdict()
        cached_dd.status_code = dd.status_code
        try:
            cached_dd.content = dd._content.decode('utf-8')
        except:
            cached_dd.content = dd._content

        try:
            cache_set(
                key='cache_resin_app_env:1:{}'.format(
                    app_id
                ),
                value=json.dumps(cached_dd),
                ttl=DEFAULT_CACHE_TTL
            )
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()

    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def post_resin_device_env(payload=None):
    global RESN_API_TOKEN
    cache_remove(key='cache_resin_device_env:1:{}'.format(payload['device']))

    headers = {
        'Authorization': 'Bearer {}'.format(
            RESN_API_TOKEN
        ),
        'Content-Type': 'application/json'
    }

    data = json.dumps(payload)
    res = requests.post(
        '{}/v1/device_environment_variable'.format(
            RESN_API_HOST
        ),
        headers=headers,
        data=data
    )

    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()

    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def delete_resin_device_env(device_id=None, env_id=None):
    global RESN_API_TOKEN
    cache_remove(key='cache_resin_device_env:1:{}'.format(device_id))

    headers = {
        'Authorization': 'Bearer {}'.format(
            RESN_API_TOKEN
        ),
        'Content-Type': 'application/json'
    }

    res = requests.delete(
        '{}/v1/device_environment_variable({})'.format(
            RESN_API_HOST,
            env_id
        ),
        headers=headers
    )

    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def patch_resin_device_env(device_id=None, env_id=None, payload=None):
    global RESN_API_TOKEN
    cache_remove(key='cache_resin_device_env:1:{}'.format(device_id))

    headers = {
        'Authorization': 'Bearer {}'.format(
            RESN_API_TOKEN
        ),
        'Content-Type': 'application/json'
    }

    data = json.dumps(payload)
    res = requests.patch(
        '{}/v1/device_environment_variable({})'.format(
            RESN_API_HOST,
            env_id
        ),
        headers=headers,
        data=data
    )

    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    return res


@retry(Exception, cdata='method={0}'.format(stack()[0][3]))
def delete_resin_device(device_id=None):
    global RESN_API_TOKEN

    cache_remove(key='cache_resin_devices')

    headers = {
        'Authorization': 'Bearer {}'.format(
            RESN_API_TOKEN
        ),
        'Content-Type': 'application/json'
    }

    res = requests.delete(
        '{}/v1/device({})'.format(
            RESN_API_HOST,
            device_id
        ),
        headers=headers
    )

    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    return res


###################
# wrapper methods #
###################
@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device(guid=None):
    if not guid: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    global RESN_API_TOKEN
    result = None
    res = get_resin_devices()
    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    try:
        devices = json.loads(res.content.decode('utf-8'))
    except:
        devices = json.loads(res.content)
    for device in devices['d']:
        if device['uuid'].startswith(guid):
            result = device
        if result: break
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device_id_by(guid):
    if not guid: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    return get_resin_device(guid=guid)['id']


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_app_id_by(guid):
    if not guid: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    return get_resin_device(guid=guid)['belongs_to__application']['__id']


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device_envs_by(guid):
    if not guid: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    global RESN_API_TOKEN
    res = get_resin_device_env(get_resin_device_id_by(guid))
    if res.status_code in [FORBIDDEN, UNAUTHORIZED]:
        RESN_API_TOKEN = get_resin_token()
    if res.status_code not in [OK]:
        raise AssertionError((res.status_code, res.content))
    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device_env_by_name(guid=None, name=None, default=None):
    if not guid and not name: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    global RESN_API_TOKEN
    res = get_resin_device_envs_by(guid)
    assert res.status_code in [OK]
    try:
        evs = json.loads(res.content.decode('utf-8'))
    except:
        evs = json.loads(res.content)
    for ev in evs['d']:
        if ev['env_var_name'] == name:
            return ev['value']
    return default


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def delete_resin_device_env_by_name(guid=None, name=None):
    if not guid and not name: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    global RESN_API_TOKEN
    device_id = get_resin_device_id_by(guid)
    assert device_id
    res = get_resin_device_envs_by(guid)
    assert res.status_code in [OK]
    try:
        evs = json.loads(res.content.decode('utf-8'))
    except:
        evs = json.loads(res.content)
    for ev in evs['d']:
        if ev['env_var_name'] == name:
            return delete_resin_device_env(device_id=device_id, env_id=ev['id'])
    return False


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def create_update_resin_device_env(guid=None, name=None, value=None):
    if not guid and not name and not value: return None
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    global RESN_API_TOKEN
    res = get_resin_device_envs_by(guid)
    assert res.status_code in [OK]
    try:
        evs = json.loads(res.content.decode('utf-8'))
    except:
        evs = json.loads(res.content)
    device_id = get_resin_device_id_by(guid)
    assert device_id
    env_id = None
    for ev in evs['d']:
        if ev['env_var_name'] == name:
            # found, update existing env var
            payload = {'value': value}
            env_id = ev['id']
            res = patch_resin_device_env(device_id=device_id, env_id=env_id, payload=payload)
    if not env_id:
        # not found, create new env var
        payload = {
            'device': device_id,
            'env_var_name': name,
            'value': value
        }
        res = post_resin_device_env(payload=payload)
    return {
        'guid': guid,
        'device': device_id,
        'env_id': env_id,
        'env_var_name': name,
        'value': value
    }


def purge_resin_devices(guid=None, app_id=None):
    if not app_id and not guid: return
    filter_states = [
        'ResinOS: update successful, rebooting...',
        'Update successful, rebooting'
    ]
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    devices = json.loads(get_resin_devices(app_id=app_id)['content'])
    utcnow = datetime.utcnow()
    expired_devices = list()
    if guid: devices['d'] = [d for d in devices['d'] if d['uuid'] == guid]
    for device in devices['d']:
        try:
            if DEBUG: print('device: {}'.format(device))
            device_dict = dict()
            guid = device['uuid']
            try:
                last_connectivity_event = device['last_connectivity_event']
                assert last_connectivity_event
            except:
                last_connectivity_event = utcnow

            try:
                download_progress = device['download_progress']
                assert download_progress
            except:
                download_progress = None

            try:
                provisioning_progress = device['provisioning_progress']
                assert provisioning_progress
            except:
                provisioning_progress = None

            try:
                provisioning_state = device['provisioning_state']
                assert provisioning_state
            except:
                provisioning_state = None

            try:
                expired = datetime.strptime(
                    last_connectivity_event, '%Y-%m-%dT%H:%M:%S.%fZ'
                ) + timedelta(days=MAX_LAST_SEEN_DAYS) < utcnow
            except:
                expired = False

            try:
                device_type = get_resin_device_env_by_name(
                    guid=guid, name='DEVICE_TYPE'
                )
                assert device_type
            except:
                device_type = DEVICE_TYPE

            try:
                webhook_id = get_resin_device_env_by_name(
                    guid=guid, name='BITCOIN_BLOCKCYPHER_WEBHOOK_ID'
                )
                assert webhook_id
            except:
                webhook_id = None

            try:
                paypal_subscription = get_resin_device_env_by_name(
                    guid=guid, name='PAYPAL_BILLING_AGREEMENT'
                )
                assert paypal_subscription
            except:
                paypal_subscription = None

            try:
                expired_bitcoin_payment = bitcoin_payments.bitcoin_payment_expired(
                    guid=guid
                )
                assert expired_bitcoin_payment in [True, False]
            except:
                expired_bitcoin_payment = None

            if DEBUG:
                print('last_connectivity_event={} download_progress={} provisioning_progress={} provisioning_state={} expired={} device_type={} webhook_id={} paypal_subscription={} expired_bitcoin_payment={}'.format(
                    last_connectivity_event,
                    download_progress,
                    provisioning_progress,
                    provisioning_state,
                    expired,
                    device_type,
                    webhook_id,
                    paypal_subscription,
                    expired_bitcoin_payment
                ))

            device_expired = False
            if (not device['is_online'] and expired)\
               and (not download_progress or download_progress in [3, 66])\
               and (not provisioning_progress or provisioning_progress in [100])\
               and (not provisioning_state or provisioning_state in filter_states)\
               and paypal_subscription is None\
               and (expired_bitcoin_payment is None or expired_bitcoin_payment)\
               and (device_type is not None and device_type in ['2', '4', '5'])\
               and not guid in PURGE_WHITELIST.split(','):
                device_dict['device'] = device
                device_dict['guid'] =  guid
                device_dict['webhook_id'] = webhook_id
                device_dict['device_type'] = device_type
                device_dict['paypal_subscription'] = paypal_subscription
                device_dict['expired_bitcoin_payment'] = expired_bitcoin_payment
                device_dict['expired_dt'] = expired
                device_dict['is_expired'] = True
                device_dict['purged'] = True and PURGE
                expired_devices.append(device_dict)
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()

    if expired_devices:
        purged_count = len([d for d in expired_devices if d['purged']])
        expired_count = len([d for d in expired_devices if d['is_expired']])

        try:
            background_smtp_send(
                subject='devices expired={} purged={}'.format(
                    expired_count,
                    purged_count
                ),
                body=json.dumps(expired_devices),
                preamble='Device purge'
            )
        except:
            pass

        if PURGE:
            for device in expired_devices:
                res = delete_resin_device(device_id=get_resin_device_id_by(device['guid']))
                if device['webhook_id']:
                    res = bitcoin_payments.remove_webhook(webhook_id=device['webhook_id'])
    return expired_devices


if not os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    if RESN_USERNAME and RESN_PASSWORD:
        try:
            RESN_API_TOKEN = get_resin_token()
            if DEBUG: print('resin_api_token={}'.format(RESN_API_TOKEN))
        except Exception as e:
            pass

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import re
import sys
import time
import json
import pickle
import socket
import struct
import jwt

from glob import glob
from inspect import stack
from flask_sslify import SSLify
from datetime import datetime, timedelta
from sqlalchemy.sql import func, update, text

from functools import wraps
from traceback import print_exc
from werkzeug.serving import WSGIRequestHandler
from base64 import b64decode
from PIL import Image


try:
    from cStringIO import StringIO
except ImportError:
    from io import BytesIO

from flask import (
    abort,
    Flask,
    jsonify,
    make_response,
    redirect,
    request,
    Response
)

try:
    from httplib import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN,
        INTERNAL_SERVER_ERROR,
        CREATED,
        CONFLICT,
        FOUND
    )
except ImportError:
    from http.client import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN,
        INTERNAL_SERVER_ERROR,
        CREATED,
        CONFLICT,
        FOUND
    )

try:
    from paypalrestsdk.notifications import WebhookEvent
except ImportError:
    pass

from update import *
from utils import *
from vpns import *
from bitcoin_payments import *
from paypal import *
from model import *
from resin import *
from country import *
from config import *


application = Flask(__name__)
application.config.from_object('config')
application.debug = DEBUGGER

sslify = SSLify(
    application, skips=[
        'api/v{}/ping'.format(API_VERSION),
        'status',
        'ddwrt',
        'api/v{}/ddwrt'.format(API_VERSION),
        'api/v{}/vpnprovider'.format(API_VERSION)
    ]
)

# set HTTP/1.1
WSGIRequestHandler.protocol_version = 'HTTP/1.1'

# initialise globals and cache
if not os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    print('cache_flush: {}'.format(cache_flush()))
    print('init_cache: {}'.format(init_cache()))

BLACKBOX = load_blackbox_data()


@application.teardown_appcontext
def shutdown_session(exception=None):
    session.commit()
    session.remove()


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not 'X-Auth-Token' in request.headers:
            abort(UNAUTHORIZED)
        if API_SECRET == request.headers.get('X-Auth-Token'):
            return f(*args, **kwargs)
        else:
            abort(UNAUTHORIZED)
    return decorated


def add_response_headers(headers={}):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            resp = make_response(f(*args, **kwargs))
            h = resp.headers
            for header, value in headers.items():
                h[header] = value
            return resp
        return decorated_function
    return decorator


def add_cors_header(f):
    return add_response_headers(
        {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'origin, content-type, accept'
        }
    )(f)


def add_download_headers(f):
    return add_response_headers(
        {
            'Content-Disposition': 'attachment; filename="blackbox.ovpn"',
            'Content-Type': 'application/x-openvpn-profile',
            'X-Content-Type-Options': 'nosniff'
        }
    )(f)


def add_cache_control_max_age_1hr(f):
    return add_response_headers(
        {
            'Cache-Control': 'max-age=3600'
        }
    )(f)


@application.route('/api/v{}/ping'.format(API_VERSION))
@application.route('/status')
def _ping_pong():
    return json.dumps({'ping': 'pong'})



################
# PayPal views #
################
@application.route('/api/v{}/paypal/billing-<string:btype>'.format(API_VERSION), methods=['GET'], defaults={'bid': None})
@application.route('/api/v{}/paypal/billing-<string:btype>/<string:bid>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_billing(bid, btype):
    if btype.lower() not in ['agreements', 'plans']: abort(NOT_FOUND)
    try:
        res = get_pp_billing(bid=bid, btype=btype)
        if DEBUG: print('{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        ))
        if res.status_code not in [OK]: abort(res.status_code)
        try:
            payload = json.loads(res.content.decode('utf-8'))
        except:
            payload = json.loads(res.content)
        return jsonify(payload)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/paypal/billing-agreements/<string:baid>/confirm'.format(API_VERSION), methods=['GET'])
@requires_auth
def _confirm_active_billing_agreement(baid):
    try:
        res = get_pp_billing(bid=baid, btype='agreements')
        if DEBUG: print('{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        ))
        if res.status_code not in [OK]: abort(res.status_code)
        try:
            payload = json.loads(res.content.decode('utf-8'))
        except:
            payload = json.loads(res.content)
        state = payload['state'].lower()
        if state in ['active']:
            return jsonify({'agreement_state': state})
        else:
            return abort(NOT_FOUND)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/paypal/billing-plans/create/<string:bptype>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _create_billing_plan(bptype):
    if not bptype.lower() in ['trial', 'regular']: abort(BAD_REQUEST)
    result = create_pp_billing_plan(bptype=bptype)
    if result.status_code in [OK, CREATED, NO_CONTENT]:
        try:
            try:
                payload = json.loads(result.content.decode('utf-8'))
            except:
                payload = json.loads(result.content)
            if DEBUG: print('{}: {}'.format(stack()[0][3], result.content))
            return jsonify(payload)
        except ValueError as e:
            print(repr(e))
            if DEBUG: print_exc()

    return json.dumps({'pp_status_code': result.status_code}), result.status_code


@application.route('/api/v{}/paypal/billing-plans/<string:bpid>/activate'.format(API_VERSION), methods=['GET'])
@requires_auth
def _activate_billing_plan(bpid):
    result = update_pp_billing_plan_status(id=bpid)
    if result.status_code in [OK, CREATED, NO_CONTENT]:
        try:
            try:
                payload = json.loads(result.content.decode('utf-8'))
            except:
                payload = json.loads(result.content)
            if DEBUG: print('{}: {}'.format(stack()[0][3], result.content))
            return jsonify(payload)
        except ValueError as e:
            print(repr(e))

    return json.dumps({'pp_status_code': result.status_code}), result.status_code


@application.route('/api/v{}/paypal/billing-plans/<string:bpid>/delete'.format(API_VERSION), methods=['GET'])
@requires_auth
def _delete_billing_plan(bpid):
    result = update_pp_billing_plan_status(id=bpid, status='DELETED')
    if result.status_code in [OK, CREATED, NO_CONTENT]:
        try:
            try:
                payload = json.loads(result.content.decode('utf-8'))
            except:
                payload = json.loads(result.content)
            if DEBUG: print('{}: {}'.format(stack()[0][3], result.content))
            return jsonify(payload)
        except ValueError as e:
            print(repr(e))

    return json.dumps(
        {'pp_status_code': result.status_code}
    ), result.status_code


@application.route('/api/v{}/paypal/billing-agreements/<string:payload>/create/<string:bptype>'.format(API_VERSION), methods=['GET'])
def _create_billing_agreement(payload, bptype):
    if not bptype.lower() in ['trial', 'regular']: abort(BAD_REQUEST)
    try:
        res = create_pp_billing_agreement(payload=payload, bptype=bptype)
        if res.status_code in [OK, CREATED, NO_CONTENT]:
            try:
                payload = json.loads(res.content.decode('utf-8'))
            except:
                payload = json.loads(res.content)
            location = [link['href'] for link in payload['links'] if link['rel'] == 'approval_url'][0]
            return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


# create regular PayPal subscription by clicking a web link
@application.route('/api/v{}/paypal/billing-agreement/create'.format(API_VERSION), methods=['GET'])
def _create_billing_agreement_by_link():
    try:
        data = {
            'i': generate_hash_key()[:32],
            'p': generate_hash_key()[:16],
            't': 'OTHER', 'u': ''
        }

        hdr = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[0]
        sig = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[2]
        payload = jwt.encode(data, data['p'], algorithm='HS256').decode('utf-8').split('.')[1]
        print('{}: hdr={} sig={} data={} payload={}'.format(
            stack()[0][3],
            hdr,
            sig,
            data,
            payload
        ))
        res = create_pp_billing_agreement(payload=payload, bptype='regular')
        if res.status_code in [OK, CREATED, NO_CONTENT]:
            try:
                payload = json.loads(res.content.decode('utf-8'))
            except:
                payload = json.loads(res.content)
            location = [link['href'] for link in payload['links'] if link['rel'] == 'approval_url'][0]
            return redirect(location, code=302)

    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


# PayPal call-back URL
@application.route('/api/v{}/paypal/billing-agreements/execute'.format(API_VERSION), methods=['GET'])
def _execute_billing_agreement():
    args = request.args.to_dict()
    if DEBUG: print('{}: {}'.format(stack()[0][3], args))
    try:
        # execute billing agreement and get billing agreement id and customer details
        token = args['token']
        res = execute_pp_billing_agreement(token=token)
        assert res.status_code in [OK, CREATED, NO_CONTENT]
        try:
            payload = json.loads(res.content.decode('utf-8'))
        except:
            payload = json.loads(res.content)
        description = payload['description']

        # check JWT token or use GUID
        try:
            hdr = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[0]
            sig = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[2]
            jwtoken = jwt.decode('{}.{}.{}'.format(hdr, description, sig), verify=False)
            print('{}: hdr={} sig={} jwt={}'.format(
                stack()[0][3],
                hdr,
                sig,
                jwtoken
            ))
            device_type = jwtoken['t']
            guid = jwtoken['i']
            tun_passwd = jwtoken['p']
            try:
                ip = socket.inet_ntoa(struct.pack('!L', int(jwtoken['u'])))
            except:
                ip = None

        except:
            guid = description
            device_type = None
            tun_passwd = None
            ip = None

        if DEBUG: print('{}: guid={} device_type={} ip={} tun_passwd={}'.format(
            stack()[0][3],
            guid,
            device_type,
            ip,
            tun_passwd
        ))

        baid = payload['id']
        payer_id = payload['payer']['payer_info']['payer_id']
        payer_email = payload['payer']['payer_info']['email']
        start_date = payload['start_date']
        payment_defs = payload['plan']['payment_definitions']
        if DEBUG: print('{}: token={} baid={} guid={} payer_id={} start_date={}'.format(
            stack()[0][3],
            token,
            baid,
            guid,
            payer_id,
            start_date
        ))

        # check subscription billing plan type
        bptype = 'REGULAR'
        for payment_def in payment_defs:
            if DEBUG: print('{}: payment_def={} type={}'.format(
                stack()[0][3],
                payment_def,
                payment_def['type']
            ))
            if payment_def['type'].upper() in ['TRIAL']:
                bptype = payment_def['type'].upper()
                break

        # subscription from DD-WRT or TOMATO router
        if device_type in ['DDWRT', 'DD-WRT', 'DD_WRT', 'TOMAT']:
            if bptype in ['REGULAR']:
                alert_type = 'success'
                if device_type in ['DDWRT', 'DD-WRT', 'DD_WRT']:
                    alert_msg = 'Subscribed successfully, dismiss alert to continue.'
                    location = 'http://{}/MyPage.asp?1&type={}&msg={}&billingid={}&payerid={}&payeremail={}'.format(
                        ip,
                        alert_type,
                        alert_msg,
                        baid,
                        payer_id,
                        payer_email
                    )
            else:
                # cancel billing agreement (TRIAL not supported on 'dumb' routers)
                if DEBUG: print('{}: bptype={} ip={}'.format(
                    stack()[0][3],
                    payment_def['type'],
                    ip
                ))
                res = cancel_pp_billing_agreement(id=baid)
                assert res.status_code in [OK, CREATED, NO_CONTENT]
                if DEBUG: print('cancel_pp_billing_agreement({}): {}'.format(baid, res))

                alert_type = 'warning'
                alert_msg = 'Free trial period is not available on {} device type.'.format(device_type)
                location = 'http://{}/?1&type={}&msg={}'.format(ip, alert_type, alert_msg)

            return redirect(location, code=302)

        # subscription from URL
        if device_type in ['OTHER']:
            if bptype in ['REGULAR']:
                alert_type = 'success'
                alert_msg = 'Subscribed successfully.'
                location = '{}/sub?type={}&msg={}&jwtoken={}&billing_id={}'.format(
                    BLACKBOX_RETURN_URL,
                    alert_type,
                    alert_msg,
                    description,
                    baid
                )
            else:
                # cancel billing agreement (TRIAL not supported)
                if DEBUG: print('{}: bptype={} ip={}'.format(
                    stack()[0][3],
                    payment_def['type'],
                    ip
                ))
                res = cancel_pp_billing_agreement(id=baid)
                assert res.status_code in [OK, CREATED, NO_CONTENT]
                if DEBUG: print('cancel_pp_billing_agreement({}): {}'.format(baid, res))

                alert_type = 'warning'
                alert_msg = 'Free trial period is not available on {} device type.'.format(device_type)
                location = '{}/sub?type={}&msg={}'.format(
                    BLACKBOX_RETURN_URL,
                    alert_type,
                    alert_msg
                )

            return redirect(location, code=302)

        # trial subscription from resin dot io device (legacy)
        trial_expired = False
        trial_start_date = start_date
        if bptype == 'TRIAL':
            res = get_resin_device_envs_by(guid)
            assert res.status_code in [OK]
            try:
                evs = json.loads(res.content.decode('utf-8'))
            except:
                evs = json.loads(res.content)
            # check if trial expired (existing device)
            for ev in evs['d']:
                if ev['env_var_name'] == 'PAYPAL_TRIAL_START_DATE':
                    trial_start_date = ev['value']
                    trial_expires = datetime.strptime(
                        trial_start_date,
                        '%Y-%m-%dT%H:%M:%SZ'
                    ) + timedelta(days=365/12)
                    today = datetime.utcnow()
                    if today > trial_expires: trial_expired = True
                    break

            # record trial start date
            res = create_update_resin_device_env(
                guid=guid,
                name='PAYPAL_TRIAL_START_DATE',
                value=trial_start_date
            )

            if DEBUG: print('{}: guid={} trial_start_date={}'.format(
                stack()[0][3],
                guid,
                trial_start_date
            ))

        if trial_expired:
            # record expired buyer id
            res = create_update_resin_device_env(
                guid=guid,
                name='PAYPAL_TRIAL_EXPIRED',
                value=payer_id
            )

            if DEBUG: print('{}: guid={} payer_id={}'.format(
                stack()[0][3],
                guid,
                payer_id
            ))

            # cancel billing agreement
            if DEBUG: print('{}: baid={} payer_id={} today={} trial_expires={} trial_expired={} trial_start_date={}'.format(
                stack()[0][3],
                baid,
                payer_id,
                today,
                trial_expires,
                trial_expired,
                trial_start_date
            ))

            res = cancel_pp_billing_agreement(id=baid)
            assert res.status_code in [OK, CREATED, NO_CONTENT]
            if DEBUG: print('cancel_pp_billing_agreement({}): {}'.format(baid, res))

            # default to regular subscription
            location = '{}/?guid={}&result=402'.format(BLACKBOX_RETURN_URL, guid)
            return redirect(location, code=302)

        # return to dashboard
        location = '{}/?guid={}&result=200'.format(BLACKBOX_RETURN_URL, guid)

        time.sleep(5) # wait 5 seconds for PayPal WebHook to fire (unreliable)
        return redirect(location, code=302)

    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


# PayPal call-back URL (payment flow errors or user abort)
@application.route('/api/v{}/paypal/billing-agreements/cancel'.format(
    API_VERSION
), methods=['GET'])
def __cancel_billing_agreement__():
    args = request.args.to_dict()
    if DEBUG: print('{}: {}'.format(stack()[0][3], args))
    return redirect('http://{}/'.format(LOCAL_DEVICE, code=302))


@application.route('/api/v{}/paypal/billing-agreements/<string:baid>/cancel'.format(
    API_VERSION
), methods=['GET'])
@requires_auth
def _cancel_billing_agreement(baid):
    if not baid: abort(BAD_REQUEST)
    result = cancel_pp_billing_agreement(id=baid)

    if result.status_code in [OK, CREATED, NO_CONTENT]:
        try:
            try:
                payload = json.loads(result.content.decode('utf-8'))
            except:
                payload = json.loads(result.content)
            if DEBUG: print('{}: {}'.format(stack()[0][3], result.content))
            return jsonify(payload)
        except ValueError as e:
            print(repr(e))
            if DEBUG: print_exc()

    return json.dumps({'pp_status_code': result.status_code}), result.status_code


# PayPal call-back URL, WebHook(s)
@application.route('/api/v{}/paypal/webhook'.format(API_VERSION), methods=['POST'])
def _paypal_webhook_receive():
    try:
        headers = request.headers.__dict__
        request.get_data()
        try:
            raw_post_body = request.data.decode('utf-8')
        except:
            raw_post_body = request.data
        json_post_body = json.loads(request.data)

        if DEBUG:
            print('request.headers.__dict__: {}'.format(headers))
            print('{}: {}'.format(stack()[0][3], json_post_body))

        res = True
        if PAYPAL_VERIFY_WEBHOOK:
            if DEBUG:
                print('WebhookEvent.verify({}, {}, {}, {}, {}, {}, {})'.format(
                    headers['environ']['HTTP_PAYPAL_TRANSMISSION_ID'],
                    headers['environ']['HTTP_PAYPAL_TRANSMISSION_TIME'],
                    PAYPAL_WEBHOOK_ID,
                    raw_post_body,
                    headers['environ']['HTTP_PAYPAL_CERT_URL'],
                    headers['environ']['HTTP_PAYPAL_TRANSMISSION_SIG'],
                    headers['environ']['HTTP_PAYPAL_AUTH_ALGO']
                ))
            res = WebhookEvent.verify(
                headers['environ']['HTTP_PAYPAL_TRANSMISSION_ID'],
                headers['environ']['HTTP_PAYPAL_TRANSMISSION_TIME'],
                PAYPAL_WEBHOOK_ID,
                raw_post_body,
                headers['environ']['HTTP_PAYPAL_CERT_URL'],
                headers['environ']['HTTP_PAYPAL_TRANSMISSION_SIG'],
                headers['environ']['HTTP_PAYPAL_AUTH_ALGO']
            )

            print('WebhookEvent.verify: {}'.format(res))

        if not res: return json.dumps({'WebhookEvent.verify': res}), 401

        try:
            description = json_post_body['resource']['description']
        except KeyError as e:
            print(repr(e))
            if DEBUG: print_exc()
            return jsonify(json_post_body)

        try:
            # check for JWT token
            try:
                hdr = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[0]
                sig = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[2]
                jwtoken = jwt.decode(
                    '{}.{}.{}'.format(
                        hdr,
                        description,
                        sig
                    ),
                    verify=False
                )
                guid = jwtoken['i']
                device_type = jwtoken['t']
                print('{}: hdr={} sig={} jwt={}'.format(
                    stack()[0][3],
                    hdr,
                    sig,
                    jwtoken
                ))
            except Exception as e:
                print(repr(e))
                if DEBUG: print_exc()
                device_type = None
                guid = description

            baid = json_post_body['resource']['id']
            start_date = json_post_body['resource']['start_date']
            payer_id = json_post_body['resource']['payer']['payer_info']['payer_id'].upper()
            email = json_post_body['resource']['payer']['payer_info']['email']
            evtid = json_post_body['id']
            payment_defs = json_post_body['resource']['plan']['payment_definitions']
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()
            return jsonify(raw_post_body)

        # nothing further to do for router devices or web subscriptions
        if device_type in ['DD-WRT', 'DDWRT', 'DD_WRT', 'OTHER', 'TOMAT']:
            return jsonify(raw_post_body)

        # resin dot io device, continue with processing
        bptype = 'REGULAR'
        for payment_def in payment_defs:
            if payment_def['type'].upper() in ['TRIAL']:
                bptype = payment_def['type'].upper()
                break

        res = get_resin_device_envs_by(guid)
        assert res.status_code in [OK]
        try:
            evs = json.loads(res.content.decode('utf-8'))
        except:
            evs = json.loads(res.content)

        if json_post_body['event_type'] in [
            'BILLING.SUBSCRIPTION.CREATED',
            'BILLING.SUBSCRIPTION.RE-ACTIVATED',
            'BILLING.SUBSCRIPTION.UPDATED'
        ]:
            original_start_date = None
            for ev in evs['d']:
                if ev['env_var_name'] == 'PAYPAL_TRIAL_START_DATE':
                    original_start_date = ev['value']
                    break

            # keep original trial date from previous device(s)
            if original_start_date and bptype in ['TRIAL']:
                start_date = original_start_date

            for ev in [
                {'name': 'PAYPAL_PAYER_ID', 'value': payer_id},
                {'name': 'PAYPAL_PAYER_EMAIL', 'value': email},
                {'name': 'PAYPAL_BILLING_AGREEMENT_START_DATE', 'value': start_date},
                {'name': 'PAYPAL_BILLING_AGREEMENT', 'value': baid}
            ]:
                res = create_update_resin_device_env(
                    guid=guid,
                    name=ev['name'],
                    value=ev['value']
                )

            return jsonify({
                'GUID': guid,
                'PAYPAL_BILLING_PLAN_TYPE': bptype,
                'PAYPAL_PAYER_ID': payer_id,
                'PAYPAL_PAYER_EMAIL': email,
                'PAYPAL_BILLING_AGREEMENT_START_DATE': start_date,
                'PAYPAL_BILLING_AGREEMENT': baid
            })

        elif json_post_body['event_type'] in [
            'BILLING.SUBSCRIPTION.CANCELLED',
            'BILLING.SUBSCRIPTION.SUSPENDED'
        ]:
            response = {'GUID': guid}
            for ev in evs['d']:
                if ev['env_var_name'] == 'PAYPAL_BILLING_AGREEMENT' and ev['value'] == baid:
                    # delete env var
                    res = delete_resin_device_env_by_name(
                        guid=guid,
                        name='PAYPAL_BILLING_AGREEMENT'
                    )
                    response['PAYPAL_BILLING_AGREEMENT'] = baid
                    break
            return jsonify(response)
        else:
            return jsonify(raw_post_body)

    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)



#################
# Bitcoin views #
#################
@application.route('/api/v{}/bitcoin/btc_price/<string:currency>'.format(API_VERSION))
def _blocktrail_btc_price(currency):
    try:
        btc_price = get_btc_price(currency=currency)
        return jsonify(btc_price)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/bitcoin/payment_address/guid/<string:guid>'.format(API_VERSION))
@requires_auth
def _blockcypher_new_payment_address(guid):
    try:
        (payment_address, webhook_id) = generate_new_payment_address(guid=guid)

        return jsonify({
            'payment_address': payment_address,
            'webhook_id': webhook_id
        })
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/blockcypher/webhook/{}'.format(API_VERSION, BLOCKCYPHER_WEBHOOK_TOKEN), methods=['POST'])
def _blockcypher_webhook_receive():
    try:
        headers = request.headers.__dict__
        request.get_data()
        raw_post_body = request.data
        json_post_body = json.loads(request.data)

        if DEBUG:
            print('request.headers.__dict__: {}'.format(headers))
            print('{}: {}'.format(stack()[0][3], json_post_body))

        if headers['environ']['HTTP_X_EVENTTYPE'] in ['confirmed-tx', 'unconfirmed-tx']:
            devices = get_resin_devices()
            assert devices.status_code in [OK]
            try:
                devices = json.loads(devices.content.decode('utf-8'))
            except:
                devices = json.loads(devices.content)

            (payment_address, guid, btc_amount) = [(
                out['addresses'][0],
                cache_get(key=out['addresses'][0]),
                int(out['value'])
            ) for out in json_post_body['outputs'] if cache_get(key=out['addresses'][0])][0]

            last_payment_date = datetime.strftime(
                datetime.utcnow(),
                '%Y-%m-%dT%H:%M:%SZ'
            )
            transaction_id = json_post_body['hash']
            confirmation = json_post_body['confirmations']

            try:
                guid = guid.decode('utf-8')
            except:
                pass

            last_txn_id = get_resin_device_env_by_name(
                guid=guid,
                name='BITCOIN_LAST_TRANSACTION_ID'
            )

            confirmations = confirmation + int(
                get_resin_device_env_by_name(
                    guid=guid,
                    name='BITCOIN_CONFIRMATIONS',
                    default=0
                )
            )
            res = create_update_resin_device_env(
                guid=guid,
                name='BITCOIN_CONFIRMATIONS',
                value=str(confirmations)
            )

            if DEBUG: print('{}: guid={} payment_address={} btc_amount={} last_payment_date={} hash={} last_hash={} conf={} confs={}'.format(
                stack()[0][3],
                guid,
                payment_address,
                btc_amount,
                last_payment_date,
                transaction_id,
                last_txn_id,
                confirmation,
                confirmations
            ))

            if guid and last_txn_id != transaction_id:
                # calculate new expiry date if a new payment arrives
                prev_last_payment_date = get_resin_device_env_by_name(guid=guid, name='BITCOIN_LAST_PAYMENT_DATE')
                prev_last_payment_amount = get_resin_device_env_by_name(guid=guid, name='BITCOIN_LAST_PAYMENT_AMOUNT')
                btc_daily_amount = get_resin_device_env_by_name(guid=guid, name='BITCOIN_DAILY_AMOUNT')

                if prev_last_payment_date and prev_last_payment_amount and btc_daily_amount:
                    btc_expiry_date = datetime.strptime(prev_last_payment_date, '%Y-%m-%dT%H:%M:%SZ') + timedelta(days=float(prev_last_payment_amount) / float(btc_daily_amount))
                    today = datetime.utcnow()

                    if today <= btc_expiry_date:
                        remain_days = float(timedelta(seconds=(btc_expiry_date - today).total_seconds()).total_seconds()) / float(86400)
                        remain_amount = int(float(remain_days) * int(btc_daily_amount))
                        btc_amount = btc_amount + remain_amount

                        msg = '{}: prev_last_payment_date={} prev_last_payment_amount={} btc_daily_amount={} btc_expiry_date={} remain_days={} remain_amount={} btc_amount={}'.format(
                            stack()[0][3],
                            prev_last_payment_date,
                            prev_last_payment_amount,
                            btc_daily_amount,
                            btc_expiry_date,
                            remain_days,
                            remain_amount,
                            btc_amount
                        )

                for ev in [
                    {'name': 'BITCOIN_LAST_PAYMENT_AMOUNT', 'value': str(btc_amount)},
                    {'name': 'BITCOIN_LAST_PAYMENT_DATE', 'value': last_payment_date},
                    {'name': 'BITCOIN_LAST_TRANSACTION_ID', 'value': transaction_id}
                ]:
                    res = create_update_resin_device_env(
                        guid=guid,
                        name=ev['name'],
                        value=ev['value']
                    )

                response = {
                    'GUID': guid,
                    'BITCOIN_LAST_TRANSACTION_ID': transaction_id,
                    'BITCOIN_LAST_PAYMENT_DATE': last_payment_date,
                    'BITCOIN_PAYMENT_ADDRESS': payment_address,
                    'BITCOIN_LAST_PAYMENT_AMOUNT': btc_amount
                }

                body = json.dumps(
                    {
                        'WebHook': json_post_body,
                        'api_response': response
                    },
                    indent=4
                )

                print('body={}'.format(body))

                background_smtp_send(
                    subject='{} payment of {} Satoshi received from {}'.format(
                        BLOCKCYPHER_COIN_SYMBOL,
                        btc_amount,
                        guid
                    ),
                    body=body,
                    preamble='Bitcoin payment notification'
                )
                return jsonify(response)
        return jsonify(json_post_body)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)



##################
# resin.io views #
##################
@application.route('/api/v{}/devices/purge/<string:app_id>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _purge_expired_devices(app_id):
    try:
        expired_devices = purge_resin_devices(app_id=app_id)
        return jsonify(expired_devices)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/device/<string:guid>'.format(API_VERSION), methods=['GET', 'POST'])
@requires_auth
def _get_resin_device(guid):
    device = None
    try:
        device = get_resin_device(guid=guid)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if device:
        return jsonify(device)
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/device/<string:guid>/<string:action>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _device_action(guid, action):
    if action not in ['restart', 'reboot', 'shutdown']: abort(BAD_REQUEST)
    try:
        res = resin_device_action(guid=guid, action=action)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    try:
        return jsonify(res.content.decode('utf-8')), res.status_code
    except:
        return jsonify(res.content), res.status_code


@application.route('/api/v{}/device/<string:guid>/env'.format(API_VERSION), methods=['PUT'])
@requires_auth
def _put_device_env(guid):
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    devices = get_resin_devices()
    if devices.status_code in [OK]:
        try:
            devices = json.loads(devices.content.decode('utf-8'))
        except:
            devices = json.loads(devices.content)
    else:
        abort(devices.status_code)
    for device in devices['d']:
        if device['uuid'].startswith(guid):
            try:
                data = json.loads(request.data.decode('utf-8'))
            except:
                data = json.loads(request.data)
            data['device'] = device['id']
            res = post_resin_device_env(payload=data)
            if res.status_code in [CREATED]:
                try:
                    return jsonify(json.loads(res.content.decode('utf-8')))
                except:
                    return jsonify(json.loads(res.content))
            else:
                abort(CONFLICT)
    abort(NOT_FOUND)


@application.route('/api/v{}/env/<int:env_id>/dev/<string:device_id>'.format(API_VERSION), methods=['PATCH'])
@requires_auth
def _patch_device_env(env_id, device_id):
    try:
        data = json.loads(request.data.decode('utf-8'))
    except:
        data = json.loads(request.data)
    res = patch_resin_device_env(device_id=device_id, env_id=env_id, payload=data)
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    return json.dumps({'resin_status_code': res.status_code}), res.status_code


@application.route('/api/v{}/env/<int:env_id>/dev/<string:device_id>'.format(API_VERSION), methods=['DELETE'])
@requires_auth
def _delete_device_env(env_id, device_id):
    res = delete_resin_device_env(device_id=device_id, env_id=env_id)
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    return json.dumps({'resin_status_code': res.status_code}), res.status_code


@application.route('/api/v{}/device/<string:guid>/env/<string:name>'.format(API_VERSION), methods=['DELETE'])
@requires_auth
def _delete_device_env_by_name(guid, name):
    res = delete_resin_device_env_by_name(guid=guid, name=name)
    if not res: return json.dumps({'delete_resin_device_env_by_name': res}), OK
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    return json.dumps({'resin_status_code': res.status_code}), res.status_code


@application.route('/api/v{}/device/<string:guid>/env'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_device_envs(guid):
    try:
        res = get_resin_device_envs_by(guid)
        assert res.status_code in [OK]
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/device/<string:guid>/env/<string:name>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_device_env_by_name(guid, name):
    try:
        guid = guid.decode('utf-8')
    except:
        pass
    devices = get_resin_devices()
    if devices.status_code in [OK]:
        try:
            devices = json.loads(devices.content.decode('utf-8'))
        except:
            devices = json.loads(devices.content)
    else:
        abort(devices.status_code)
    for device in devices['d']:
        if device['uuid'].startswith(guid):
            id = device['id']
            res = get_resin_device_env(id)
            if res.status_code in [OK]:
                try:
                    evs = json.loads(res.content.decode('utf-8'))
                except:
                    evs = json.loads(res.content)
            else:
                abort(res.status_code)
            for ev in evs['d']:
                if ev['env_var_name'] == name:
                    return ev['value']
            abort(NOT_FOUND)
    abort(NOT_FOUND)


@application.route('/api/v{}/app/<int:id>/env'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_app_env(id):
    res = get_resin_app_env(id)
    if res.status_code in [OK]:
        try:
            return jsonify(json.loads(res.content.decode('utf-8')))
        except:
            return jsonify(json.loads(res.content))
    else:
        abort(res.status_code)
    abort(NOT_FOUND)


@application.route('/api/v{}/app/<int:id>/env/<string:name>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_app_env_by_name(id, name):
    res = get_resin_app_env(id)
    if res.status_code in [OK]:
        try:
            evs = json.loads(res.content.decode('utf-8'))
        except:
            evs = json.loads(res.content)
    else:
        abort(res.status_code)
    for ev in evs['d']:
        if ev['name'] == name:
            return ev['value']
    abort(NOT_FOUND)



##################
# MySQL DB views #
##################
@application.route(
    '/api/v{}/countries/<string:mask>'.format(API_VERSION),
    methods=['GET']
)
@requires_auth
def _get_countries(mask):
    try:
        return jsonify(get_countries(mask=mask))
    except:
        abort(NOT_FOUND)


@application.route('/api/v{}/device/<int:type>/<string:guid>/<int:proto>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_device(type, guid, proto):
    if proto not in PROTO_TYPES: abort(BAD_REQUEST)
    if type not in DEVICE_TYPES: abort(BAD_REQUEST)
    result = None
    try:
        sql = '''
SELECT *
FROM device
WHERE SUBSTRING(guid,1,32)=:guid
AND type=:type
AND proto=:proto
AND dt >= DATE_SUB(NOW(), INTERVAL {} second)
ORDER BY id DESC
LIMIT 1'''.format(STALE_NODE_THSHLD)

        result = session.execute(
            text(sql),
            {
                'guid': guid[:32],
                'type': type,
                'proto': proto
            }
        )
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if result.rowcount > 0:
        return json.dumps([dict(row._mapping) for row in result][0], default=str)
    else:
        abort(NOT_FOUND)

@application.route(
    '/api/v{}/device/<int:type>/<string:guid>/<int:proto>'.format(
        API_VERSION),
    methods=['PUT']
)
@requires_auth
def _put_device(type, guid, proto):
    if proto not in PROTO_TYPES: abort(BAD_REQUEST)
    if type not in DEVICE_TYPES: abort(BAD_REQUEST)
    result = None
    data = None
    if DEBUG: print('{}: {}'.format(stack()[0][3], request.data))
    try:
        try:
            data = json.loads(request.data.decode('utf-8'))
        except:
            data = json.loads(request.data)

        country = data['country']
        try:
            assert data['city']
            city = data['city']
        except:
            # city is missing from geo-ip response
            data['city'] = country

        try:
            data['country'] = country.encode('utf8')
            data['city'] = city.encode('utf8')
        except:
            pass

        for opt in [
            'cipher',
            'auth',
            'upnp',
            'hostapd',
            'ip',
            'status',
            'bytesin',
            'bytesout',
            'conns',
            'country',
            'city'
        ]:
            if opt not in data: data[opt] = None

        result = Device(
            func.now(),
            guid,
            type,
            proto,
            data['ip'],
            data['country'],
            data['city'],
            data['conns'],
            data['weight'],
            data['bytesin'],
            data['bytesout'],
            data['status'],
            data['cipher'],
            data['auth'],
            data['upnp'],
            data['hostapd']
        )

        session.add(result)
        session.commit()
        return jsonify(result.guid)
    except Exception as e:
        session.rollback()
        print(repr(e))
        abort(BAD_REQUEST)


def __get_nodes(limit=1, proto=4, country=TARGET_COUNTRY, client_ip='127.0.0.1'):
    try:
        results = pickle.loads(
            cache_get(
                key='nodes:1:{}:{}:{}'.format(
                    proto,
                    country,
                    client_ip
                )
            )
        )
    except:
        results = None
        print(
            '{}: cache-miss'.format(
                stack()[0][3]
            )
        )
    if results: return results

    try:
        sql = '''
SELECT ip FROM
(
    SELECT max(dt) as dt, ip, (conns/weight) AS weight
    FROM device
    WHERE (type=1 OR type=3)
    AND status >= 1
    AND proto=:proto
    AND country=:country
    AND dt >= DATE_SUB(NOW(), INTERVAL {} second)
    GROUP BY ip
    ORDER BY weight ASC
) AS weighted
LIMIT {}'''.format(STALE_NODE_THSHLD, limit)

        results = session.execute(
            text(sql),
            {
                'proto': proto,
                'country': country
            }
        ).fetchall()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()

    try:
        cache_set(
            key='nodes:1:{}:{}:{}'.format(
                proto,
                country,
                client_ip
            ),
            value=pickle.dumps(results),
            ttl=60
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()

    return results


@application.route('/api/v{}/node/<int:proto>/country/<string:country>'.format(API_VERSION))
@requires_auth
def _get_public_node_by_country(proto, country):
    try:
        results = __get_nodes(
            proto=proto,
            country=country
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)
    if len(results) > 0:
        return results[0][0]
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/node/<int:proto>/country/<string:country>/geo/<string:ip>'.format(API_VERSION))
@requires_auth
def _get_public_closest_geo_node_by_country(proto, country, ip):
    try:
        results = __get_nodes(
            limit=3,
            proto=proto,
            country=country,
            client_ip=ip
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if len(results) > 1: # multiple nodes
        nodes = [r[0] for r in results]
        if DEBUG: print('nodes={}'.format(nodes))
        return get_closest_node(nodes=nodes, client_ip=ip)
    elif len(results) == 1: # single node
        return results[0][0]
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/node/<int:proto>/guid/<string:guid>'.format(API_VERSION))
@requires_auth
def _get_private_node_by_guid(proto, guid):
    node = None
    try:
        sql = '''
SELECT ip
FROM device
WHERE type=4
AND proto=:proto
AND SUBSTRING(guid,1,32)=:guid
AND dt >= DATE_SUB(NOW(), INTERVAL {} second)
ORDER BY conns ASC
LIMIT 1'''.format(STALE_NODE_THSHLD)

        result = session.execute(
            text(sql),
            {
                'proto': proto,
                'guid': guid[:32]
            }
        ).fetchall()
        if len(result) > 0: node = result[0][0]
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if not node:
        abort(NOT_FOUND)
    else:
        return node


@application.route('/api/v{}/ipaddr/<string:ip>/<int:family>'.format(API_VERSION))
@requires_auth
def _get_guid_by_public_ip(ip, family):
    guid = None
    try:
        sql = '''
SELECT guid
FROM device
WHERE ip=:ip
AND proto=:proto
ORDER BY dt ASC
LIMIT 1'''

        result = session.execute(text(sql), {'proto': family, 'ip': ip}).fetchall()
        if len(result) > 0:
            guid = result[0][0]
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if not guid:
        abort(NOT_FOUND)
    else:
        return guid


@application.route('/api/v{}/tests/<string:table>'.format(API_VERSION))
@requires_auth
def _get_test_table(table):
    result = None
    if table not in ['sessions', 'screenshots', 'nflx_video_diags', 'errors']: abort(BAD_REQUEST)
    try:
        sql = '''
SELECT *
FROM {}
ORDER BY id
DESC
LIMIT 1'''.format(table)

        result = session.execute(text(sql))
        if result.rowcount > 0:
            return json.dumps([dict(row._mapping) for row in result][0], default=str)
        else:
            abort(NOT_FOUND)
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/screenshot/<string:alpha>'.format(API_VERSION))
@requires_auth
def _get_test_screenshot(alpha):
    result = None
    try:
        sql = '''
SELECT ses.host, scr.*
FROM screenshots scr, sessions ses
WHERE ses.id = scr.session_id
AND ses.host=:alpha
ORDER BY scr.id DESC
LIMIT 1'''

        result = session.execute(text(sql), {'alpha': alpha.upper()})
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if result.rowcount > 0:
        return json.dumps([dict(row._mapping) for row in result][0], default=str)
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/screenshot/tags/<int:limit>'.format(API_VERSION))
@requires_auth
def _get_test_tag_screenshots(limit):
    result = None
    try:
        sql = '''
SELECT ses.host, ses.tag, scr.*
FROM screenshots AS scr
LEFT JOIN sessions AS ses ON ses.id = scr.session_id
WHERE
    scr.id = (
        SELECT MAX(id)
            FROM screenshots
            WHERE session_id = ses.id
    )
ORDER BY scr.ts DESC
LIMIT :limit
'''

        result = session.execute(text(sql), {'limit': limit})
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if result.rowcount > 0:
        return json.dumps([dict(row._mapping) for row in result][0], default=str)
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/speedtest/<string:guid>'.format(API_VERSION), methods=['HEAD'])
@requires_auth
def _dequeue_speedtest(guid):
    result = dict()
    try:
        sql = '''
SELECT dt, status, up, down
FROM speedtest
WHERE SUBSTRING(guid,1,32)=:guid
AND status IS NULL
ORDER BY dt DESC
LIMIT 1'''

        result = session.execute(text(sql), {'guid': guid[:32]})
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if result.rowcount > 0:
        return ('', NO_CONTENT)
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/speedtest/<string:guid>'.format(API_VERSION))
@requires_auth
def _get_speedtest(guid):
    result = dict()
    try:
        sql = '''
SELECT dt, status, up, down
FROM speedtest
WHERE SUBSTRING(guid,1,32)=:guid
AND status IS NOT NULL
ORDER BY dt DESC
LIMIT 1'''

        result = session.execute(text(sql), {'guid': guid[:32]})
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if result.rowcount > 0:
        return json.dumps([dict(row._mapping) for row in result][0], default=str)
    else:
        abort(NOT_FOUND)


@application.route('/api/v{}/speedtest/<string:guid>'.format(API_VERSION), methods=['PATCH'])
@requires_auth
def _update_speedtest(guid):
    data = None
    request.get_data()
    raw_post_body = request.data
    try:
        data = json.loads(request.data.decode('utf-8'))
    except:
        data = json.loads(request.data)
    if DEBUG: print('{}: {}'.format(stack()[0][3], data))
    if not data: abort(BAD_REQUEST)

    result = None
    try:
        sql = '''
SELECT id
FROM speedtest
WHERE SUBSTRING(guid,1,32)=:guid
AND status IS NULL
ORDER BY dt ASC
LIMIT 1'''

        result = session.execute(text(sql), {'guid': guid[:32]})
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if DEBUG: print('{}: {}'.format(stack()[0][3], result))
    if result.rowcount <= 0: abort(NOT_FOUND)
    speedtest_id = [row for row in result.mappings()][0]['id']

    result = None
    try:
        query = Speedtest.__table__.update().where(
            Speedtest.id==speedtest_id
        ).where(
            Speedtest.guid==guid[:32]
        ).values(
            down=data['down'],
            up=data['up'],
            status=data['status'],
            dt=func.now()
        )
        result = session.execute(query)
        session.commit()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    return jsonify(result.rowcount)


@application.route('/api/v{}/speedtest/<string:guid>'.format(API_VERSION), methods=['PUT'])
@requires_auth
def _queue_speedtest(guid):
    try:
        result = Speedtest(func.now(), guid[:32], None, None, None)
        session.add(result)
        session.commit()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    return jsonify(guid)


@application.route('/api/v{}/device/<int:type>/<string:guid>/<int:proto>/stats'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_device_stats(type, guid, proto):
    if proto not in PROTO_TYPES: abort(BAD_REQUEST)
    if type not in DEVICE_TYPES: abort(BAD_REQUEST)
    result = None
    try:
        sql = '''
SELECT
    dt
   ,ABS(IFNULL(IF(bytesin - IFNULL(
        (SELECT MAX(bytesin) FROM device WHERE guid = t1.guid AND (dt < t1.dt)), 0) < 0
       ,(SELECT MIN(bytesin) FROM device WHERE guid = t1.guid AND (dt > t1.dt)) - bytesin
       ,bytesin - IFNULL(
           (SELECT MAX(bytesin) FROM device WHERE guid = t1.guid AND (dt < t1.dt)), 0)
    ), 0)) AS bytesin
   ,ABS(IFNULL(IF(bytesout - IFNULL(
        (SELECT MAX(bytesout) FROM device WHERE guid = t1.guid AND (dt < t1.dt)), 0) < 0
       ,(SELECT MIN(bytesout) FROM device WHERE guid = t1.guid AND (dt > t1.dt)) - bytesout
       ,bytesout - IFNULL(
           (SELECT MAX(bytesout) FROM device WHERE guid = t1.guid AND (dt < t1.dt)), 0)
    ), 0)) AS bytesout
FROM device AS t1
WHERE SUBSTRING(guid,1,32)=:guid
AND proto=:proto
AND type=:type
ORDER BY dt;'''

        results = session.execute(
            text(sql),
            {
                'guid': guid[:32],
                'type': type,
                'proto': proto
            }
        )
        if results.rowcount > 0:
            return json.dumps([dict(row._mapping) for row in results], default=str)
        else:
            abort(NOT_FOUND)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


################
# DD-WRT views #
################
@application.route('/api/v{}/vpnprovider/groups'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_vpn_provider_groups():
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    try:
        return jsonify(provider_groups())
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/vpnproviders'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_vpn_providers():
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    try:
        return jsonify(providers_by_group())
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/vpnproviders/group/<string:group>'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_vpn_providers_by(group):
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    groups = provider_groups()
    if group not in groups: group = 'default'

    try:
        return jsonify(providers_by_group(group=group))
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/vpnprovider/<string:provider>/groups'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_location_groups_by(provider):
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    try:
        return jsonify(location_groups_by_provider(provider=provider))
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route('/api/v{}/vpnprovider/<string:provider>/usercert'.format(API_VERSION), methods=['GET', 'OPTIONS'])
@add_cors_header
def _get_client_cert_required(provider):
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    try:
        return jsonify(client_cert_required(provider=provider))
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route(
    '/api/v{}/vpnprovider/<string:provider>/group/<string:group>/locations'.format(
        API_VERSION
    ),
    methods=['GET', 'OPTIONS']
)
@application.route(
    '/api/v{}/vpnprovider/<string:provider>/group/<string:group>/locations/<string:sort>'.format(
        API_VERSION
    ),
    methods=['GET', 'OPTIONS']
)
@application.route(
    '/api/v{}/vpnprovider/<string:provider>/group/<string:group>/locations/<string:sort>/lat/<string:lat>/lon/<string:lon>'.format(
        API_VERSION
    ),
    methods=['GET', 'OPTIONS']
)
@add_cors_header
def _get_locations_by(provider, group, sort=None, lat=None, lon=None):
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    try:
        return jsonify(
            locations_by_provider(
                provider=provider,
                group=group,
                sort=sort,
                lat=lat,
                lon=lon
            )
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route(
    '/api/v{}/vpnprovider/<string:provider>/group/<string:group>/name/<string:name>/profile'.format(
        API_VERSION
    ),
    methods=['GET', 'OPTIONS']
)
@add_cors_header
@add_download_headers
def _get_vpn_profile_by(provider, group, name):
    if request.method == 'OPTIONS': return ('', NO_CONTENT)
    result = None
    try:
        result = generate_ovpn_profile(provider=provider, group=group, name=name)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if not result: abort(NOT_FOUND)
    return result


@application.route(
    '/api/v{}/ddwrt/group/<string:group>/provider/<string:provider>/install'.format(API_VERSION), methods=['GET', 'HEAD']
)
@application.route(
    '/ddwrt', methods=['GET', 'HEAD'],
    defaults={'group': 'default', 'provider': 'blackbox'}
)
def _install_ddwrt_app(provider, group):
    args = request.args.to_dict()
    headers = dict(request.headers)
    if DEBUG: print('args={} headers={}'.format(args, headers))

    try:
        dev = args['dev']
    except:
        dev = 0

    fetch_git_repo()
    fetch_git_repo(
        dir=VPN_PROVIDERS_GIT_DIR,
        url=VPN_PROVIDERS_GIT_URL,
        tag=VPN_PROVIDERS_GIT_TAG
    )

    tmpl = None
    try:
        tmpl = open(
            '{}/install.sh.template'.format(
                DDWRT_GIT_DIR
            )
        ).read()
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(INTERNAL_SERVER_ERROR)

    try:
        host = headers['X-Forwarded-For']
    except:
        try:
            host = headers['Host']
        except:
            host = LOCAL_DEVICE

    host = host.split(':')[:1][0]
    logo = LOGO
    try:
        path = '{}/{}/img'.format(
            DDWRT_GIT_DIR,
            DDWRT_APP
        )
        for png in glob('{}/*.png'.format(path)):
            filename = png.split('/')[-1:][0]
            file_sans_ext = filename.split('.')[:1][0]
            m = re.search(file_sans_ext, host)
            try:
                assert m.group(0)
                assert os.path.exists(png)
                logo = 'user/img/{}'.format(filename)
                break
            except:
                if DEBUG: print('file_sans_ext={} host={}'.format(
                    file_sans_ext,
                    host
                ))
    except:
        if DEBUG: print_exc()

    if DEBUG: print('host={} path={} png={} logo={} filename={}'.format(
        host,
        path,
        png,
        logo,
        filename
    ))

    tmpl = tmpl.replace('{{API_HOST}}', API_HOST)
    tmpl = tmpl.replace('{{API_VERSION}}', API_VERSION)
    tmpl = tmpl.replace('{{APP}}', DDWRT_APP)
    tmpl = tmpl.replace('{{TAG}}', DDWRT_GIT_TAG)
    tmpl = tmpl.replace('{{DEV}}', str(dev))
    tmpl = tmpl.replace('{{COMMIT}}', get_last_commit())
    tmpl = tmpl.replace('{{BOOTSTRAP_CSS}}', BOOTSTRAP_CSS)
    tmpl = tmpl.replace('{{LOGO}}', logo)

    if provider in providers_by_group():
        tmpl = tmpl.replace('{{DEFAULT_PROVIDER}}', provider)
    else:
        tmpl = tmpl.replace('{{DEFAULT_PROVIDER}}', 'default')

    if group in provider_groups():
        tmpl = tmpl.replace('{{DEFAULT_PROVIDER_GROUP}}', group)
    else:
        tmpl = tmpl.replace('{{DEFAULT_PROVIDER_GROUP}}', 'default')

    return Response(tmpl, mimetype='application/x-sh')


@application.route('/api/v{}/ddwrt/download'.format(API_VERSION), methods=['GET', 'HEAD'])
def _download_ddwrt_app():
    fetch_git_repo()
    return Response(stream_tar_gz(), mimetype='application/gzip')


@application.route('/', methods=['GET'])
def _ddwrt_mypage_redirect():
    if request.host.startswith('dd-wrt'):
        return redirect('http://dd-wrt./MyPage.asp', code=FOUND)
    else:
        return redirect('http://unzoner.com/', code=FOUND)


@requires_auth
@application.route(
    '/api/v{}/vpnprovider/<string:provider>/update'.format(
        API_VERSION
    ),
    methods=['GET']
)
def _update_vpn_profiles(provider):
    providers = providers_by_group()
    provider = [
        p for p in providers_by_group()
        if provider.lower() == p.lower()
    ][0]
    assert provider

    class Args():
        def __init__(self, provider):
            self.provider = provider

    args = Args(provider)
    try:
        return jsonify(main(args=args))
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@application.route(
    '/api/v{}/ddwrt/version'.format(
        API_VERSION
    ),
    methods=['GET', 'HEAD', 'OPTIONS']
)
@application.route(
    '/api/v{}/ddwrt/guid/<string:guid>/version'.format(
        API_VERSION
    ),
    methods=['GET', 'HEAD', 'OPTIONS']
)
@add_cors_header
def _get_last_commit(guid=None):
    try:
        return jsonify(
            {
                'version': get_last_commit()
            }
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)



#################
# Utility views #
#################
@application.route(
    '/api/v{}/country/<string:country>'.format(
        API_VERSION
    ),
    methods=['GET']
)
@requires_auth
def _get_country_alpha2(country):
    try:
        return get_country_alpha2(name=country).upper()
    except:
        abort(NOT_FOUND)


@application.route(
    '/api/v{}/countries/available/flags.png'.format(
        API_VERSION
    ),
    methods=['GET']
)
@add_cache_control_max_age_1hr
def _available_country_flags_image():
    images = list(map(
        Image.open,
        [
            '{}/{}/{}.png'.format(
                COUNTRY_FLAGS_DIR,
                COUNTRY_FLAGS_SIZE,
                country['alpha2']
            )
            for country in get_countries(mask='available')
        ]
    ))
    scale_factor = 2
    widths, heights = zip(*(i.size for i in images))
    total_width = sum(widths) / scale_factor
    max_height = max(heights) / scale_factor
    canvas = Image.new(
        'RGBA',
        (
            int(total_width + (len(images) * (10 / scale_factor)) + (10 / scale_factor)),
            int(max_height + (20 / scale_factor))
        )
    )
    x_offset = int(10 / scale_factor)
    for img in images:
        new_width  = int(img.size[0] / scale_factor)
        new_height = int(new_width * img.size[1] / img.size[0])
        img = img.resize((new_width, new_height), Image.ANTIALIAS)
        canvas.paste(
            img,
            (
                x_offset,
                int(((max_height + (20 / scale_factor)) - img.size[1]) / 2)
            )
        )
        x_offset += int(img.size[0] + (10 / scale_factor))
    try:
        imgstream = StringIO()
        canvas.save(imgstream, format='PNG')
        response = make_response(imgstream.getvalue())
    except:
        with BytesIO() as imgstream:
            canvas.save(imgstream, format='PNG')
            response = make_response(imgstream.getvalue())
    response.mimetype = 'image/png'
    return response


@application.route('/api/v{}/alpha/<string:alpha>/asns/<string:services>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_asns(alpha, services):
    try:
        services = services.split(',')
        asns = ' '.join([BLACKBOX[alpha.upper()][service]['ASN'] for service in BLACKBOX[alpha.upper()] if service in services and 'ASN' in BLACKBOX[alpha.upper()][service].keys()]).replace(',', ' ')
        return asns
    except KeyError:
        abort(NOT_FOUND)


@application.route('/api/v{}/alpha/<string:alpha>/domains/<string:services>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_domains(alpha, services):
    try:
        services = services.split(',')
        domains = ' '.join([BLACKBOX[alpha.upper()][service]['DOMAIN'] for service in BLACKBOX[alpha.upper()] if service in services and 'DOMAIN' in BLACKBOX[alpha.upper()][service].keys()]).replace(',', ' ')
        return domains
    except KeyError:
        abort(NOT_FOUND)


@application.route('/api/v{}/alpha/<string:alpha>/services/default/<int:default>'.format(API_VERSION), methods=['GET'])
@requires_auth
def _get_services(alpha, default):
    alpha = alpha.upper()
    try:
        services = [
            service for service in BLACKBOX[alpha]
            if BLACKBOX[alpha][service]['default'] == bool(default)
            and 'DOMAIN' in list(BLACKBOX[alpha][service].keys())
        ]
        return ' '.join(services)
    except KeyError:
        abort(NOT_FOUND)


@application.route(
    '/api/v{}/iotest/queue/<string:guid>'.format(
        API_VERSION
    )
)
@requires_auth
def _dequeue_iotest(guid):
    result = dict()
    try:
        sql = '''SELECT test
            FROM iotest
            WHERE SUBSTRING(guid,1,32)=:guid
            AND status IS NULL
            ORDER BY dt DESC
            LIMIT 1'''
        result = session.execute(
            text(sql),
            {
                'guid': guid[:32]
            }
        ).fetchone()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)
    if result:
        return jsonify(int(result[0]))
    else:
        abort(NOT_FOUND)


@application.route(
    '/api/v{}/iotest/<int:test>/guid/<string:guid>'.format(
        API_VERSION
    )
)
@requires_auth
def _get_iotest(test, guid):
    result = dict()
    try:
        sql = '''SELECT dt, status, test, result
            FROM iotest
            WHERE SUBSTRING(guid,1,32)=:guid
            AND test=:test
            AND status IS NOT NULL
            ORDER BY dt DESC
            LIMIT 1'''
        result = session.execute(
            text(sql),
            {
                'guid': guid[:32],
                'test': test
            }
        )
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)
    if result.rowcount > 0:
        return json.dumps([dict(row._mapping) for row in result][0], default=str)
    else:
        abort(NOT_FOUND)


@application.route(
    '/api/v{}/iotest/<string:guid>'.format(
        API_VERSION
    ),
    methods=['PATCH']
)
@requires_auth
def _update_iotest(guid):
    data = None
    request.get_data()
    raw_post_body = request.data
    try:
        data = json.loads(request.data.decode('utf-8'))
    except:
        data = json.loads(request.data)
    if DEBUG: print('{}: {}'.format(stack()[0][3], data))
    if not data: abort(BAD_REQUEST)
    result = None
    try:
        sql = '''SELECT id
            FROM iotest
            WHERE SUBSTRING(guid,1,32)=:guid
            AND test=:test
            AND status IS NULL
            ORDER BY dt ASC
            LIMIT 1'''
        result = session.execute(
            text(sql),
            {
                'guid': guid[:32],
                'test': data['test']
            }
        )
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    if DEBUG: print('{}: {}'.format(stack()[0][3], result))
    if result.rowcount <= 0: abort(NOT_FOUND)
    test_id = [row for row in result.mappings()][0]['id']

    result = None
    try:
        query = IOtest.__table__.update().where(
            IOtest.id==test_id
        ).where(
            IOtest.guid==guid[:32]
        ).values(
            test=data['test'],
            result=data['result'],
            status=data['status'],
            dt=func.now()
        )
        result = session.execute(query)
        session.commit()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    return jsonify(result.rowcount)


@application.route(
    '/api/v{}/iotest/<int:test>/guid/<string:guid>'.format(
        API_VERSION
    ),
    methods=['PUT']
)
@requires_auth
def _queue_iotest(test, guid):
    try:
        result = IOtest(func.now(), guid[:32], None, test, None)
        session.add(result)
        session.commit()
    except Exception as e:
        session.rollback()
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

    return jsonify(guid)


if __name__ == '__main__':
    application.run(
        threaded=THREADED,
        debug=DEBUGGER,
        host=LISTEN_ADDR,
        port=PORT
    )

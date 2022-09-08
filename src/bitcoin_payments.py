# -*- coding: utf-8 -*-

from __future__ import print_function

import json
import requests

from datetime import datetime, timedelta
from inspect import stack

from blockcypher import (
    list_wallet_names, derive_hd_address, subscribe_to_address_webhook,
    list_webhooks, create_hd_wallet, get_wallet_addresses,
    unsubscribe_from_webhook
)

import resin # prevent circular imports

from utils import *
from config import *


@retry(Exception, cdata='method={0}'.format(stack()[0][3]))
def bitcoin_payment_expired(guid=None):
    try:
        utcnow = datetime.utcnow()
        payment_date = resin.get_resin_device_env_by_name(\
            guid=guid, name='BITCOIN_LAST_PAYMENT_DATE')
        payment_amount = resin.get_resin_device_env_by_name(\
            guid=guid, name='BITCOIN_LAST_PAYMENT_AMOUNT')
        daily_rate = resin.get_resin_device_env_by_name(\
            guid=guid, name='BITCOIN_DAILY_AMOUNT')

        expiry_date = datetime.strptime(
            payment_date, '%Y-%m-%dT%H:%M:%SZ') + \
            timedelta(
                days=float(payment_amount) / float(daily_rate)
            )

        if DEBUG:
            print('utcnow={} payment_date={} payment_amount={} daily_rate={} expiry_date={}'.format(
                utcnow,
                payment_date,
                payment_amount,
                daily_rate,
                expiry_date
            ))
        return utcnow > expiry_date
    except:
        return None 


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_btc_price(currency=DEFAULT_CURRENCY):
    res = requests.get('https://blockchain.info/tobtc?currency={}&value={}'.format(
        currency,
        DEFAULT_MONTHLY_AMOUNT
    ))
    if res.status_code not in [200]:
        raise AssertionError((res.status_code, res.content))
    try:
        btc_price = float(res.content.decode('utf-8'))
    except:
        btc_price = float(res.content)
    satoshi_price = int(btc_price * 100000000)
    if DEBUG: print('btc_price: {} BTC satoshi_price: {}'.format(
        btc_price,
        satoshi_price
    ))
    price_per_day = int(satoshi_price * 12 / 365)
    return price_per_day


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def generate_new_payment_address(guid=None):
    create_wallet = True
    wallets = list_wallet_names(
        BLOCKCYPHER_API_TOKEN,
        coin_symbol=BLOCKCYPHER_COIN_SYMBOL
    )
    if DEBUG: print('list_wallet_names(): {}'.format(wallets))

    for name in wallets['wallet_names']:
        if name == BLOCKCYPHER_WALLET_NAME:
            create_wallet = False
            break

    if create_wallet:
        result = create_hd_wallet(
            wallet_name=BLOCKCYPHER_WALLET_NAME,
            xpubkey=BITCOIN_PAYMENT_WALLET_XPUBKEY,
            api_key=BLOCKCYPHER_API_TOKEN,
            coin_symbol=BLOCKCYPHER_COIN_SYMBOL,
            subchain_indices=[0, 1]
        )
        if DEBUG: print('create_hd_wallet(): {}'.format(result))
        
    wallet = derive_hd_address(
        api_key=BLOCKCYPHER_API_TOKEN,
        wallet_name=BLOCKCYPHER_WALLET_NAME,
        coin_symbol=BLOCKCYPHER_COIN_SYMBOL
    )
    if DEBUG: print('derive_hd_address(): {}'.format(wallet))

    payment_address = wallet['chains'][0]['chain_addresses'][0]['address']

    webhook_id = subscribe_to_address_webhook(
        callback_url='{}/api/v{}/blockcypher/webhook/{}'.format(
            API_HOST, API_VERSION, BLOCKCYPHER_WEBHOOK_TOKEN
        ),
        subscription_address=payment_address,
        event=BITCOIN_CONFIRMATION_EVENT,
        api_key=BLOCKCYPHER_API_TOKEN,
        coin_symbol=BLOCKCYPHER_COIN_SYMBOL,
        confirmations=BITCOIN_MAX_CONFIRMATIONS
    )

    if DEBUG: print('subscribe_to_address_webhook(): {}'.format(webhook_id))

    cache_set(key=payment_address, value=guid)

    return (payment_address, webhook_id)


@retry(Exception, cdata='method={0}'.format(stack()[0][3]))
def remove_webhook(webhook_id=None):
    result = unsubscribe_from_webhook(
        webhook_id, api_key=BLOCKCYPHER_API_TOKEN,
        coin_symbol=BLOCKCYPHER_COIN_SYMBOL)
    
    if DEBUG: print('unsubscribe_from_webhook: webhook_id={} result={}'.format(
        webhook_id,
        result
    ))
    
    return result


@retry(Exception, cdata='method={0}'.format(stack()[0][3]))
def get_addresses():
    addresses = get_wallet_addresses(
        is_hd_wallet=True, api_key=BLOCKCYPHER_API_TOKEN,
        wallet_name=BLOCKCYPHER_WALLET_NAME,
        coin_symbol=BLOCKCYPHER_COIN_SYMBOL)
    return addresses


@retry(Exception, cdata='method={0}'.format(stack()[0][3]))
def get_webhooks():
    webhooks = list_webhooks(
        api_key=BLOCKCYPHER_API_TOKEN, coin_symbol=BLOCKCYPHER_COIN_SYMBOL)
    return webhooks

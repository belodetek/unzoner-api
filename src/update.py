#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from traceback import print_exc, format_exc
from argparse import ArgumentParser
from zipfile import ZipFile
from shutil import copyfileobj, rmtree

try:
    from cStringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO 

from git import Repo, Git, Actor
from git.exc import GitCommandError
from importlib import import_module

import os
import json
import boto3
import jinja2
import smtplib
import requests

from config import *


def ensure_dir(file_path):
    if not os.path.exists(file_path):
        os.makedirs(file_path)


def get_zip(url):
    req = requests.get(url)
    print('url={} status_code={}'.format(url, req.status_code))
    memcontent = StringIO()
    memcontent.write(req.content)
    return memcontent


def get_url(url):
    req = requests.get(url)
    print('url={} status_code={}'.format(url, req.status_code))
    return req.content


def update(zip_file=None, ca_cert=None, provider=None):
    temp_dir = '{}/__{}'.format(VPN_PROFILES, provider)
    target_dir = '{}/{}'.format(VPN_PROFILES, provider)
    try:
        rmtree(temp_dir)
    except:
        pass
    ensure_dir(temp_dir)
    ensure_dir(target_dir)

    try:
        filename = ca_cert.split('/')[-1]
        target = file(os.path.join(temp_dir, filename), 'wb')
        target.write(get_url(ca_cert))
        target.close()
        print('copied file={} target={}'.format(filename, temp_dir))
    except:
        pass

    try:
        memcontent = get_zip(zip_file)
        with ZipFile(memcontent) as archive:
            for member in archive.namelist():
                filename = os.path.basename(member.split('/')[-1])
                if not filename: continue
                source = archive.open(member)
                try:
                    target = file(os.path.join(temp_dir, filename), 'wb')
                except NameError:
                    target = open(os.path.join(temp_dir, filename), 'wb')
                if DEBUG:
                    print('unpacking {} to {}'.format(filename, temp_dir))
                with source, target:
                    copyfileobj(source, target)
            print('unpacked {} files to {}'.format(
                len(archive.namelist()),
                temp_dir
            ))
    except Exception as e:
        rmtree(temp_dir)
        return (False, format_exc())

    rmtree(target_dir)
    os.rename(temp_dir, target_dir)
    return (True, '')


def gitpull():
    try:
        repo = Repo(VPN_PROVIDERS_GIT_DIR)
    except:
        repo = Repo.clone_from(VPN_PROVIDERS_GIT_URL, VPN_PROVIDERS_GIT_DIR)
    origin = repo.remotes.origin
    origin.fetch()
    origin.pull()
    Git(VPN_PROVIDERS_GIT_DIR).checkout(VPN_PROVIDERS_GIT_TAG)
    return (repo, origin)


def gitcommit(repo=None, comment=None, author=None):
    untracked = len(repo.untracked_files)
    modified = len(repo.index.diff(None)) 
    if untracked or modified:
        print('files untracked={} modified={}'.format(untracked, modified))
        try:
            repo.git.add('--all')
            staged = len(repo.index.diff('HEAD'))
            if staged:
                repo.git.commit('-m', comment, author=author)
        except:
            body = {
                'provider': repo,
                'exception': format_exc(),
            }
            email_body=[
                render('templates/plaintext-email.tpl', body),
                render('templates/html-email.tpl', body)
            ]
            preamble = '{} commit failed'.format(repo)
            subject = preamble
            send_email(preamble=preamble, body=email_body, subject=subject)
    else:
        print('nothing to commit')


def gitpush(repo=None, origin=None):
    ahead = list(
        repo.iter_commits(
            'origin/{}..{}'.format(
                VPN_PROVIDERS_GIT_TAG,
                VPN_PROVIDERS_GIT_TAG
            )
        )
    )
    if len(ahead) > 0:
        print('commits ahead={}'.format(len(ahead)))
        try:
            try:
                origin.push(
                    refspec='{}:{}'.format(
                        VPN_PROVIDERS_GIT_TAG,
                        VPN_PROVIDERS_GIT_TAG
                    )
                )
            except:
                repo.git.push(
                    'origin',
                    '{}:{}'.format(
                        VPN_PROVIDERS_GIT_TAG,
                        VPN_PROVIDERS_GIT_TAG
                    )
                )
        except:
            body = {
                'provider': repo,
                'exception': format_exc(),
            }
            email_body=[
                render('templates/plaintext-email.tpl', body),
                render('templates/html-email.tpl', body)
            ]
            preamble = '{} push failed'.format(repo)
            subject = preamble
            send_email(preamble=preamble, body=email_body, subject=subject)
    else:
        print('nothing to push')


def render(tpl_path, context):
    path, filename = os.path.split(tpl_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './')
    ).get_template(filename).render(context=context)


def send_email(subject=None, rcpt_to=SMTP_RCPT_TO, body=None, preamble=None):
    msg = MIMEMultipart('alternative')
    try:
        plain = MIMEText(body[0].encode('utf-8'), 'plain')
    except AttributeError:
        plain = MIMEText(body[0], 'plain')
    try:
        html = MIMEText(body[1].encode('utf-8'), 'html')
    except AttributeError:
        html = MIMEText(body[1], 'html')
    msg.attach(plain)
    msg.attach(html)
    msg['From'] = SMTP_FROM
    msg['To'] = rcpt_to
    msg['Subject'] = subject
    msg.preamble = preamble
    print('msg={}'.format(msg))
    smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
    print(
        'smtp={} ehlo={} login={} sendmail={} quit={}'.format(
            smtp,
            smtp.ehlo(),
            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            ),
            smtp.sendmail(
                SMTP_FROM,
                rcpt_to.split(','),
                msg.as_string()
            ),
            smtp.quit()
        )
    )


def main(args=None):
    repo, origin = gitpull()
    mod = import_module(args.provider.lower())
    
    with repo.config_writer() as cw:
        cw.set_value('user', 'email', SMTP_FROM)
        cw.set_value('user', 'name', GITHUB_USERNAME)
    with origin.config_writer as cw:
        cw.set('pushurl', VPN_PROVIDERS_GIT_URL)

    (result, exception) = update(
        zip_file=mod.Provider.zip_file,
        ca_cert=mod.Provider.ca_cert,
        provider=args.provider
    )
    if not result and exception:
        body = {
            'provider': args.provider,
            'exception': exception,
        }
        email_body=[
            render('templates/plaintext-email.tpl', body),
            render('templates/html-email.tpl', body)
        ]
        preamble = '{} update failed'.format(args.provider)
        subject = preamble
        send_email(preamble=preamble, body=email_body, subject=subject)
    else:
        comment = '{} update'.format(args.provider)
        author = Actor(GITHUB_USERNAME, SMTP_FROM)
        gitcommit(repo=repo, comment=comment, author=author)
        gitpush(repo=repo, origin=origin)
        print(repo.git.status())
    return result


def get_args():
    parser = ArgumentParser()
    parser.add_argument(
        '--provider', type=str, default='NordVPN', choices=[
            'NordVPN', 'IPVanish'
        ],
        help='provider to update')
    return parser.parse_args()


if __name__ == '__main__':
    main(args=get_args())

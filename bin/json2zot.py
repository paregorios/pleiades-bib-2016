#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
template
"""

import argparse
import copy
import csv
from datetime import date
from functools import wraps
import json
import logging
import os
from pprint import PrettyPrinter, pformat
import random
import string
import sys
from time import sleep
import traceback

import requests

AWOL_INDEX_BASE = 'http://isaw.nyu.edu/publications/awol-index/html'
MAX_CHUNKS = sys.maxsize
#MAX_CHUNKS = 3
CHUNK_SIZE = 50

DEFAULTLOGLEVEL = logging.WARNING
PP = PrettyPrinter(indent=4)
ZOT_BASE = 'https://api.zotero.org'
ZOT_HEADERS = {
    'Zotero-API-Version': 3,
    'Authorization': 'Bearer BKlvC2V183615qko8hM7Year',
    'user-agent': 'ParegoriosPleiadesBot/0.1 (http://www.paregorios.org/)'
}
ZOT_CONTEXT = 'users/465'   # paregorios 
ZOT_COLLECTIONS = ['AN2AH2XZ',]  #pbib-2016
ZOT_PAUSE = 0.0
ZOT_DELAY = 0
ZOT_TEMPLATES = {}

def ztoken_generator(size=32, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def arglogger(func):
    """
    decorator to log argument calls to functions
    """
    @wraps(func)
    def inner(*args, **kwargs):
        logger = logging.getLogger(func.__name__)
        logger.debug("called with arguments: %s, %s" % (args, kwargs))
        return func(*args, **kwargs)
    return inner


def handle_pause():
    """ handle user-directed pause between requests """
    global ZOT_PAUSE
    logger = logging.getLogger(sys._getframe().f_code.co_name)
    if ZOT_PAUSE > 0.0:
        logger.info(
            'per command-line directive (-p), pausing {0} before issuing request to zotero'.format(ZOT_PAUSE))
        sleep(ZOT_PAUSE)
        logger.info('awake!')


def handle_backoff():
    """ handle any previous backoff request """
    global ZOT_DELAY
    logger = logging.getLogger(sys._getframe().f_code.co_name)
    if ZOT_DELAY != 0:
        logger.info(
            'responding to backoff request\n\nsleeping for {0} seconds'.format(ZOT_DELAY))
        sleep(ZOT_DELAY)
        logger.info('\n\nawake!\n\n')
        ZOT_DELAY = 0


def zot_get(url, headers={}):
    global ZOT_DELAY
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    logger.debug('url: {0}'.format(url))

    handle_pause()
    handle_backoff()
    req_headers = ZOT_HEADERS.copy()
    for k, v in list(headers.items()):
        req_headers[k] = v

    log_request(url, req_headers)
    r = requests.get(url, headers=req_headers)
    log_response(r)

    if r.status_code == 429:
        # too many requests
        delay = r.headers['Retry-After']
        logger.warning(
            'Server sent 429 Too Many Requests with Retry-After={0}\n\nsleeping...'.format(delay))
        sleep(float(delay) + 0.1)
        logger.info('awake!')
        log_request(url, req_headers)
        r = requests.get(url, headers=req_headers)
        log_response(r)

    if r.status_code != requests.codes.ok:
        r.raise_for_status()

    # check for backoff
    try:
        ZOT_DELAY = int(r.headers['Backoff'])
    except KeyError:
        pass

    # parse response
    d = {}
    try:
        d['last-modified-version'] = r.headers['last-modified-version']
    except KeyError:
        pass
    try:
        d['length'] = r.headers['total-results']
    except KeyError:
        pass
    try:
        d['json'] = r.json()
    except ValueError:
        pass
    d['content'] = r.content
    return d


def zot_del(url, headers={}):
    global ZOT_DELAY
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    logger.debug('url: {0}'.format(url))

    handle_pause()
    handle_backoff()
    req_headers = ZOT_HEADERS.copy()
    for k, v in list(headers.items()):
        req_headers[k] = v

    log_request(url, req_headers)
    r = requests.delete(url, headers=req_headers)
    log_response(r)

    if r.status_code == 429:
        # too many requests
        delay = r.headers['Retry-After']
        logger.warning(
            'Server sent 429 Too Many Requests with Retry-After={0}\n\nsleeping...'.format(delay))
        sleep(float(delay) + 0.1)
        logger.info('awake!')
        log_request(url, req_headers)
        r = requests.delete(url, headers=req_headers)
        log_response(r)

    if r.status_code != 204:
        r.raise_for_status()

    # check for backoff
    try:
        ZOT_DELAY = int(r.headers['Backoff'])
    except KeyError:
        pass

    # parse response
    d = {}
    try:
        d['last-modified-version'] = r.headers['last-modified-version']
    except KeyError:
        pass
    return d


def zot_post(url, headers={}, payload=[]):
    global ZOT_DELAY
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    handle_pause()
    handle_backoff()
    req_headers = ZOT_HEADERS.copy()
    for k, v in list(headers.items()):
        req_headers[k] = v
    req_headers['Content-Type'] = 'application/json'
    req_headers['Zotero-Write-Token'] = ztoken_generator()

    log_request(url, req_headers)
    r = requests.post(url, headers=req_headers, json=payload)
    log_response(r)

    if r.status_code == 429:
        # too many requests
        delay = r.headers['Retry-After']
        logger.warning(
            'Server sent 429 Too Many Requests with Retry-After={0}\n\nsleeping...'.format(delay))
        sleep(float(delay) + 0.1)
        logger.info('awake!')
        log_request(url, req_headers)
        r = requests.post(url, headers=req_headers, json=payload)
        log_response(r)

    if r.status_code != requests.codes.ok:
        r.raise_for_status()

    # check for backoff
    try:
        ZOT_DELAY = int(r.headers['Backoff'])
    except KeyError:
        pass

    # parse response
    d = {}
    try:
        d['last-modified-version'] = r.headers['last-modified-version']
    except KeyError:
        pass
    try:
        d['length'] = r.headers['total-results']
    except KeyError:
        pass
    try:
        d['json'] = r.json()
    except ValueError:
        pass
    d['content'] = r.content
    return d


def log_request(url, headers):
    logger = logging.getLogger(sys._getframe().f_code.co_name)
    logger.debug('\nREQUEST')
    logger.debug('    url: {0}'.format(url))
    for k, v in list(headers.items()):
        logger.debug('    header: {0}: "{1}"'.format(k, v))


def log_response(r):
    logger = logging.getLogger(sys._getframe().f_code.co_name)
    logger.debug('\nRESPONSE')
    logger.debug('    status: {0}'.format(r.status_code))
    for k, v in list(r.headers.items()):
        logger.debug('    header: {0}: "{1}"'.format(k, v))
    try:
        logger.debug('result json: {0}'.format(pformat(r.json(), indent=4)))
    except ValueError:
        try:
            logger.debug('result content: {0}'.format(
                pformat(r.content, indent=4)))
        except AttributeError:
            logger.debug('no result content found')


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def clear_library_contents(zot_context):
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    url = '/'.join((ZOT_BASE, zot_context, 'items', '?format=keys'))
    result = zot_get(url)
    keys = result['content'].strip().split('\n')
    if len(keys) == 1:
        keys[0] = keys[0].strip()
        if len(keys[0]) == 0:
            keys = []
    if len(keys) != int(result['length']):
        raise ValueError('reported length of result ({0}) does not match length of unpacked raw content ({1})'.format(
            int(result['length']), len(keys)))

    logger.debug('there are {0} items in the library'.format(len(keys)))
    chunk_size = 50
    for chunk in chunks(keys, chunk_size):
        logger.debug(
            'attemping to delete the next {0} items'.format(len(chunk)))
        url = '/'.join((ZOT_BASE, zot_context,
                        'items?itemKey={0}'.format(','.join(chunk))))
        headers = {
            'If-Unmodified-Since-Version': result['last-modified-version']
        }
        result = zot_del(url, headers=headers)

def get_template(ztype):
    try:
        return ZOT_TEMPLATES[ztype]
    except KeyError:
        url = '/'.join((ZOT_BASE, 'items', 'new?itemType={0}'.format(ztype)))
        result = zot_get(url)
        ZOT_TEMPLATES[ztype] = result['json']
        return ZOT_TEMPLATES[ztype]

def main(args):
    """
    main functions
    """
    logger = logging.getLogger(sys._getframe().f_code.co_name)

    context = ZOT_CONTEXT
    global ZOT_PAUSE
    ZOT_PAUSE = args.pause

    if not(args.create):
        logger.info(
            'nothing will be created (command line -c option was NOT invoked)')


    # load and loop through the bibliographic data to upload

    path = args.json[0]
    with open(path, 'r', newline='', encoding='utf-8') as f:
        works = json.load(f)

    # define crosswalk actions
    cw = {
        'abstract': {
            'type': 'str',
            'action': 'append',
            'target': 'abstractNote',
            'delimiter': ';'
        },
        'author': {
            'action': 'ignore'
        },
        'authors': {
            'action': 'ignore'
        },
        'bookTitle': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'bookTitle'
        },
        'publicationTitle': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'publicationTitle'
        },
        'journalAbbreviation': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'journalAbbreviation'
        },
        'issn': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'ISSN'
        },
        'edition': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'edition'
        },
        'editors': {
            'action': 'ignore'
        },
        'extra': {
            'type': 'str',
            'action': 'append',
            'target': 'extra',
            'delimiter': ';'
        },
        'numVols': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'numberOfVolumes'
        },
        'places': {
            'type': 'list',
            'preaction': 'join',
            'action': 'append',
            'target': 'place',
            'delimiter': ', '
        },
        'publisher': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'publisher'
        },
        'series': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'series'
        },
        'seriesNumber': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'seriesNumber'
        },
        'shorts': {
            'type': 'str',
            'action': 'append',
            'target': 'shortTitle',
            'delimiter': ';'
        },
        'short_new': {
            'action': 'ignore'
        },
        'thesisType': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'thesisType'
        },
        'title': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'title'
        },
        'translators': {
            'action': 'ignore'
        },
        'university': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'university'
        },
        'vols': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'volume'
        },
        'volume': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'volume'
        },
        'year': {
            'type': 'list',
            'action': 'overwrite',
            'preaction': 'join',
            'delimiter': ', ',
            'target': 'date'
        },
        'date': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'date'
        },
        'pages': {
            'type': 'str',
            'action': 'overwrite',
            'target': 'pages'
        }
    }
    id_index = []
    omit = ['journal', 'series']
    for i, w in enumerate(works):
        work_type_zot = w['ztype'].strip()
        if work_type_zot == '':
            logger.error("blank work type for {0}: {1} ({2})".format(w['workID'], w['title'], w['shorts']))
        if len(work_type_zot) > 0 and work_type_zot not in omit:
            d = copy.deepcopy(get_template(work_type_zot))
            d['creators'] = []

            logger.debug('template keys: {0}'.format(sorted(d.keys())))
            for k,v in w.items():
                logger.debug('handling: {0}:{1}'.format(k,v))
                if v != '':
                    try:
                        hdlr = cw[k]
                    except KeyError:
                        if k == '' or k in ['long', 'pieces', 'ztype']:
                            pass
                        else:
                            logger.debug('key miss: {0}'.format(k))
                    else:
                        act = hdlr['action']
                        if act == 'ignore':
                            if k in ['authors', 'editors', 'translators'] and len(v) > 0:
                                d['creators'].extend([{'creatorType': k[:-1], 'name': c} for c in v])
                            if k == 'short_new':
                                if v not in w['shorts']:
                                    if len(d['shortTitle']) == 0:
                                        d['shortTitle'] = v
                                    else:
                                        d['shortTitle'] += str('; ' + v)
                        else:
                            tgt = hdlr['target']
                            try:
                                delimiter = hdlr['delimiter']
                            except KeyError:
                                delimiter = ''
                            try:
                                prefix = hdlr['prefix']
                            except KeyError:
                                prefix = ''
                            try:
                                preact = hdlr['preaction']
                            except KeyError:
                                preact = ''
                            htype = hdlr['type']
                            logger.debug('htype: {0}'.format(htype))
                            if type(v) == int and k == 'year':
                                v = [str(v),]
                            if htype == 'str' and len(v) > 0:
                                if type(v) == list:
                                    val = ''.join(v)
                                else:
                                    val = v
                                val = prefix + val
                                if act == 'append':
                                    if len(d[tgt]) > 0:
                                        d[tgt] += str(delimiter + ' ' + val)
                                    else:
                                        d[tgt] = val
                                elif act == 'overwrite':
                                    d[tgt] = val
                                elif act == 'suppress':
                                    if len(d[tgt]) == 0:
                                        d[tgt] = val
                            elif htype == 'list' and len(v) > 0:
                                if preact == 'join':
                                    val = delimiter.join(v)
                                else:
                                    val = v
                                if act == 'overwrite':
                                    d[tgt] = val
                                elif act == 'append':
                                    if type(val) == list:
                                        d[tgt].extend(val)
                                    else:
                                        if len(d[tgt]) > 0:
                                            d[tgt] += str(delimiter + val)
                                        else:
                                            d[tgt] = val




            # collections and tags
            d['collections'] = ZOT_COLLECTIONS

            # cleanup

            logger.debug(pformat(d, indent=4))

            # create the bibliographic record
            if args.create:
                logger.info('\n\nsending "{0}" to zotero'.format(d['title']))
                url = '/'.join((ZOT_BASE, context, 'items'))
                try:
                    result = zot_post(url, payload=[d, ])
                except requests.exceptions.HTTPError as err:
                    logger.error('API call failed with HTTPError. Details:\n'
                        '>>> msg: {0}\n'
                        '>>> response: {1}\n'
                        '>>> request: {2}\n'
                        '>>> payload: {3}\n'.format(
                            err.strerror, 
                            pformat(err.response.content, indent=4), 
                            pformat(err.request.body, indent=4),
                            pformat(d, indent=4)))
                else:
                    if len(result['json']['failed']) != 0:
                        logger.error('API call failed per JSON response. '
                            'Details:\n'
                            '>>> response: {0}\n'
                            '>>> payload: {1}\n'.format(
                                pformat(result['json'], indent=4),
                                pformat(d, indent=4)))
                    else:
                        item_key = result['json']['success']['0']
                        print(item_key)
        else:
            pass
            #logger.debug("skipping '{0}'' because work_type {1} omitted".format(w['title'], work_type))

    if len(id_index) > 0:
        with open(os.path.join(path, 'id_index.csv'), 'w') as f:
            writer = csv.DictWriter(f, fieldnames=['awmc_id', 'zotero_key'])
            writer.writeheader()
            for pair in id_index:
                writer.writerow(pair)

if __name__ == "__main__":
    log_level = DEFAULTLOGLEVEL
    log_level_name = logging.getLevelName(log_level)
    logging.basicConfig(level=log_level)

    try:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-l", "--loglevel", type=str,
                            help="desired logging level (case-insensitive string: DEBUG, INFO, WARNING, ERROR")
        parser.add_argument("-v", "--verbose", action="store_true",
                            default=False, help="verbose output (logging level == INFO")
        parser.add_argument("-vv", "--veryverbose", action="store_true",
                            default=False, help="very verbose output (logging level == DEBUG")
        parser.add_argument("-k", "--kill", action="store_true",
                            default=False, help="kill everything currently in the library!")
        parser.add_argument("-c", "--create", action="store_true",
                            default=False, help="create new resources in zotero")
        parser.add_argument("-p", "--pause", type=float, default=0,
                            help="pause between zotero api requests in decimal seconds (float)")
        parser.add_argument('json', type=str, nargs=1,
                            help='json file to load')
        # example positional argument:
        # parser.add_argument('integers', metavar='N', type=int, nargs='+', help='an integer for the accumulator')
        args = parser.parse_args()
        if args.loglevel is not None:
            args_log_level = re.sub('\s+', '', args.loglevel.strip().upper())
            try:
                log_level = getattr(logging, args_log_level)
            except AttributeError:
                logging.error("command line option to set log_level failed because '%s' is not a valid level name; using %s" % (
                    args_log_level, log_level_name))
        if args.veryverbose:
            log_level = logging.DEBUG
        elif args.verbose:
            log_level = logging.INFO
        log_level_name = logging.getLevelName(log_level)
        logging.getLogger().setLevel(log_level)
        if log_level != DEFAULTLOGLEVEL:
            logging.warning(
                "logging level changed to %s via command line option" % log_level_name)
        else:
            logging.info("using default logging level: %s" % log_level_name)
        logging.debug("command line: '%s'" % ' '.join(sys.argv))
        main(args)
        sys.exit(0)
    except KeyboardInterrupt as e:  # Ctrl-C
        raise e
    except SystemExit as e:  # sys.exit()
        raise e
    except Exception as e:
        print("ERROR, UNEXPECTED EXCEPTION")
        print(str(e))
        traceback.print_exc()
        os._exit(1)

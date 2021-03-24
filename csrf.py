#!/usr/bin/env python

from core.colors import green, yellow, end, run, good, info, bad, white, red

lightning = '\033[93;5m⚡\033[0m'

def banner():
    print('''
         %s⚡ %sCSRF-SCANNER%s  ⚡%s
        ''' % (yellow, white, yellow, end))

banner()

try:
    import concurrent.futures
    try:
        from fuzzywuzzy import fuzz, process
    except:
        import os
        print ('%s fuzzywuzzy library is not installed, installing now.' % info)
        os.system('pip3 install fuzzywuzzy')
        print ('%s fuzzywuzzy has been installed, please restart Bolt.' % info)
        quit()
except:
    print ('%s CSRF-SCANNER is not compatible with python 2. Please run it with python 3.' % bad)

import argparse
import json
import random
import re
import statistics

from core.entropy import isRandom
from core.datanize import datanize
from core.prompt import prompt
from core.photon import photon
from core.tweaker import tweaker
from core.evaluate import evaluate
from core.ranger import ranger
from core.zetanize import zetanize
from core.requester import requester
from core.utils import extractHeaders, strength, isProtected, stringToBinary, longestCommonSubstring

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='target url', dest='target')
parser.add_argument('-t', help='number of threads', dest='threads', type=int)
parser.add_argument('-l', help='levels to crawl', dest='level', type=int)
parser.add_argument('--delay', help='delay between requests',
                    dest='delay', type=int)
parser.add_argument('--timeout', help='http request timeout',
                    dest='timeout', type=int)
parser.add_argument('--headers', help='http headers',
                    dest='add_headers', nargs='?', const=True)
args = parser.parse_args()

if not args.target:
    print('\n' + parser.format_help())
    quit()

if type(args.add_headers) == bool:
    headers = extractHeaders(prompt())
elif type(args.add_headers) == str:
    headers = extractHeaders(args.add_headers)
else:
    from core.config import headers

target = args.target
delay = args.delay or 0
level = args.level or 2
timeout = args.timeout or 20
threadCount = args.threads or 2

allTokens = []
weakTokens = []
tokenDatabase = []
insecureForms = []

print (' %s Phase: Crawling %s[%s1/6%s]%s' %
       (lightning, green, end, green, end))
dataset = photon(target, headers, level, threadCount)
allForms = dataset[0]
print ('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
       (info, dataset[1], len(allForms), ' '))
print (' %s Phase: Evaluating %s[%s2/6%s]%s' %
       (lightning, green, end, green, end))
evaluate(allFroms, weakTokens, tokenDatabase, allTokens, insecureForms)

if weakTokens:
    print ('%s Weak token(s) found' % good)
    for weakToken in weakTokens:
        url = list(weakToken.keys())[0]
        token = list(weakToken.values())[0]
        print ('%s %s %s' % (info, url, token))

if insecureForms:
    print ('%s Insecure form(s) found' % good)
    for insecureForm in insecureForms:
        url = list(insecureForm.keys())[0]
        action = list(insecureForm.values())[0]['action']
        form = action.replace(target, '')
        if form:
            print ('%s %s %s[%s%s%s]%s' %
                   (bad, url, green, end, form, green, end))


print (' %s Phase: Comparing %s[%s3/6%s]%s' %
       (lightning, green, end, green, end))
uniqueTokens = set(allTokens)
if len(uniqueTokens) < len(allTokens):
    print('%s Potential Replay Attack condition found' % good)
    print('%s Verifying and looking for the cause' % run)
    replay = False
    for url, token in tokenDatabase:
        for url2, token2 in tokenDatabase:
            if token == token2 and url != url2:
                print('%s The same token was used on %s%s%s and %s%s%s' %
                      (good, green, url, end, green, url2, end))
                replay = True
    if not replay:
        print('%s Further investigation shows that it was a false positive.')

with open('./db/hashes.json') as f:
    hashPatterns = json.load(f)

if not allTokens:
    print('%s No CSRF protection to test' % bad)
    quit()

aToken = allTokens[0]
matches = []
for element in hashPatterns:
    pattern = element['regex']
    if re.match(pattern, aToken):
        for name in element['matches']:
            matches.append(name)
if matches:
    print('%s Token matches the pattern of following hash type(s):' % info)
    for name in matches:
        print('    %s>%s %s' % (yellow, end, name))

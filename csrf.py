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


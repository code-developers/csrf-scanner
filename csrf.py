#!/usr/bin/env python

from core.colors import green, yellow, end, run, good, info, bad, white, red

lightning = '\033[93;5m⚡\033[0m'

def banner():
    print('''
         %s⚡ %sCSRF-SCANNER%s  ⚡%s
        ''' % (yellow, white, yellow, end))

banner()

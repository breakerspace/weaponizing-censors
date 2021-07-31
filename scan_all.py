"""
Helper script for automating multiple scans back to back.
"""

import os
import time
import sys

# Coverage guided list of domains (not in order)
hosts = [
    'www.youporn.com',
    'www.roxypalace.com',
    'www.bittorrent.com',
    'plus.google.com',
    'www.survive.org.uk',
    "example.com"
]

if len(sys.argv) < 2:
    print("Usage: %s <output_filename>" % __file__)
    exit()

config = sys.argv[1]
path = "scan/%s" % config
os.makedirs(path)
try:
    for host in hosts:
        print("*" * 100)
        print("INITIATING SCAN FOR %s" % host)
        cmd = """
        sed "s/#define HOST .*/#define HOST \\\"%s\\\"/g" src/probe_modules/module_forbidden_scan.c > src/probe_modules/.backup
        """ % host
        print(cmd)
        os.system(cmd)
        time.sleep(1)
        os.system("mv src/probe_modules/.backup src/probe_modules/module_forbidden_scan.c")
        time.sleep(1)
        os.system("cmake . && make -j4 && sudo src/zmap -M forbidden_scan -p 80 -f \"saddr,len,payloadlen,flags,validation_type\" -o %s/%s_%s.csv -O csv -B 350M" % (path, config, host))
        print("Scan for %s finished" % host)
        print("Sleeping for 60 seconds before next scan.")
        time.sleep(60)
except KeyboardInterrupt:
    print("Exiting")

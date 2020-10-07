#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
'''
    Automates malware hashing and pivoting to OSINT data sources for additional values of interest. 
'''

__author__ = 'Victor Fernandez III'
__version__ = '2.0'

import argparse
import hashlib
import json
import os
import re
import requests
import select
import socket
import time

def collect():
    directory = os.listdir('.')
    files = []
    for item in directory:
        if os.path.isfile(item):
            files.append(item)
    fingerprint(files)

def fingerprint(files):
    evidence = {}
    for filename in files:
        md5 = hashlib.md5()
        blocksize = 65536
        with open(filename,'rb') as item:
            filebuffer = item.read(blocksize)
            while len(filebuffer) > 0:
                md5.update(filebuffer)
                filebuffer = item.read(blocksize)
        digest = md5.hexdigest()
        evidence[digest] = filename
    total = len(evidence)
    banner = "[+] Pivoting to " + data_source + " with " + str(total) + " values of interest"
    if data_source == 'VirusTotal' and total > 4:
        minutes = str(int((total * 15) / 60))
        seconds = time.time() + (total * 15)
        future = time.gmtime(seconds)
        timestamp = time.strftime("%H:%M:%S", future)
        eta = " (ETA: " + minutes + " minutes, " + timestamp + ")."
        print(banner + eta)
    else:
        print(banner + '.')
    pivot(evidence)

def pivot2zeek(evidence):
    zeek = 'missing'
    for directory, subdirectories, files in os.walk("/opt/"):
        for name in files:
            if name == 'intel.dat':
                zeek = os.path.join(directory,name)
    if zeek != 'missing':
        intel = open(zeek).readlines()
        for digest in evidence:
            for line in intel:
                if re.findall(digest,line):
                    filename = evidence[digest]
                    print(" --> 100 " + digest, filename)
    else:
        print("[x] Failed to pivot to Zeek.")

def pivot2teamcymru(evidence):
    try:
        mhr = ('hash.cymru.com', 43)
        hashes = ['begin']
        for digest in evidence:
            hashes.append(digest)
        hashes.append('end')
        hashes = '\n'.join(hashes)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(mhr)
        client.sendall(bytes(hashes,'UTF-8'))
        data = client.recv(1)
        on,off,out = select.select([client],[client],[client])
        while on:
            data += client.recv(2048)
            time.sleep(.15)
            on,off,out = select.select([client],[client],[client])
        client.close()
        results = data.decode().split('\n')[:-1]
        del results[0:2]
        for result in results:
            percent = result.split(' ')[-1]
            if percent != 'NO_DATA':
                digest = result.split(' ')[0]
                filename = evidence[digest] 
                print(" --> " + percent, digest, filename)
    except:
        print("[x] Failed to pivot to Team Cymru's Malware Hash Registry.")
        exit()

def pivot2virustotal(evidence):
    try:
        vt = 'https://www.virustotal.com/api/v3/files/'
        #key = ''
        key = input("[>] VirusTotal API key: ")
        for digest in evidence:
            filename = evidence[digest]
            with requests.session() as browser:
                url = vt + digest
                custom_headers = { 'x-apikey': key }
                response = requests.get(url, headers = custom_headers)
                if response.status_code == 200:
                    results = json.loads(response.content)['data']
                    attributes = results.get('attributes')
                    detected = attributes['last_analysis_stats']['malicious']
                    if detected > 0:
                        undetected = attributes['last_analysis_stats']['undetected']
                        scanner_count = detected + undetected
                        percent = str(detected) + '/' + str(scanner_count)
                        print(" --> " + percent, digest, filename)
            if len(evidence) > 4:
                time.sleep(15)
    except:
        print("[x] Failed to pivot to VirusTotal.")
        exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--zeek', action='store_true')
    parser.add_argument('--team-cymru', action='store_true')
    parser.add_argument('--virus-total', action='store_true')
    args = parser.parse_args()
    if args.zeek:
        data_source = 'Zeek'
        pivot = pivot2zeek
    elif args.team_cymru:
        data_source = 'Team Cymru'
        pivot = pivot2teamcymru
    elif args.virus_total:
        data_source = 'VirusTotal'
        pivot = pivot2virustotal
    else:
        print('[x] Please select a data source.')
        parser.print_help()
        exit()
    collect()

# REFERENCES
# https://developers.virustotal.com/reference#file-search
# https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
# https://docs.python.org/3/library/os.html#os.scandir
# https://developers.google.com/edu/python/dict-files
# https://stackoverflow.com/questions/930397/getting-the-last-element-of-a-list
# https://gist.github.com/aunyks/042c2798383f016939c40aa1be4f4aaf

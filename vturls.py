#!/usr/bin/env python3
#import argparse
import base64
import datetime as dt
# for sha256 of urls
import hashlib
import json
import optparse
import requests
import sys
import time

"""
vturls.py
version 0.1
author: jortiz
  - a simple utility for scanning urls

TODO:
  - add flag for rescan OR auto-rescan for URLS older than X 

"""
class colo:
    header = '\033[95m'
    blu = '\033[94m'
    blink = '\033[5m'
    grn = '\33[96m'
    warn = '\033[33m'
    fail = '\033[91m'
    end = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

class vtapi():
  def __init__(self):
    # i know... still plaintext, but this is because plaintext keys in scripts is apparently frowned upon.. lol
    self.api = base64.b64decode('b64encodedapikeyhere').decode('utf-8').strip()
    self.base = 'https://www.virustotal.com/api/v3/'
    self.headers = {'x-apikey': self.api}

  # tested, works
  def getsubdomainreport(self,domain):
    url = self.base+'domains/'+domain+'/subdomains'
    result = requests.get(url, headers=self.headers)
    jdata = json.loads(result.text)
    return jdata

  # tested, works
  def getdomainreport(self,domain):
    """
      Consider: ovrloading this function to return whois stuff
    """
    url = self.base+'domains/'+domain
    result = requests.get(url, headers=self.headers)
    jdata = json.loads(result.text)
    return jdata['data']

  def getdomainurlsreport(self,domain):
    url = self.base+'domains/'+domain+'/urls'
    result = requests.get(url, headers=self.headers)
    jdata = json.loads(result.text)
    return jdata

  def getfilereport(self,filehash):
    url = self.base+'files/'+filehash
    result = requests.get(url, headers=self.headers)
    jdata = json.loads(result.text)
    return jdata

  def geturlreport(self,knownurl):
    url_id = base64.urlsafe_b64encode(knownurl.encode('utf-8')).strip(b'=')
    url_id = url_id.decode()
    url = self.base + 'urls/'+url_id
    result = requests.get(url, headers=self.headers)
    if 'error' in result.text:
      return False
    return result.json()['data']

  def printurlreport(self,responsedata):
    lastscan_pretty = dt.datetime.fromtimestamp(responsedata['attributes']['last_analysis_date']).strftime('%c')
    guilink = 'https://www.virustotal.com/gui/url/'+responsedata['id']+'/detection'
    last_analysis = responsedata['attributes']['last_analysis_stats']
    mal_string = colo.fail+'Malicious: '+str(last_analysis['malicious'])+colo.end
    clean_string = colo.grn + 'Harmless: '+str(last_analysis['harmless'])+colo.end
    print("LAST SCAN: "+lastscan_pretty)
    print(guilink)
    print(clean_string,mal_string)

  # will work for multiple urls that differ "only in minor aspects"
  def getunseenurlscan(self,urltoscan):
    url_id = base64.urlsafe_b64encode(urltoscan.encode('utf-8')).strip(b'=')
    url_id = url_id.decode()
    url = self.base+'urls/'+url_id+'/analyse'
    result = requests.get(url, headers=self.headers)
    return result.json()

  def getscanfromscanid(self, scanid):
    url = self.base+'urls/'+scanid+'/analyse'
    result = requests.post(url, headers = self.headers)
    return result.json()

  def geturlreportbyid(self,urlidentifier):
    url = self.base + 'urls/'+urlidentifier
    result = requests.get(url, headers=self.headers)
    return result.json()

  def getunseenurlscanv2(self,urltoscan):
    """
      we use v2 to submit urls for scan.. sample response below
    """ 
    url_id = base64.urlsafe_b64encode(urltoscan.encode('utf-8')).strip(b'=')
    url_id = url_id.decode()
    url = self.base+'urls/'+url_id+'/analyse'
    v2_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    v2_params = {'apikey' : self.api, 'url' : urltoscan }
    result = requests.post(v2_url, data=v2_params)
    return json.loads(result.text)

  def keepitcookin(self, scan_id_whole):
    """
      Should be called on a freshly submitted url scan_id to wait for full results..
    """
    i = 1 
    while len(self.geturlreportbyid(scan_id_whole.split('-')[0])['data']['attributes']['last_analysis_results']) < 7:
      sys.stdout.write('\r')
      sys.stdout.write('Scanning'+'.'*i)
      sys.stdout.flush()
      time.sleep(1)
      i += 1
      pass
    sys.stdout.write('\r\n')
    self.printurlreport(self.geturlreportbyid(scan_id_whole.split('-')[0])['data'])

def main():
  if len(sys.argv) == 1:
    print('(-) Usage: '+sys.argv[0]+' <somedomainhere>')
    print('(-) Info: accepts a given url; will return analysis of known urls')
    sys.exit(-1)

  vtobject = vtapi()
  parser = optparse.OptionParser()
  parser.add_option("-r", "--rescan", help="force rescan of submitted url")
  (options, args) = parser.parse_args()
  if options.rescan:
    scandata = vtobject.getunseenurlscanv2(sys.argv[2])
    vtobject.keepitcookin(scandata['scan_id'])
    sys.exit(0)
  line = '='*10
  url = sys.argv[1]
  print(line)
  print(url)
  data = vtobject.geturlreport(url)
  if data:
    vtobject.printurlreport(data)
    print(line)
  else:
    print("(!) - URL not found... submitting scan")
    scandata = vtobject.getunseenurlscanv2(url)
    #print("SCANID: scandata)
    vtobject.keepitcookin(scandata['scan_id'])
    

if __name__ == '__main__':
  main()

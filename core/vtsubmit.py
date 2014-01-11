#!/usr/bin/python

"""
 Copyright (c) 2014/2016 lain <lain@braincakes.org>
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
     1) Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
     2) Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
     3) Neither the name of the <organization> nor the
        names of its contributors may be used to endorse or promote products
        derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import simplejson
import urllib
import urllib2
import postfile
import sys
import os
import time
import hashlib
import optparse
import subprocess
from re import split
from sys import stdout
from urllib2 import HTTPError

sha = ""
url_send_scan_file = "https://www.virustotal.com/vtapi/v2/file/scan"
url_rescan_file = "https://www.virustotal.com/vtapi/v2/file/rescan"
url_retrieve_file_scan_report = "https://www.virustotal.com/vtapi/v2/file/report"
url_send_scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
url_retrieve_url_scan_report = "https://www.virustotal.com/vtapi/v2/url/report"
url_retrieve_ip_address_report = "https://www.virustotal.com/vtapi/v2/ip-address/report"
url_retrieve_domain_report = "https://www.virustotal.com/vtapi/v2/domain/report"
url_make_comments = "https://www.virustotal.com/vtapi/v2/comments/put"
url_vt = "www.virustotal.com"


class VTSubmit:

    def __init__(self,api_key=None):
        self.api_key = api_key
        self.sha = sha
        self.url_scanfile = url_send_scan_file
        self.url_rescanfile = url_rescan_file
        self.url_reportfile = url_retrieve_file_scan_report
        self.url_scanurl = url_send_scan_url
        self.url_reporturl = url_retrieve_url_scan_report
        self.url_reportip = url_retrieve_ip_address_report
        self.url_reportdomain = url_retrieve_domain_report
        self.url_comment = url_make_comments
        self.url_vt = url_vt

    def sha256sum(self,filePath=""):  		 
        try:
            fh = open(filePath, "rb")
            m = hashlib.sha256()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
        except Exception: 
            return "FileNotFound"

    def timer(self):
        print "Waiting 15 seconds"
        time.sleep(15)

    def submit_file(self,file): 	
        fields = [("apikey", self.api_key)]
        file2send = open(file, "rb").read()
        files = [("file", file, file2send)]
        json = postfile.post_multipart(self.url_vt, self.url_scanfile, fields, files)
        return json

    def resubmit_file(self,resource):
        parameters = {"resource": resource, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url_rescanfile, data)
        try:
            response = urllib2.urlopen(req)
            json = response.read()
            return json
        except HTTPError as e:
            return e.code

    def submit_url(self,url):
        parameters = {"url": url, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url_scanurl, data)
        try:
            response = urllib2.urlopen(req)
            json = response.read()
            return json
        except HTTPError as e:
            return e.code

    def submit_comment(self,resource,comment):
        parameters = {"resource": resource, "comment": comment, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url_comment, data)
        try:
            response = urllib2.urlopen(req)
            json = response.read()
            return json
        except HTTPError as e:
            return e.code

    def retrieve_file_report(self,hash,file):
        self.sha = hash
        self.file = file	
        parameters = {"resource": self.sha, "apikey": self.api_key}
        print "----------------------------------------------"
        print "Checking: ", self.file
        print "SHA256: ", self.sha
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url_reportfile, data)
        try:
            response = urllib2.urlopen(req)
            json = response.read()
            return json
        except HTTPError as e:
	    return e.code

    def retrieve_ip_report(self,ip):
        self.ip = ip
        parameters = {"ip": self.ip, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        try:
            json = urllib.urlopen('%s?%s' % (self.url_reportip, data)).read()
            return json
        except HTTPError as e:
            return e.code        
    
    def retrieve_domain_report(self,domain):
        self.domain = domain
        parameters = {"domain": self.domain, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        try:
            json = urllib.urlopen('%s?%s' % (self.url_reportdomain, data)).read()
            return json
        except HTTPError as e:
            return e.code

    def report_log(self,isnew,json):
        self.isnew = isnew
        self.json = json
        n = open("./log/report.log", "a")
        n.write ("\n\nReport: " + str(self.isnew))
        if self.isnew != "Rescan" and self.isnew != "URL":
            n.write ("\nFilename: " + str(self.file))
        if self.isnew != "URL":
            n.write ("\nSHA256: " + json.get("sha256"))
        if self.isnew != "Rescan" and self.isnew != "URL":
            n.write ("\nSHA1: " + json.get("sha1"))
            n.write ("\nMD5: " + json.get("md5"))
        if self.isnew == "URL":
            n.write ("\nURL: " + json.get("url"))
        try: 
            if str(json.get("positives")) == "None":
                n.write ("\nDetection Ratio: The requested resource is not among the finished")
            else:
                n.write ("\nDetection Ratio: " + str(json.get("positives")) + "/" + str(json.get("total")))
        except KeyError: 
            n.write ("\nDetection Ratio: Unknown" )
            pass
        n.write ("\nLink report: " + json.get("permalink"))
        n.close 

    def scan_file(self,file):
        self.sha = self.sha256sum(file)
        self.file = file
        if "FileNotFound" in self.sha:
            print "----------------------------------------------"
            print "Error - Sample: ", self.file, " Not Found on system. Find it and check manually."
        else:
            response = self.retrieve_file_report(self.sha, self.file)
            if response == 403:
                print "----------------------------------------------"
	        print "HTTP Error - 403 You do not have the required privileges."
                print "Review API Key."
                sys.exit(1)
            else: 
                response_dict = simplejson.loads(response)
                status = response_dict.get("response_code")
                message = response_dict.get("verbose_msg")         
                if int(status) == 0 or int(status) == -2:
                    print "New sample: ", self.file
                    print "The requested resource is not among the finished, queued or pending scans. Go for the report ./log/report.log"
                    print "----------------------------------------------"
                    newstatus = self.submit_file(self.file)
                    response_dict = simplejson.loads(newstatus)
                    self.report_log("New sample", response_dict)
                if int(status) == 1:
                    print "Sample: ", self.file
                    print "Scan finished. Go for the report ./log/report.log"
                    print "----------------------------------------------"
                    self.report_log("Sample already reported", response_dict)
                    
    def scan_folder(self,directory):
        self.directory = directory
        files = os.listdir(self.directory)
        for file in files:
            self.file = self.directory + file
            self.scan_file(self.file)
            self.timer()

    def rescan_file(self,resource):
        self.sha = resource
        print "----------------------------------------------"
        print "Rescanning sample:", self.sha
        response = self.resubmit_file(self.sha)
        if response == 403:
                print "----------------------------------------------"
                print "HTTP Error - 403 You do not have the required privileges."
                print "Review API Key."
                sys.exit(1)
        else:
            response_dict = simplejson.loads(response)
            status = response_dict.get("response_code")
            message = response_dict.get("verbose_msg")
            if int(status) == -1:
	        print "Error - Check input data (ex: --rescanfile 'md5/sha1/sha256')" 
                print "----------------------------------------------"
                sys.exit(1)
            else:
                print "The requested resource is not among the finished, queued or pending scans. Go for the report ./log/report.log"
                self.report_log("Rescan", response_dict)

    def scan_url(self,url):
        self.url = url
        print "----------------------------------------------"
        print "Scanning URL: ", self.url
        response = self.submit_url(self.url)
        if response == 403:
            print "----------------------------------------------"
            print "HTTP Error - 403 You do not have the required privileges."
            print "Review API Key."
            sys.exit(1)
        else:
            response_dict = simplejson.loads(response)
            status = response_dict.get("response_code")
            message = response_dict.get("verbose_msg")
            if int(status) == 1:
                print message, "./log/report.log"
                self.report_log("URL", response_dict)
                print "----------------------------------------------"
            else:
                print "Error -", message
                print "----------------------------------------------"

    def scan_url_file(self,ufile):
        self.ufile = ufile
        f = open(self.ufile)
        for url in f:
            self.scan_url(url)
            self.timer()
        f.close()

    def send_comment(self,resource,comment):
        self.resource = resource
        self.comment = comment
        response = self.submit_comment(self.sha,self.comment)  
        if response == 403:
            print "----------------------------------------------"
            print "HTTP Error - 403 You do not have the required privileges."
            print "Review API Key."
            sys.exit(1)
        else:
            response_dict = simplejson.loads(response)
            status = response_dict.get("response_code")
            message = response_dict.get("verbose_msg")
            if int(status) == 1:
                print message
            else:
                print "Error -",message 

    def retrieve_ip(self,ip):
        self.ip = ip
        response = self.retrieve_ip_report(self.ip)
        if response == 403:
            print "----------------------------------------------"
            print "HTTP Error - 403 You do not have the required privileges."
            print "Review API Key."
            sys.exit(1)
        else:
            response_dict = simplejson.loads(response)
            status = response_dict.get("response_code")
            message = response_dict.get("verbose_msg")
            if int(status) == 1:
                print "----------------------------------------------"
                print "Retrieving IP Address Report:", self.ip
                if response_dict.get("resolutions") is not None and len(response_dict.get("resolutions"))>0:
                    print "\nResolutions:"
                    print "------------"
                    for r in response_dict.get("resolutions"):
                        print "\nLast Resolved:",r.get("last_resolved")
                        print "Hostname:", r.get("hostname") 
                
                if response_dict.get("detected_urls") is not None and len(response_dict.get("detected_urls"))>0:
                   print "\nDetected URLs:"
                   print "--------------"
                   for d in response_dict.get("detected_urls"):
                        print "\nURL:", d.get("url")
                        print "Positives:", d.get("positives")
                        print "Total:",d.get("total")
                        print "Scan Date:", d.get("scan_date")
                if response_dict.get("undetected_downloaded_samples") is not None and len(response_dict.get("undetected_downloaded_samples"))>0:
                   print "\nUndetected downloaded samples:"
                   print "------------------------------"
                   for u in response_dict.get("undetected_downloaded_samples"):
                        print "\nDate:", u.get("date")
                        print "Positives:", u.get("positives")
                        print "Total:",u.get("total")
                        print "SHA256:", u.get("sha256")
                if response_dict.get("detected_downloaded_samples") is not None and len(response_dict.get("detected_downloaded_samples"))>0:
                   print "\nDetected downloaded samples:"
                   print "----------------------------"
                   for s in response_dict.get("detected_downloaded_samples"):
                        print "\nDate:", s.get("date")
                        print "Positives:", s.get("positives")
                        print "Total:",s.get("total")
                        print "SHA256:", s.get("sha256")
                print "----------------------------------------------"
            else:
                print "----------------------------------------------"
                print "Error -",message 
                print "----------------------------------------------"

    def retrieve_domain(self,domain):
        self.domain = domain
        response = self.retrieve_domain_report(self.domain)
        if response == 403:
            print "----------------------------------------------"
            print "HTTP Error - 403 You do not have the required privileges."
            print "Review API Key."
            sys.exit(1)
        else:
            response_dict = simplejson.loads(response)
            status = response_dict.get("response_code")
            message = response_dict.get("verbose_msg")
            if int(status) == 1:
                print "----------------------------------------------"
                print "Retrieving Domain Report:", self.domain
                if response_dict.get("resolutions") is not None and len(response_dict.get("resolutions"))>0:
                    print "\nResolutions:"
                    print "------------"
                    for r in response_dict.get("resolutions"):
                        print "\nLast Resolved:",r.get("last_resolved")
                        print "IP Address:", r.get("ip_address")

                if response_dict.get("detected_urls") is not None and len(response_dict.get("detected_urls"))>0:
                   print "\nDetected URLs:"
                   print "--------------"
                   for d in response_dict.get("detected_urls"):
                        print "\nURL:", d.get("url")
                        print "Positives:", d.get("positives")
                        print "Total:",d.get("total")
                        print "Scan Date:", d.get("scan_date")
                if response_dict.get("undetected_downloaded_samples") is not None and len(response_dict.get("undetected_downloaded_samples"))>0:
                   print "\nUndetected downloaded samples:"
                   print "------------------------------"
                   for u in response_dict.get("undetected_downloaded_samples"):
                        print "\nDate:", u.get("date")
                        print "Positives:", u.get("positives")
                        print "Total:",u.get("total")
                        print "SHA256:", u.get("sha256")
                if response_dict.get("detected_downloaded_samples") is not None and len(response_dict.get("detected_downloaded_samples"))>0:
                   print "\nDetected downloaded samples:"
                   print "----------------------------"
                   for s in response_dict.get("detected_downloaded_samples"):
                        print "\nDate:", s.get("date")
                        print "Positives:", s.get("positives")
                        print "Total:",s.get("total")
                        print "SHA256:", s.get("sha256")
                print "----------------------------------------------"
            else:
                print "----------------------------------------------"
                print "Error -",message
                print "----------------------------------------------"

    def run(self):
        usage = "usage: python %prog [options]"

        parser = optparse.OptionParser()
        parser.set_usage(usage)

        parser.add_option("--scanfile", dest="file", help="Sending and scanning a file (ex: --scanfile 'file_path')", default=None)
        parser.add_option("--scanfolder", dest="folder", help="Sending and scanning files in a folder (ex: --scanfolder 'folder_path')", default=None)
        parser.add_option("--rescanfile", dest="rescanfile", help="Rescanning already submitted files (ex: --rescanfile 'md5/sha1/sha256')", default=None)
        parser.add_option("--scanurl", dest="url", help="Sending and scanning an URL (ex: --scanurl 'URL')", default=None)
        parser.add_option("--scanurlfile", dest="urlfile", help="Sending and scanning a file with a list of URLs (ex: --scanurlfile 'file_path')", default=None)
        parser.add_option("--reportip", dest="reportip", help="Retrieving IP address reports (ex: --reportip 'IP')", default=None)
        parser.add_option("--reportdomain", dest="reportdomain", help="Retrieving domain reports (ex: --reportdomain 'domain')", default=None)
        parser.add_option("--comment", dest="comment", help="Make comments on files and URLs (ex: --comment 'URL' 'comment' or --comment 'md5/sha1/sha256' 'comment')", default=None)


        (options,args) = parser.parse_args()

        from config import api
        for key in api:
            api_key = key['key']

        if self.api_key == '':
	    print 'Error - You must set API Key. Go to www.virustotal.com to get one.'
            sys.exit(1)

        if options.file != None:
            if os.path.isfile(options.file):
                vtsubmit = VTSubmit(api_key)
                vtsubmit.scan_file(options.file)
            else:
                print "Error - File doesn't exist"
                sys.exit(1)

        elif options.folder != None:
            if os.path.isdir(options.folder):
                vtsubmit = VTSubmit(api_key)
                vtsubmit.scan_folder(options.folder)
            else:
                print "Error - Folder doesn't exist"
                sys.exit(1)

        elif options.rescanfile != None:
            vtsubmit = VTSubmit(api_key)
            vtsubmit.rescan_file(options.rescanfile)
 
        elif options.url != None:
            vtsubmit = VTSubmit(api_key)
            vtsubmit.scan_url(options.url)

        elif options.urlfile != None:
            vtsubmit = VTSubmit(api_key)
            vtsubmit.scan_url_file(options.urlfile)

        elif options.reportip != None:
            vtsubmit = VTSubmit(api_key)
            vtsubmit.retrieve_ip(options.reportip)

        elif options.reportdomain != None:
            vtsubmit = VTSubmit(api_key)
            vtsubmit.retrieve_domain(options.reportdomain)

        elif options.comment != None:
            vtsubmit = VTSubmit(api_key)
            if len(args) == 1:
                vtsubmit.send_comment(options.comment,args[0])
            else:
                print "Error - Check input data (ex: --comment 'md5/sha1/sha256' 'comment')"
        else:
            parser.print_help()
            print ""
            sys.exit(1)
 



# -*- coding: utf-8 -*-
"""
Created on Thu Nov  9 16:20:54 2023

@author: alex
"""

import os
import subprocess


tshark = "C:\\Program Files\\Wireshark\\tshark.exe"

class TShark:
    def __init__(self,pcap_file):
        self.pcap_file = pcap_file
        self.proc = None
        
        if not os.path.isfile(tshark):
            print("Cannot find tshark in " + tshark)
            return
        
    def start(self,iface,guest_ip = None):
        pargs = [tshark,'-p','-i',iface]
        pargs.extend(['-w',self.pcap_file])
        if guest_ip:
            pargs.extend(['-f','host %s' % guest_ip])
            
        self.proc = subprocess.Popen(pargs)
        
        
    def stop(self):
        if self.proc != None and self.proc.poll() == None:
            self.proc.terminate()
            
    def read(self): 
        proc = subprocess.Popen(
            [
            tshark, '-z', 'http_req,tree', 
            '-z', 'ip_hosts,tree', '-z', 'io,phs', 
            '-r', self.pcap_file
            ], 
            stdout=subprocess.PIPE
            )
        return proc.communicate()[0]
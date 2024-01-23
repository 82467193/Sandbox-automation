# -*- coding: utf-8 -*-
"""
Only used for exe file, other file types might cause exception
"""

"""
Take away the login phase vmware doesn't provide any features for us to do auto login!!!!!'
"""


"""
Created on Thu Nov  9 13:24:23 2023

@author: alex
"""

from vt import Analyze
from vmauto import VMwareAuto
import os
import time
import analysis
import sys
import hashlib

report_path = "C:\\Users\\alex\\Desktop\\Malware_Report"

user = "Ban"
passwd = "0000"

#VM's guest IP
guest_ip = "192.168.248.129"

guest_vmx = "C:\\Malware VM\\Windows 10 x64.vmx"

def printhdr(name):
    print('#' * 75)
    print('#' + name)
    print('#' * 75)
    
def analyze(vm,sample,rdir,inetsim):
        
    printhdr("Submission details")
    #Virustotal detailed information
    Analyze(sample)
    #test Analyze !!!!!!!!!!!!!!!!!!!
    #return
    #Revert to clean image
    #vm.revert("Windows 10 x64-Snapshot1")
    #Must use the name in vmware not in directory for exmaple : Flare VM instead of win10 x64...
    #VM does not accept empty password it means we need a login session
    vm.revert("Flare VM2")
    #VM start
    vm.start()
    time.sleep(15)
    vm.setuser(user,passwd)
    
    dst = "C:\\%s" % os.path.basename(sample)
    vm.copytovm(sample,dst)
    time.sleep(5)
    #delete the malicious file right after it copies to VM
    os.remove(sample)
    
    pcap = analysis.TShark(rdir + "/file.pcap")
    pcap.start('VMware Network Adapter VMnet8',guest_ip)
    
    if inetsim:
        inet = analysis.INetSim(rdir)
        inet.start()
        
    vm.winexec(dst)
    time.sleep(60)
    
    vm.scrshot(rdir + "/shot.bmp")
    
    vm.suspend()
    
    if inetsim:
        inet.stop()
        logs = inet.read()
        if len(logs):
            printhdr('Inetsim Logs')
            print(logs)
            
    printhdr('Network Traffic')
    pcap.stop()
    print(pcap.read().decode())
    
def main(argv):
    if len(sys.argv) < 2:
        print('Usage: %s <file> [--inetsim]' % argv[0])
        return
    if sys.argv[len(sys.argv)-1] == '--inetsim':
        inetsim = True
    else:
        inetsim = False
        
    vm = VMwareAuto(guest_vmx)
    
    if os.path.isfile(sys.argv[1]):
        rdir = report_path + \
            os.path.sep + \
            hashlib.md5(open(sys.argv[1],'rb').read()).hexdigest()
            
        try:
            print("Analysis result will be stored in %s" % rdir)
            os.mkdir(rdir)
        except:
            pass
        
        analyze(vm,sys.argv[1],rdir,inetsim)
    else:
        print('You must supply a file to analyze')
        return
    
if __name__ == '__main__':
    main(sys.argv)
        
        
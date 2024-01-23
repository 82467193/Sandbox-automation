import requests

class Analyze:
    def __init__(self,sample):
        print("###ID\n")
        id = self.pescan(sample)
        print("###Hash\n")
        h = self.retrieve_hash(id)
        print("###File Info")
        self.getFile(h)
        print("###File Behavior\n")
        self.fileBehave(h)
        print("###ATT&CK\n")
        self.attck(h)
    
    def fileBehave(self,hash):
        print("-------------------------------------------------------\n")
        url = "https://www.virustotal.com/api/v3/files/%s/behaviour_summary" % hash
    
        headers = {
            "accept": "application/json",
            "x-apikey": "4a29ac52d025cb1ed75f14731f48a0ed22db5d83efcd7e0c4d2f577affdf02ed"
        }
        
        response = requests.get(url, headers=headers)
        print(response.text)
        rjson = response.json()
        #Registry opened
        if(response.status_code != 200):
            print("Failed getting behaviors")
            print("-------------------------------------------------------\n")
            return
        reg_keys = rjson['data']['registry_keys_opened']
        for i in reg_keys:
            print("Reg keys opened : %s\n" % i)
        print("-------------------------------------------------------\n")
    
    def attck(self,hash):
        print("-------------------------------------------------------\n")
    
        url = "https://www.virustotal.com/api/v3/files/%s/behaviour_mitre_trees" % hash
    
        headers = {
            "accept": "application/json",
            "x-apikey": "4a29ac52d025cb1ed75f14731f48a0ed22db5d83efcd7e0c4d2f577affdf02ed"
        }
        
        response = requests.get(url, headers=headers)
        if(response.status_code != 200):
            print("Failed getting att&ck")
            print("-------------------------------------------------------\n")
            return
        print(response.text)
        print("-------------------------------------------------------\n")
    
    def getFile(self,hash):
        print("-------------------------------------------------------\n")
    
        url = "https://www.virustotal.com/api/v3/files/%s" % hash
    
        headers = {
            "accept": "application/json",
            "x-apikey": "4a29ac52d025cb1ed75f14731f48a0ed22db5d83efcd7e0c4d2f577affdf02ed"
        }
        
        response = requests.get(url, headers=headers)
        if(response.status_code != 200):
            print("File retrieve failed")
            print("-------------------------------------------------------\n")
            return
        print(response.text)
        print("-------------------------------------------------------\n")
    
    def retrieve_hash(self,id):
        print("-------------------------------------------------------\n")
    
        url = "https://www.virustotal.com/api/v3/analyses/%s" % id
    
        headers = {
            "accept": "application/json",
            "x-apikey": "4a29ac52d025cb1ed75f14731f48a0ed22db5d83efcd7e0c4d2f577affdf02ed"
        }
    
        response = requests.get(url, headers=headers)
        if(response.status_code != 200):
            print("Retrieve hash failed")
            print("-------------------------------------------------------\n")
            return
        
        rjson = response.json()
        sha256 = rjson['meta']['file_info']['sha256']
        print("sha256 = " + rjson['meta']['file_info']['sha256'] + '\n')
        print("sha1 = " + rjson['meta']['file_info']['sha1'] + '\n')
        print("md5 = " + rjson['meta']['file_info']['md5'] + '\n')
        print("-------------------------------------------------------\n")
    
        return sha256
        #getFile(sha256)
        
    def pescan(self,sample):
        #only for exe now
        print("-------------------------------------------------------\n")
        url = "https://www.virustotal.com/api/v3/files"
    
        files = { "file": (sample, open(sample, "rb"), "application/x-msdownload") }
        headers = {
            "accept": "application/json",
            "x-apikey": "4a29ac52d025cb1ed75f14731f48a0ed22db5d83efcd7e0c4d2f577affdf02ed"
        }
        response = requests.post(url, files=files, headers=headers)
        status_code = response.status_code
        if(status_code != 200):
            print("Upload file %s failed" % sample)
            print("-------------------------------------------------------\n")
            return
        
        rjson = response.json()
        #id for /file analysis
        id = rjson['data']['id']
        print("id= %s\n" % id)
        print("-------------------------------------------------------\n")
    
        return id
        #retrieve_hash(id)
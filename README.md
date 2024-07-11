# ARLtoAWVS
ARL links with AWVS to realize automated scanning and push results

### Domain and directories
Refer to the dirsearch and subDomainsBrute dictionaries

domain_2w.txt

file_top_2000.txt

replace /opt/ARL/app/dicts/

### use
Modify the configuration CONFIG in the script

```shell
CONFIG = {
    'arl_url': 'https://ARLURL:5003',
    'username': 'admin1',
    'password': 'admin123',
    'awvs_url': 'https://AWVSURL:13443',
    'key': 'XXXXXXXXXXXXXXXXX',
    'profile_id': '11111111-1111-1111-1111-111111111111', //漏洞扫描模板
    'push_plus_url': 'http://www.pushplus.plus/send',
    'push_token': 'xxxx-push_token',
    'time_sleep': 1800,  # 秒
    'get_size': 100,  # 每次获取任务数
}

```
```shell
git clone https://github.com/InsBug/ARLtoAWVS.git
cd ARLtoAWVS
python3 arltoawvs.py
```

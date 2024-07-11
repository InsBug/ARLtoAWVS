# ARLtoAWVS
ARL与AWVS联动，实现自动化扫描并推送结果

### 域名字典和目录字典
参考 dirsearch 和 subDomainsBrute 字典

domain_2w.txt

file_top_2000.txt

替换 /opt/ARL/app/dicts/目录下的文件

### 使用
修改文件里的配置，改为自己的地址和key。

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

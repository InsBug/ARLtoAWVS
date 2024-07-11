import requests
import json
import socket
import sys
import time
import os
import logging
from time import strftime, gmtime

from requests import RequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
import threading


# 配置信息
CONFIG = {
    'arl_url': 'https://xxx.xxx.xxx.xxx:5003',
    'username': 'admin1',
    'password': 'admin123',
    'awvs_url': 'https:/xxx.xxx.xxx.xxx:13443',
    'key': 'xxxxxxxxxxxxxxxxxxxxxxxxxx',
    'profile_id': '11111111-1111-1111-1111-111111111111',
    'push_plus_url': 'http://www.pushplus.plus/send',
    'push_token': 'xxxxxxxxxxxxxxxxxxxx',
    'time_sleep': 1800,  # 秒
    'get_size': 100,  # 每次获取任务数
}

# 初始化日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 禁用InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

def login_to_arl(config):
    """登录到ARL并返回Token."""
    data = json.dumps({"username": config['username'], "password": config['password']})
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(config['arl_url'] + '/api/user/login', data=data, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        return response.json()['data']['token']
    except RequestException as e:
        logger.error("登录ARL失败: %s", e)
        return None

def fetch_assets(config, token):
    """从ARL获取资产列表."""
    headers = {'Token': token, 'Content-Type': 'application/json'}
    try:
        response = requests.get(config['arl_url'] + '/api/task/', headers=headers, params={'page': 1, 'size': config['get_size']}, timeout=30, verify=False)
        response.raise_for_status()
        return [task['_id'] for task in response.json()['items'] if task['status'] == 'done']
    except RequestException as e:
        logger.error("获取资产失败: %s", e)
        return []

def export_sites(config, token, asset_ids):
    """导出指定资产的站点."""
    data = json.dumps({"task_id": asset_ids})
    headers = {'Token': token, 'Content-Type': 'application/json'}
    try:
        response = requests.post(config['arl_url'] + '/api/batch_export/site/', data=data, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        return response.text.split()
    except RequestException as e:
        logger.error("导出站点失败: %s", e)
        return []

def add_target_to_awvs(config, target_url):
    """将目标添加到AWVS并启动扫描."""
    data = json.dumps({"targets": [{"address": target_url, "description": "ARL-AUTO"}], "groups": []})
    headers = {'Content-Type': 'application/json', "X-Auth": config['key']}
    try:
        response = requests.post(config['awvs_url'] + '/api/v1/targets/add', data=data, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        target_id = response.json()['targets'][0]['target_id']
        return target_id
    except RequestException as e:
        logger.error("添加目标到AWVS失败: %s", e)
        return None

def start_scan(config, target_id):
    """启动AWVS扫描."""
    scan_data = {
        "target_id": target_id,
        "profile_id": config['profile_id'],
        "incremental": False,
        "schedule": {
            "disable": False,
            "start_date": None,
            "time_sensitive": False
        }
    }
    headers = {'Content-Type': 'application/json', "X-Auth": config['key']}
    try:
        response = requests.post(config['awvs_url'] + '/api/v1/scans', json=scan_data, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        logger.info("扫描任务启动成功")
    except RequestException as e:
        logger.error("启动扫描任务失败: %s", e)

def push_plus_notification(config, title, content):
    """使用PushPlus发送通知."""
    push_data = {
        "token": config['push_token'],
        "title": title,
        "content": content
    }
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(config['push_plus_url'], json=push_data, headers=headers, timeout=30)
        response.raise_for_status()
        logger.info("PushPlus推送成功")
    except RequestException as e:
        logger.error("PushPlus推送失败: %s", e)

def check_vulnerabilities(config, token):
    """检查AWVS中的漏洞并准备推送通知."""
    try:
        get_target_url = f"{config['awvs_url']}/api/v1/vulnerability_types?l=100&q=status:open;severity:2;" # 漏洞等级4为严重、3为高危
        response = requests.get(get_target_url, headers={'X-Auth': config['key']}, timeout=30, verify=False)
        response.raise_for_status()
        result = response.json()
        init_high_count = sum(item['count'] for item in result['vulnerability_types'])
        return init_high_count, result
    except RequestException as e:
        logger.error("检查高危漏洞失败: %s", e)
        return None, None

def monitor_vulnerabilities(config, token):
    """监控AWVS中的漏洞并发送通知."""
    init_high_count, _ = check_vulnerabilities(config, token)
    if init_high_count is None:
        return

    while True:
        time.sleep(10)
        current_high_count, result = check_vulnerabilities(config, token)
        if current_high_count != init_high_count:
            message_title = '安全漏洞通知'
            message_content = f"{socket.gethostname()}\n{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            for item in result['vulnerability_types']:
                message_content += f"漏洞: {item['name']} 数量: {item['count']}\n"
            logger.info("推送高危漏洞通知")
            push_plus_notification(config, message_title, message_content)
            init_high_count = current_high_count

def main():
    token = login_to_arl(CONFIG)
    if token:
        threading.Thread(target=monitor_vulnerabilities, args=(CONFIG, token)).start()
        while True:
            asset_ids = fetch_assets(CONFIG, token)
            sites = export_sites(CONFIG, token, asset_ids)
            for site in set(sites):
                if site:  # 确保不是空字符串
                    target_id = add_target_to_awvs(CONFIG, site)
                    if target_id:
                        start_scan(CONFIG, target_id)
            time.sleep(CONFIG['time_sleep'])
    else:
        logger.error("无法获取有效的登录Token，程序将退出")

if __name__ == "__main__":
    main()

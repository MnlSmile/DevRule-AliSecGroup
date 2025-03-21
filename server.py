import time
import base64
import json

from dns import resolver
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526.client import Client as Client
from alibabacloud_ecs20140526 import models as models


try:
    with open('./server_config.json','r', encoding='utf-8') as f:
        config = json.load(f)
except FileNotFoundError:
    with open('./server_config.json','r', encoding='utf-8') as f:
        json.dump({'domains': [], 'access_key': '', 'access_secret': ''}, f, indent=4)
target_domains:list[str] = config['domains']
access_key:str = config['access_key']
access_secret:str = config['access_secret']
sec_group_rule_description:str = config['sec_group_rule_description']


ali_cfg = open_api_models.Config(
    access_key_id=access_key,
    access_key_secret=access_secret
)
ali_cfg.endpoint = 'ecs.cn-shenzhen.aliyuncs.com'
client = Client(ali_cfg)


def query_specific_sec_group_rule() -> list:
    return

def update_sec_group_rule(ips:list) -> None:
    return

def query_ip(domain:str) -> str:
    r = resolver.resolve(domain, 'TXT')
    bv = r[0].strings[0].decode()
    ip = base64.b64decode(bv).decode()
    return ip

print(query_ip(target_domains[0]))
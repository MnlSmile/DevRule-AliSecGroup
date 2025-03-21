import requests
import base64
import json

from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_alidns20150109.client import Client as Client
from alibabacloud_alidns20150109 import models as models


try:
    with open('./client_config.json','r', encoding='utf-8') as f:
        config = json.load(f)
except FileNotFoundError:
    with open('./client_config.json','r', encoding='utf-8') as f:
        json.dump({'domain': '', 'access_key': '', 'access_secret': ''}, f, indent=4)
target_domain:str = config['domain']
access_key:str = config['access_key']
access_secret:str = config['access_secret']


ali_cfg = open_api_models.Config(
    access_key_id=access_key,
    access_key_secret=access_secret
)
ali_cfg.endpoint = 'alidns.cn-shenzhen.aliyuncs.com'
client = Client(ali_cfg)


def get_intn_ipv4_addr() -> str:
    for i in range(5):
        try:
            resp = requests.get('https://ipv4.ip.mir6.com/')
        except Exception:
            continue
        else:
            break
    ip = resp.text
    return ip

def get_record() -> dict:
    req = models.DescribeDomainRecordsRequest()
    req.domain_name = '.'.join(target_domain.split('.')[-2:])
    resp = client.describe_domain_records(req)
    for dr in resp.to_map()['body']['DomainRecords']['Record']:
        if '.'.join(target_domain.split('.')[:-2]) == dr['RR']:
            return dr

ipv4_addr = get_intn_ipv4_addr()

def update_domain() -> None:
    req = models.UpdateDomainRecordRequest()
    rc = get_record()
    req.record_id = rc['RecordId']
    new_value = base64.b64encode(ipv4_addr.encode('utf-8')).decode('utf-8')
    if rc['Value'] == new_value:
        return
    req.rr = '.'.join(target_domain.split('.')[:-2])
    req.type = 'txt'
    req.value = new_value
    r = client.update_domain_record(req)

def main():
    update_domain()

if __name__ == '__main__':
    main()
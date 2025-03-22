import time
import base64
import json
import uuid
import requests

from dns import resolver
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526.client import Client as Client
from alibabacloud_ecs20140526 import models as models


try:
    with open('./server_config.json','r', encoding='utf-8') as f:
        config = json.load(f)
except FileNotFoundError:
    with open('./server_config.json','r', encoding='utf-8') as f:
        json.dump(
            obj = {
                "domains": ['str', 'str', '...'],
                "access_key": "str",
                "access_secret": "str",
                "sec_group_rule_description": "str",
                "security_group_id": "str",
                "region_id": "str",
                "ports": ['str/str | int', 'str/str | int', '...']
            },
            fp = f,
            indent = 4
        )
target_domains:list[str] = config['domains']
target_ports:list[str] = list(set([(f"{str(int(float(p)))}/{str(int(float(p)))}" if type(p) != str else p) for p in config['ports']]))
access_key:str = config['access_key']
access_secret:str = config['access_secret']
sec_group_id:str = config['security_group_id']
region_id:str = config['region_id']
sec_group_rule_description:str = config['sec_group_rule_description']

def is_aliyun_ecs() -> bool:
    try:
        r = requests.get('http://100.100.100.200/latest/meta-data/', timeout=1)
        return r.status_code == 200
    except Exception:
        return False


ali_cfg = open_api_models.Config(
    access_key_id = access_key,
    access_key_secret = access_secret
)
ali_cfg.endpoint = 'ecs-vpc.cn-shenzhen.aliyuncs.com' if is_aliyun_ecs() else 'ecs.cn-shenzhen.aliyuncs.com'
client = Client(ali_cfg)


def create_specific_sec_group_rule(domain:str, ipaddr:str, port:str) -> None:
    req = models.AuthorizeSecurityGroupRequest(
        region_id = region_id,
        security_group_id = sec_group_id,
        ip_protocol = 'TCP',
        description = f"{sec_group_rule_description}({domain},{port})",
        source_cidr_ip = ipaddr,
        port_range = port,
        client_token = str(uuid.uuid4())
    )
    r = client.authorize_security_group(req)
    return

def query_specific_sec_group_rules(domains:list=[]) -> list:
    result = []
    req = models.DescribeSecurityGroupAttributeRequest(
        security_group_id = sec_group_id,
        region_id = region_id,
        direction = 'ingress'
    )
    resp = client.describe_security_group_attribute(req)
    for rl in resp.to_map()['body']['Permissions']['Permission']:
        for dm in domains:
            for port in target_ports:
                if f"{sec_group_rule_description}({dm},{port})" == rl['Description']:
                    result.append(rl)
    return result

def update_sec_group_rules(domain:str, ipaddr:str, port:str, rule_id:str) -> None:
    req = models.ModifySecurityGroupRuleRequest(
        region_id = region_id,
        security_group_id = sec_group_id,
        security_group_rule_id = rule_id,
        ip_protocol = 'TCP',
        description = f"{sec_group_rule_description}({domain},{port})",
        source_cidr_ip = ipaddr,
        port_range = port,
        client_token = str(uuid.uuid4())
    )
    r = client.modify_security_group_rule(req)
    return

def query_ip(domain:str) -> str:
    reso = resolver.Resolver()
    reso.nameservers = ['223.5.5.5', '119.29.29.29']
    for i in range(10):
        try:
            r = reso.resolve(domain, 'TXT')
            bv = r[0].strings[0].decode()
            ip = base64.b64decode(bv).decode()
        except Exception:
            return None
        else:
            return ip if len(ip.split('.')) == 4 else None

def update_once():
    current_rules = query_specific_sec_group_rules(target_domains)
    current_rules_existed_rule = [rl['Description'] for rl in current_rules]
    for dm in target_domains:
        ip = query_ip(dm)
        for port in target_ports:
            if not current_rules:
                create_specific_sec_group_rule(
                        domain = dm,
                        ipaddr = ip,
                        port = port
                    )
                print(
                        f"Created {f"{sec_group_rule_description}({dm},{port})"} due to empty current rules -> {ip}"
                    )
                continue
            for rl in current_rules:
                if f"{sec_group_rule_description}({dm},{port})" in current_rules_existed_rule:
                    if ip not in rl['SourceCidrIp']:
                        update_sec_group_rules(
                            rule_id = rl['SecurityGroupRuleId'],
                            domain = dm,
                            ipaddr = ip,
                            port = port
                        )
                        print(
                            f"Modified {f"{sec_group_rule_description}({dm},{port})"} -> {ip}"
                        )
                    else:
                        print(
                            f"Passed modify {f"{sec_group_rule_description}({dm},{port})"} while meeting {rl['Description']}"
                        )
                else:
                    create_specific_sec_group_rule(
                        domain = dm,
                        ipaddr = ip,
                        port = port
                    )
                    print(
                        f"Created {f"{sec_group_rule_description}({dm},{port})"} due to specific rule not found -> {ip}"
                    )

def main():
    while True:
        update_once()
        time.sleep(300)

if __name__ == '__main__':
    main()
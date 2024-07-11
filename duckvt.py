import requests
import argparse
import duckdb
import json 
from dotenv import dotenv_values

config = dotenv_values(".env")
api_key = config["api_key"]
parser = argparse.ArgumentParser(
                    prog='DuckHunt',
                    description='Threat hunting leveraging VT and Duckdb',
                    epilog='Built by ChalkingCode')
parser.add_argument('-gn','--get_name', help='''Get data from VT endpoints, example answers: 
                                                popular_threat_categories,
                                                ip_report -ip is needed,
                                                domain_report -d is needed,
                                                attack_tactic_object -id is needed,
                                                attack_technique_object -id is needed,
                                                file_report -id is needed,
                                                techniques_observed -id is needed,
                                                get_data -sql is needed
                                             ''')
parser.add_argument('-ip','--ip_address', help='ip address - needed for vt ip address report')
parser.add_argument('-d','--domain', help='domain needed for vt domain report')
parser.add_argument('-id','--id', help='id needed for some vt endpoints')
parser.add_argument('-sql','--sql_args', help='sql args needed for the duck db magic to read json files')
args = vars(parser.parse_args())

def main(args):
    print(args)
    if args['get_name'] == 'popular_threat_categories':
        get_popular_threat_categories(api_key)
    elif args['get_name'] == 'ip_report':
        get_ip_address_report(api_key, args)
    elif args['get_name'] == 'yara_rules':
        get_yara_ruleset(api_key)
    elif args['get_name'] == 'domain_report':
        get_domain_report(api_key, args)
    elif args['get_name'] == 'attack_tactic_object':
        get_attack_tactic_object(api_key, args)
    elif args['get_name'] == 'attack_technique_object':
        get_attack_technique_object(api_key, args)
    elif args['get_name'] == 'file_report':
        get_file_report(api_key, args)
    elif args['get_name'] == 'techniques_observed':
        get_techniques_observed(api_key, args)
    elif args['get_name'] == 'get_data':
        get_duck_data(args)
    else:
        print("Wrong arg choice please look at duckhunt.py -h")

def get_popular_threat_categories(api_key):
    file = "popular_threat_categories.json"
    headers = {'x-apikey': api_key,}
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    r = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_ip_address_report(api_key, args):
    ip = args['ip_address']
    file = "ip_address_report.json"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_yara_ruleset(api_key):
    file = "yara_ruleset.json"
    url = "https://www.virustotal.com/api/v3/yara_rules?limit=50"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_domain_report(api_key, args):
    domain = args['domain']
    file = f"{domain}_domain_report.json"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_attack_tactic_object(api_key, args):
    id = args['id']
    file = f"{id}_attack_tactic_object.json"
    url = f"https://www.virustotal.com/api/v3/attack_tactics/{id}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_attack_technique_object(api_key, args):
    id = args['id']
    file = f"{id}_attack_technique_object.json"
    url = f"https://www.virustotal.com/api/v3/attack_techniques/{id}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_file_report(api_key, args):
    id = args['id']
    file = f"{id}_file_report.json"
    url = f"https://www.virustotal.com/api/v3/files/{id}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_techniques_observed(api_key, args):
    id = args['id']
    file = f"{id}_techniques_observed.json"
    url = f"https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(f"Writing out report to file {file}")
    json_response = response.json()
    json_object = json.dumps(json_response, indent=4)
    with open(file, "w") as outfile:
        outfile.write(json_object)

def get_duck_data(args):
    sql_args = args['sql_args']
    data = duckdb.sql(f"{sql_args}")
    print(data)
    

main(args)

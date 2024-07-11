# DuckVT
A simple tool that leverages Virus Total API and DuckDB

## Features
- Grabs data from https://docs.virustotal.com/reference/.
- Output unique results for any given endpoint to a JSON file.
- Give you the ability to quickly search through the json files to find the data you want leveraging DuckDB and sql

## Table of contents
* [Features](#features)
* [Setup](#setup)
* [HowTo](#howto)

## Features
- Grabs data from https://docs.virustotal.com/reference/.
- Output unique results for any given endpoint to a JSON file.
- Give you the ability to quickly search through the json files to find the data you want leveraging DuckDB and sql

## Setup

### Prerequisites

#### Enviroment
```
1.) ensure you have python 3.x installed 
$ python3 -m venv /path/you/want/the/env/in
$ source /path/you/want/the/env/in/bin/activate 
```
#### Clone repository 

        $ git clone https://github.com/ChalkingCode/DuckVT.git
        $ cd DuckVT


#### Install Packages on env
```       
duckdb
requests
python-dotenv

# This only needs to be ran once per env 
$ pip install -r requirements.txt
```

#### Create .env file to store your Virus Total API key
```
$ vi .env # you could also vim .env or touch .env 
# once file opens 
api_key = "Your VT API KEY HERE" 

## HowTo

How to run the script that will search and grab your data 

```
$ python duckvt.py -h

usage: DuckHunt [-h] [-gn GET_NAME] [-ip IP_ADDRESS] [-d DOMAIN] [-id ID] [-sql SQL_ARGS]

Threat hunting leveraging VT and Duckdb

optional arguments:
  -h, --help            show this help message and exit
  -gn GET_NAME, --get_name GET_NAME
                        Get data from VT endpoints, example answers: popular_threat_categories, ip_report -ip is needed, domain_report -d is needed, attack_tactic_object -id is needed,
                        attack_technique_object -id is needed, file_report -id is needed, techniques_observed -id is needed, get_data -sql is needed
  -ip IP_ADDRESS, --ip_address IP_ADDRESS
                        ip address - needed for vt ip address report
  -d DOMAIN, --domain DOMAIN
                        domain needed for vt domain report
  -id ID, --id ID       id needed for some vt endpoints
  -sql SQL_ARGS, --sql_args SQL_ARGS
                        sql args needed for the duck db magic to read json files

Built by ChalkingCode

$ python duckvt.py -gn attack_technique_object -id T1203

{'get_name': 'attack_technique_object', 'ip_address': None, 'domain': None, 'id': 'T1203', 'sql_args': None}
Writing out report to file T1203_attack_technique_object.json

$ python duckvt.py -gn get_data -sql 'SELECT * FROM T1203_attack_technique_object.json'

{'get_name': 'get_data', 'ip_address': None, 'domain': None, 'id': None, 'sql_args': 'SELECT * FROM T1203_attack_technique_object.json'}

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                   data                                                                                                   │
│ struct(id varchar, "type" varchar, links struct(self varchar), attributes struct(description varchar, info struct(x_mitre_domains varchar[], x_mitre_platforms varchar[], x_mitre_is_subtechnique bool…  │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ {'id': T1203, 'type': attack_technique, 'links': {'self': https://www.virustotal.com/api/v3/attack_techniques/T1203}, 'attributes': {'description': Adversaries may exploit software vulnerabilities i…  │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

$ python duckvt.py -gn get_data -sql 'SELECT data.id, data.type, data.links, data.attributes.stix_id, data.attributes.link, data.attributes.last_modification_date, data.attributes.name, data.attributes.description FROM T1203_attack_technique_object.json'

{'get_name': 'get_data', 'ip_address': None, 'domain': None, 'id': None, 'sql_args': 'SELECT data.id, data.type, data.links, data.attributes.stix_id, data.attributes.link, data.attributes.last_modification_date, data.attributes.name, data.attributes.description FROM T1203_attack_technique_object.json'}

┌─────────┬──────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────────────────────────────────────────┐
│   id    │       type       │        links         │       stix_id        │         link         │ last_modification_…  │         name         │                       description                        │
│ varchar │     varchar      │ struct(self varchar) │       varchar        │       varchar        │        int64         │       varchar        │                         varchar                          │
├─────────┼──────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────────────────────────────────────────┤
│ T1203   │ attack_technique │ {'self': https://w…  │ attack-pattern--be…  │ https://attack.mit…  │           1650307686 │ Exploitation for C…  │ Adversaries may exploit software vulnerabilities in cl…  │
└─────────┴──────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────────────────────────────────────────┘``` 

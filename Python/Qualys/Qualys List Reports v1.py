from tokenize import group
import requests, json, re, time, sys, xmltodict, csv
from collections import defaultdict
from jsonpath_ng import jsonpath, parse
from requests.auth import HTTPBasicAuth


# Step Input Parameters
qualys_username = "{{ $.integrations.qualys.qualys_username }}"
qualys_password = "{{ $.integrations.qualys.qualys_password }}"
report_id = "{{ $.filter_array.result.0.ID }}"
debug = False

def debug_msg(debug_msg):
    if debug == True:
        print(debug_msg)

def list_reports(username, password):
    url = f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/report/?action=list"
    debug_msg("Listing Reports "+ url)
    out = requests.get(url, headers={"X-Requested-With": "Torq"}, auth=HTTPBasicAuth(username, password))
    xmlobj = xmltodict.parse(out.content) #Convert XML response to JSON
    return json.loads(json.dumps(xmlobj)) 

def fetch_report(username, password, id):
    url = f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/report/?action=fetch&id="+id
    debug_msg("Fetch Report "+ url)
    out = requests.get(url, headers={"X-Requested-With": "Torq"}, auth=HTTPBasicAuth(username, password))
    filename="report.csv"
    file_open=open(filename,'w')
    file_open.write(str(out.text))
    file_open.flush()
    file_open.close()

fetch_report(qualys_username, qualys_password, report_id)

#Convert report from CSV to JSON
filename="report.csv"
jsonArray=[]
count=0
with open(filename, encoding='utf-8') as csvf:
        ex_header = csvf.readlines()[4:] #Location of the CSV header
        csvReader = csv.DictReader(ex_header)
        for rows in csvReader:
            jsonArray.append(rows) 
        
print("{\"qualysreport\":"+json.dumps(jsonArray)+"}")
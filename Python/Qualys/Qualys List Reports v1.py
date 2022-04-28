from tokenize import group
import requests, json, re, time, sys, xmltodict
from collections import defaultdict
from jsonpath_ng import jsonpath, parse
from requests.auth import HTTPBasicAuth


# Step Input Parameters
qualys_username = "{{ $.set_variable.qualys.user }}"
qualys_password = "{{ $.set_variable.qualys.pass }}"
report_id = ""
report_name="IL vulnerability results"
debug = True
export_severity="critical"
export_state="open"


found = False
final_data=defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))))

def debug_msg(debug_msg):
    if debug == True:
        print(debug_msg)

def list_reports(username, password):
    url = f"https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/report/?action=list"
    #print("Listing Reports, url)
    out = requests.get(url, headers={"X-Requested-With": "Torq"}, auth=HTTPBasicAuth(username, password))
    xmlobj = xmltodict.parse(out.content) #Convert XML response to JSON
    return json.dumps(xmlobj)


def export_vulnerabilities(export_severity,export_state):
    url = f"https://cloud.tenable.com/vulns/export"
    #print("Exporting Vulnerabilities", url)
    payload = {"filters": {"severity": [export_severity],"state": [export_state]},"num_assets": 50}
    out = requests.post(url, headers={"Content-Type":"application/json; charset=utf-8","X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"},json=json.dumps(payload))
    return json.loads(out.content)

def check_export(export_uuid):
    url = f"https://cloud.tenable.com/vulns/export/{export_uuid}/status"
    #print("Checking Export Status", url)
    out = requests.get(url, headers={"X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"})
    return json.loads(out.content)

def download_chunk(chunk_number):
    url = f"https://cloud.tenable.com/vulns/export/{export_uuid}/chunks/{chunk_number}"
    #print("Getting", url)
    out = requests.get(url, headers={"X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"})
    return json.loads(out.content)

def get_custom_entry(entry,mapping):
    current_entry = {}
    for key, jsonpath in mapping.items():
        val = ""
        match = jsonpath.find(entry)
        if match:
            val = match[0].value
        current_entry[key] = val
    return current_entry


#------------------------------

# Check if report ID Provided -> If not, get report ID from Qualys before continuing
if not report_id:
    #List Tenable Scans
    data = list_reports(qualys_username,qualys_password)   
    for x in data.get('REPORT_LIST_OUTPUT'):
        if x['TITLE'] == report_name:
             scan_id=(x['ID'])
             debug_msg("scan uuid: "+str(scan_uuid))
             break

    if report_id == "":
        #Display error in Torq UI
        print('{"step_status": {"code": 9,"message": "Unable to find scan id.", "verbose": "Unable to find the Qualys scan. Please check the report name provided OR provide the id of the scan."}}')
        sys.exit(1)









# Export vulnerabilities
data = export_vulnerabilities(export_severity,export_state)
export_uuid = data.get("export_uuid")

#Wait for export to complete before continuing
counter = 0
while counter < 25:
    data = check_export(export_uuid)
    export_status = data.get('status')
    
    if export_status == "FINISHED":
        chunks = data.get('chunks_available')
        break
    else:
        time.sleep( 5 )
        counter = counter + 1

else:
    #Display error in Torq UI
    print('{"step_status": {"code": 9,"message": "Timeout exceeded waiting for exported scan.", "verbose": "The vulnerability export exceeded the 120 second timer."}}')
    sys.exit(1)

# Process Data Chunks From Tenable
for chunk in chunks:
   data = download_chunk(chunk)
   for entry in data:
       if not entry.get("scan") or entry.get("scan").get("uuid") != scan_uuid:
           continue

       solution = entry.get("plugin", {}).get("solution")
       cve = entry.get("plugin", {}).get("cve")
       plugin_id = entry.get("plugin", {}).get("id")
       plugin_name = entry.get("plugin", {}).get("name")

       found = False
       #Grouped Items
       for group in solution_groups:
           
           if re.search(group["match"],solution,re.IGNORECASE):
               #soultion group substring found in solution value - Group all hosts to the same solution
               if (isinstance(final_data['grouped'][entry['severity']][group["label"]]['hosts'][entry['asset']['hostname']],dict)):
                   final_data['grouped'][entry['severity']][group["label"]]['hosts'][entry['asset']['hostname']]=[]
               final_data['grouped'][entry['severity']][group["label"]]['general_recommendation']=group['general_recommendation']
               final_data['grouped'][entry['severity']][group["label"]][solution]['cve']=cve
               final_data['grouped'][entry['severity']][group["label"]][solution]['severity']=entry['severity']
               final_data['grouped'][entry['severity']][group["label"]][solution]['plugin_name']=plugin_name
               final_data['grouped'][entry['severity']][group["label"]][solution]['plugin_id']=plugin_id
               final_data['grouped'][entry['severity']][group["label"]][solution]['output']=entry["output"]
               final_data['grouped'][entry['severity']][group["label"]][solution]['cvss']=get_custom_entry(entry,CVSS_JSON_MAPPING)
               final_data['grouped'][entry['severity']][group["label"]][solution]['cvss3']=get_custom_entry(entry,CVSS3_JSON_MAPPING)
               final_data['grouped'][entry['severity']][group["label"]]['hosts'][entry['asset']['hostname']].append(get_custom_entry(entry,FINAL_JSON_MAPPING))
               found = True

       #Ungrouped Items
       if found == False:
          test="1"
          if (isinstance(final_data['ungrouped'][entry['severity']][solution],dict)):
               final_data['ungrouped'][entry['severity']][solution]['hosts']=[]
          final_data['ungrouped'][entry['severity']][solution]['hosts'].append(get_custom_entry(entry,FINAL_JSON_MAPPING))
          final_data['ungrouped'][entry['severity']][solution]['cve']=cve
          final_data['ungrouped'][entry['severity']][solution]['severity']=entry['severity']
          final_data['ungrouped'][entry['severity']][solution]['plugin_name']=plugin_name
          final_data['ungrouped'][entry['severity']][solution]['plugin_id']=plugin_id

       
#print("<-- END -->" + json.dumps(final_data))
print(json.dumps(final_data))
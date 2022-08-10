from tokenize import group
import requests, json, re, time, sys
from collections import defaultdict
from jsonpath_ng import jsonpath, parse

#Version 2.2.3

FINAL_JSON_MAPPING = {
    "hostname": parse("$.asset.hostname"),
    "first_found": parse("$.first_found"),
    "last_found": parse("$.last_found"),
    "solution": parse("$.plugin.solution"),
    "severity": parse("$.severity"),
    "plugin_id": parse("$.plugin.id"),
    "exploit_available": parse("$.plugin.exploit_available")
}

CVSS_JSON_MAPPING = {
    "cvss_base_score": parse("$.plugin.cvss_base_score"),
    "cvss_temporal_score": parse("$.plugin.cvss_temporal_score"),
    "cvss_temporal_vector": parse("$.plugin.cvss_temporal_vector"),
    "cvss_vector": parse("$.plugin.cvss_vector")
}

CVSS3_JSON_MAPPING = {
    "cvss3_base_score": parse("$.plugin.cvss3_base_score"),
    "cvss3_temporal_score": parse("$.plugin.cvss3_temporal_score"),
    "cvss3_temporal_vector": parse("$.plugin.cvss3_temporal_vector"),
    "cvss3_vector": parse("$.plugin.cvss3_vector")
}

solution_groups=[
{"label":"Adobe InDesign","match":"Adobe InDesign","general_recommendation":"Upgrade to the latest Adobe InDesign version. For more details see attached .CSV"},
{"label":"Adobe Photoshop","match":"Adobe Photoshop","general_recommendation":"Upgrade to the latest Photoshop version"},
{"label":"Adobe Acrobat","match":"Adobe Acrobat","general_recommendation":"Upgrade to the latest Acrobat version"},
{"label":"Adobe Media Encoder","match":"Adobe Media Encoder","general_recommendation":"Upgrade to the latest Adobe Media Encoder version"},
{"label":"Node.js","match":"Node.js","general_recommendation":"Upgrade to the latest Node.js version"},
{"label":"Atlassian SourceTree","match":"Atlassian SourceTree","general_recommendation":"Upgrade to the latest SourceTree version"},
{"label":"Adobe Creative Cloud Desktop","match":"Adobe Creative Cloud Desktop","general_recommendation":"Upgrade to the latest Creative Cloud version"},
{"label":"Upgrade to MySQL","match":"Upgrade to MySQL","general_recommendation":"Upgrade to the latest MySQL version"},
{"label":"Adobe AIR","match":"Adobe AIR","general_recommendation":"Upgrade to the latest Adobe AIR version"},
{"label":"Adobe Reader","match":"Adobe Reader","general_recommendation":"Upgrade to the latest Adobe Reader version"},
{"label":"Chrome","match":"Chrome","general_recommendation":"Upgrade to the latest Chrome version"},
{"label":"macOS","match":"macOS","general_recommendation":"Upgrade to the latest MacOs version"},
{"label":"Firefox","match":"Firefox","general_recommendation":"Upgrade to the latest Firefox version"},
{"label":"Adobe Shockwave Player","match":"Adobe Shockwave Player","general_recommendation":"Upgrade to the latest Adobe Shockwave Player version"},
{"label":"Adobe Bridge","match":"Adobe Bridge","general_recommendation":"Upgrade to the latest version of Adobe Bridge"},
{"label":"Wireshark","match":"Wireshark","general_recommendation":"Upgrade to the latest version of Wireshark"},
{"label":"Oracle VM VirtualBox","match":"Oracle VM VirtualBox","general_recommendation":"Upgrade to the latest version of Oracle Virtual Box"},
{"label":"MS Office for Mac","match":"Microsoft has released.+Office.+Mac","general_recommendation":"Upgrade to the latest version of MS Office for Mac" },
{"label":"MS Silverlight","match":"Microsoft has released.+Silverlight","general_recommendation":"Upgrade to the latest version of MS Silverlight" },
{"label":"Apache","match":"Upgrade to Apache version","general_recommendation":"Upgrade to the latest version of Apache"}
]


found = False
final_data=defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))))

def debug_msg(debug_msg):
    if debug == True:
        print(debug_msg)

def super_debug_msg(debug_msg):
    if super_debug == True:
        print(debug_msg)

def list_scans():
    url = f"https://cloud.tenable.com/scans/?"
    debug_msg("Listing Scans "+ url)
    out = requests.get(url, headers={"X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"})
    
    if int(out.status_code) > 299:
        print("Status: "+str(out.status_code)+", Error: "+str(out.content))
        sys.exit(9) #Exit with error
    else:
        super_debug_msg("[Listing Scans Output]")
        super_debug_msg("   - "+str(out.content))
    
    return json.loads(out.content)

def export_vulnerabilities(export_severity,export_state):
    url = f"https://cloud.tenable.com/vulns/export"
    debug_msg("Exporting Vulnerabilities "+ url)
    if export_state == "":
        payload = {"filters": {"severity": [export_severity]},"num_assets": 50}
    else:
        payload = {"filters": {"severity": [export_severity],"state": [export_state]},"num_assets": 50}

    out = requests.post(url, headers={"Content-Type":"application/json; charset=utf-8","X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"},json=json.dumps(payload))
    super_debug_msg("[Exporting Scan: Payload = "+str(payload)+"]")
    super_debug_msg("   - "+str(out.content))
    return json.loads(out.content)

def check_export(export_uuid):
    url = f"https://cloud.tenable.com/vulns/export/{export_uuid}/status"
    debug_msg("Checking Export Status " +url)
    out = requests.get(url, headers={"X-ApiKeys": f"accessKey={access_key}; secretKey={secretKey}"})
    return json.loads(out.content)

def download_chunk(chunk_number):
    url = f"https://cloud.tenable.com/vulns/export/{export_uuid}/chunks/{chunk_number}"
    debug_msg("Getting "+ url)
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


# Step Input Parameters
debug = False
super_debug = False #Brace yourself
access_key = "{{ $.integrations.tenableio.tenable_access_key }}"
secretKey = "{{ $.integrations.tenableio.tenable_secret_key }}"
scan_uuid = ""
scan_name= "{{ $.scan_names.scan_name }}"
export_severity="critical"
export_state="open"
group_vulnerabilities=True

# Check if Scan UUID Provided -> If not, get Scan UUID from Tenable before continuing
if not scan_uuid:
    #List Tenable Scans
    data = list_scans()   
    for x in data.get('scans'):
        if x['name'] == scan_name:
             scan_uuid=(x['uuid'])
             debug_msg("scan uuid: "+str(scan_uuid))
             break

    if scan_uuid == "":
        #Display error in Torq UI
        print('{"step_status": {"code": 9,"message": "Unable to find scan uuid.", "verbose": "Unable to find the Tenable scan. Please check the scan name provided OR provide the uuid of the scan."}}')
        sys.exit(1)


# Export vulnerabilities
data = export_vulnerabilities(export_severity,export_state)
export_uuid = data.get("export_uuid")

#Wait for export to complete before continuing
counter = 0
while counter < 240:
    data = check_export(export_uuid)
    export_status = data.get('status')
    
    if export_status == "FINISHED":
        chunks = data.get('chunks_available')
        debug_msg("scan chunks: "+str(chunks))
        break
    else:
        time.sleep( 5 )
        counter = counter + 1

else:
    #Display error in Torq UI
    print('{"step_status": {"code": 9,"message": "Timeout exceeded waiting for exported scan.", "verbose": "The vulnerability export exceeded the 120 second timer."}}')
    sys.exit(1)

# Process Data Chunks From Tenable
entries_matched = 0
entries_unmatched = 0
entries_total = 0

for chunk in chunks:
   data = download_chunk(chunk)
   for entry in data:
       entries_total = entries_total + 1

       super_debug_msg("[Chunk #"+str(chunk)+" - Entry #"+str(entries_total)+"]")
       super_debug_msg("   - Entry Data: "+str(entry))
       if not entry.get("scan") or entry.get("scan").get("uuid") != scan_uuid:
           
           entries_unmatched = entries_unmatched + 1
           continue

       solution = entry.get("plugin", {}).get("solution")
       cve = entry.get("plugin", {}).get("cve")
       plugin_id = entry.get("plugin", {}).get("id")
       plugin_name = entry.get("plugin", {}).get("name")
       entries_matched = entries_matched + 1
       
       super_debug_msg("   - "+solution)
       super_debug_msg("   - "+cve)


       found = False
       if group_vulnerabilities == True:
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
debug_msg("Total entries: "+str(entries_total))
debug_msg("UUID matched entries: "+str(entries_matched))
debug_msg("UUID unmatched entries: "+str(entries_unmatched))

#Final Step Output

print(json.dumps(final_data))

#print('{"step_status": {"code": 1,"message": "Matched '+str(entries_matched)+" of "+str(entries_total)+" vulnerabilities to scan "+str(scan_uuid)+'", "verbose": ""}}')
sys.exit(0)

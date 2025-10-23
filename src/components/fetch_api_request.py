import requests
import json
from cvss import CVSS3

def fetch_cve(vendor,product,app_type = 'o',skip_amount = 1):
    if skip_amount > 0:
        skip_amount = (skip_amount) * 10 # goes to next 10 vulnerabilities
    new_cve_list = list()
    try:
        res = requests.get(f"https://cvedb.shodan.io/cves?cpe23=cpe:2.3:{app_type}:{vendor}:{product}:-&limit=10&skip={skip_amount}")
    except Exception as e:
        raise e("Invalid Vendor Or Product or potentially reached the end of the list of cves")
        pass
    json_res= res.json()
    cve_list = json_res.get("cves")
    for i in range(len(cve_list)):
        cve_map = dict()
        cve_dict = cve_list[i]
        id = cve_dict.get("cve_id")
        cve_map["cve_id"] = id
        desc = cve_dict.get("summary")
        cve_map["desc"] = desc
        cvss = cve_dict.get("cvss")
        cve_map["cvss"] = cvss
        epss = cve_dict.get("epss")
        cve_map["epss"] = epss
        kev_status = cve_dict.get("kev")
        cve_map["is_kev"] = kev_status
        new_cve_list.append(cve_map)
    return new_cve_list

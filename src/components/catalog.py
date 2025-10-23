import requests
import json
import os

def find_kev(cve_list):
    kev_list = list()
    try: 
        with open("./kev_store/kev.json","r") as file:
            data = json.load(file)
            lst = data.get("vulnerabilities")
            j = 0  # separate index
            for i in range(len(lst)):
                kev_dict = dict()
                id = cve_list[j].get("cve_id") 
                kev_dict["cve_id"] = id
                if lst[i].get("cveID") == id:
                    kev_dict["is_kev"] = True
                    kev_list.append(kev_dict)
            return kev_list
    except Exception as e:
        raise e("path doesn't exists")

def download_kev():
    res = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    data = res.json()
    with open("./kev_store/kev.json", "w") as file:
        file.write(json.dumps(data))






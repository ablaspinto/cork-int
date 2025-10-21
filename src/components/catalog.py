import requests
import json

def find_kev(cve_list):
    ...

def download_kev():
    res = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    data = res.json()
    with open("./kev_store/kev.json", "w") as file:
        file.write(json.dumps(data))






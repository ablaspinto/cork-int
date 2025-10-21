import requests
import json
from cvss import CVSS3

def fetch_cve(vendor,product,page_amount = 10):
    cve_list = list()
    try:
        res = requests.get(f"https://cve.circl.lu/api/vulnerability/search/{vendor}/{product}?page=1&per_page={page_amount}")
        json_res= res.json()
    except Exception as e:
        raise e("Invalid Vendor Or Product")
        pass
    json_res= res.json()
    nvd = json_res["results"]["nvd"]
    for i in range(len(nvd)):
        cve_map = dict()
        nvd_dict = nvd[i] # contains cve id
        cve_map["cve_id"] = nvd_dict
        cna_vec = nvd_dict[1].get("containers").get("cna").get("metrics")[0].get("cvssV3_1").get("vectorString")
        c_vec = CVSS3(cna_vec)
        cve_map["cna_string"] = c_vec.clean_vector()
        cve_map["cna_scores"] = c_vec.scores()
        cve_map["cna_severities"] = c_vec.severities()
        if nvd_dict[1].get("containers").get("adp") != None:
            adp_str = nvd_dict[1].get("containers").get("adp")[0].get("metrics")[0].get("cvssV3_1").get("vectorString")
            adp_vec=  CVSS3(adp_str)
            cve_map["adp_string"] = adp_vec.clean_vector()
            cve_map["adp_scores"] = adp_vec.scores()
            cve_map["adp_severities"] = adp_vec.severities()
        cve_map["version"] = nvd_dict[1].get("containers").get("cna").get("affected")[0].get("versions")[0].get("version")
        cve_map["desc"] = nvd_dict[1].get("containers").get("cna").get("descriptions")[0].get("value")
        cve_list.append(cve_map)
    print(cve_list)
    return cve_list

def fetch_epss(cve_list):
    epss_list = list()
    for i in range(len(cve_list)):
        epss_map = dict()
        cve_map = cve_list[i]
        id = cve_map["cve_id"][0]
        try:
            res = requests.get(f"https://api.first.org/data/v1/epss?cve={id}")
        except Exception as e:
            raise e("Error occured grabbing cve_id")
        json= res.json() 
        print(id)
        epss_map["cve_id"] = id
        epss= json.get("data")[0].get("epss")
        epss_map["epss"] = epss
        percentile = json.get("data")[0].get("percentile")
        epss_map["percentile"] = epss
        epss_list.append(epss_map)
    return epss_list
    




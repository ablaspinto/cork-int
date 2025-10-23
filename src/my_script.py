import argparse
from components.catalog import download_kev , find_kev
from components.fetch_api_request import fetch_cve
from components.risk_object import RiskObject
import os


def construct_risk_objects(cve_list, kev_list):
    kev_status = False
    list_objects = list()
    if len(kev_list) > 0:
        for i in range(len(kev_list)):
            kev_map = kev_list[i]
            for j in range((len(cve_list))):
                id = cve_list[i].get("cve_id")
                desc= cve_list[i].get("desc")
                cvss = cve_list[i].get("cvss")
                epss = cve_list[i].get("epss")
                if kev_list[i].get("cve_id") == id:
                    risk_obj = RiskObject(id,desc,cvss,epss,0,True,0)
                    list_objects.append(risk_obj)
                else:
                    risk_obj = RiskObject(id,desc,cvss,epss)
                    list_objects.append(risk_obj)
    else:
        for i in range(len(cve_list)):
            id = cve_list[i].get("cve_id")
            desc= cve_list[i].get("desc")
            cvss = cve_list[i].get("cvss")
            epss = cve_list[i].get("epss")
            risk_obj = RiskObject(id,desc,cvss,epss)
            risk_obj.assess_risk()
            list_objects.append(risk_obj)
    return list_objects


def represent_risk_obj(list_obj):
    for i in range(len(list_obj)):
        print(list_obj[i])


def main():
    if not os.path.exists("./kev_store/kev.json"):
        download_kev()
    argument_parser = argparse.ArgumentParser(description="CLI Tool that calculates risk based on CVSS Score, EPSS, and KEV")
    argument_parser.add_argument("vendor" , type=str, help="enter a name of a vendor, for example microsoft, adobe")
    argument_parser.add_argument("product", type=str, help="enter the name of a product, for example windows, adobe, for specific version use _after product windows_10")
    argument_parser.add_argument("application_type", type=str, help="type in o for operating system, a for application, and h for hardware")
    argument_parser.add_argument("--next", type=int,default=1, help="Type in 1 for the first 1-10 vulnerabiliteis, 2 10-20 ... etc --next 1")
    arguments = argument_parser.parse_args()
    vendor = arguments.vendor.lower()
    prod = arguments.product.lower()
    app_type = arguments.application_type.lower()
    skip_amount = arguments.next
    print("Arguments put in:", "Vendor:",vendor ,"Product:", prod)
    cve_list = fetch_cve(vendor,prod,app_type,skip_amount)
    kev_list = find_kev(cve_list)
    list_object = construct_risk_objects(cve_list,kev_list)
    represent_risk_obj(list_object)


if __name__ == "__main__":
    main()

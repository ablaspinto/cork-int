import argparse
from components.catalog import download_kev , find_kev
from components.fetch_api_request import fetch_cve, fetch_epss
import os


def construct_risk_objects(epss_map, cve_scores, kev_scores):
    ...



def main():
    if not os.path.exists("./kev_store/kev.json"):
        download_kev()
    argument_parser = argparse.ArgumentParser(description="CLI Tool that calculates risk based on CVSS Score, EPSS, and KEV")
    argument_parser.add_argument("vendor" , type=str, help="enter a name of a vendor, for example microsoft, adobe")
    argument_parser.add_argument("product", type=str, help="enter the name of a product, for example windows, adobe, for specific version use _after product windows_10")

    arguments = argument_parser.parse_args()
    vendor = arguments.vendor.lower()
    prod = arguments.product.lower()
    print("Arguments put in:", "Vendor:",vendor ,"Product:", prod)

    cve_list = fetch_cve(vendor,prod)
    print(cve_list)
    epss_list = fetch_epss(cve_list)
    print(epss_list)

if __name__ == "__main__":
    main()

import argparse


def construct_risk_objects(epss_map, cve_scores, kev_scores):
    ...



def main():
    argument_parser = argparse.ArgumentParser(description="CLI Tool that calculates risk based on CVSS Score, EPSS, and KEV")
    argument_parser.add_argument("vendor" , type=str, help="enter a name of a vendor, for example microsoft, adobe")
    argument_parser.add_argument("product", type=str, help="enter the name of a product, for example windows, adobe, for specific version use _after product windows_10")

    arguments = argument_parser.parse_args()
    vendor = arguments.vendor.lower()
    prod = arguments.product.lower()
    print("Arguments put in:", "Vendor:",vendor ,"Product:", prod)
    

    




if __name__ == "__main__":
    main()

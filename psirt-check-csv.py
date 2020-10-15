#!/usr/bin/env python3
# Author
__author__ = 'Omer Chohan'
__date__= 'Oct 2020'

import argparse
import requests
import urllib3
import json
import csv
try:
    from creds import CLIENT_ID, CLIENT_SECRET
except:
    print("Error reading credentials. Check credentials in creds.py file.\n")
    exit()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_TOKEN_URL = "https://cloudsso2.cisco.com/as/token.oauth2"
API_GET_ADVISORIES = "https://api.cisco.com/security/advisories/iosxe/?version={0}"
DETAIL_TEXT = "    ID {0} - {1}\n      First Published: {2}\n      First fixed: {3}\n      Bug IDs: {4}\n      CVE ID: {5}\n      Score: {6} - Severity: {7}\n"


def get_api_token(url):
    response = requests.post(url, verify=False, data={"grant_type": "client_credentials"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             params={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
    
    if response is not None:
        print("Authentication Successful\n")
        return json.loads(response.text)["access_token"]

    return None


def get_advisories_by_release(token, ver):
    version_dict = { "release": ver, "advisories": []}
    # Uncomment to debug
    #print(version_dict)
    url = API_GET_ADVISORIES.format(ver)
    #print("<<<<<<<<<{}>>>>>>>>>>".format(url))
    response = requests.get(url, verify=False, headers={"Authorization": "Bearer {0}".format(token), "Accept": "application/json"})

    if response.status_code == 200:
        # Uncomment to see the full dict return by the API
        #print("<<<<<.....>>>>>",json.loads(response.text)["advisories"])
        version_dict["advisories"] = build_advisories_dict(json.loads(response.text)["advisories"])
        # Uncomment to debug the data returned by  build_advisories_dict()
        #print(version_dict)
        return version_dict

    return {"release": ver, "advisories": [], "state": "ERROR", "detail": response.status_code}


def build_advisories_dict(advisories):
    adv_list = []
    for adv in advisories:
        adv_dict = dict()
        adv_dict["advisory_id"] = adv["advisoryId"] if "advisoryId" in adv else "Unknown"
        adv_dict["advisory_title"] = adv["advisoryTitle"] if "advisoryTitle" in adv else "Unknown"
        adv_dict["bug_ids"] = adv["bugIDs"] if "bugIDs" in adv else "Unknown"
        adv_dict["cves"] = adv["cves"] if "cves" in adv else "Unknown"
        adv_dict["cvssBaseScore"] = adv["cvssBaseScore"] if "cvssBaseScore" in adv else "Unknown"
        adv_dict["first_fixed"] = adv["firstFixed"] if "firstFixed" in adv else "Unknown"
        adv_dict["firstPublished"] = adv["firstPublished"] if "firstPublished" in adv else "Unknown"
        #adv_dict["productNames"] = adv["productNames"] if "productNames" in adv else "Unknown"
        adv_dict["sir"] = adv["sir"] if "sir" in adv else "Unknown"
        adv_list.append(adv_dict)
    #print(">>>>",adv_list)
    return adv_list


def load_version_file(input_file, token):
    version_list = []
    advisories_list = []
    
    # Open text file, read and append version numbers to version list
    try:
        with open(input_file, 'r') as f:
            f.readlines
            for line in f:
                version_list.append(line.strip())
        #print(version_list)
    except (FileNotFoundError, IOError) as error:
        print(error)
        print("Check filename and path.\n")
        exit()
    for version in version_list:
        advisories_list.append(get_advisories_by_release(token, version))
 
    return advisories_list


def write_to_csv(source_list):
    csv_headers = ["version", "advisory_id", "advisory_title", "first_fixed", "bug_ids"]

    with open("vuln_check_output" + ".csv", "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=",")
        csvwriter.writerow(csv_headers)
        
        for item in source_list:
            #print(item)
            version = item["release"]
            advisories = item["advisories"]
            #print(advisories)
            for i in advisories:
                row = [version, i["advisory_id"], i["advisory_title"],
                   "/".join(i["first_fixed"]), "/".join(i["bug_ids"])]
                #print(row)
                csvwriter.writerow(row)


def print_advisories(source_list, detail=True):
    #print(source_dict)
    for item in source_list:
        
        print("Current Release: {0}".format(item["release"]))
        print("Advisories Published: {0}".format(len(item["advisories"])))
        if len(item["advisories"]) == 0:
            message = "ERROR encountered during lookup: {0}".format(item["detail"]) if item["state"] == "ERROR" \
                else "None found"

            print("{0}".format(message))
        else:
            formatted_text = ""
            # Create a list of fixed releases
            fixed_releases = []
            for adv in item["advisories"]:
                if adv is not None:
                    formatted_text += DETAIL_TEXT.format(adv["advisory_id"], 
                                                         adv["advisory_title"],
                                                         adv["firstPublished"],
                                               ", ".join(adv["first_fixed"]), 
                                               ", ".join(adv["bug_ids"]),
                                               ", ".join(adv["cves"]),
                                                         adv["cvssBaseScore"],
                                                         adv["sir"],                                                                                                                                           
                                               )
                    # Populated the list with fixed release in each advisory
                    fixed_releases += adv["first_fixed"]
                    #print(sorted(fixed_releases))
            print("Minimum Suggested Release: {0}\n".format(sorted(fixed_releases)[len(fixed_releases)-1]))
            if detail:
                print(formatted_text)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    required_args = parser.add_argument_group('Required Arguments')
    required_args.add_argument('-f', '--file', type=str, dest="file", required=True, help='Text file with versions.')
    parser.add_argument('-d', '--detail', dest="detail", action='store_true', help='Print Details.')
    args = parser.parse_args() 

    filename = args.file
    detail_flag = args.detail

    print()
    print("Cisco PSRIT openVuln API Query Engine Starting ...")

    if detail_flag == False:
        print("Use -d/--detail flag to print details.")   

    advisory_list = load_version_file(filename, get_api_token("https://cloudsso.cisco.com/as/token.oauth2"))

    print_advisories(advisory_list, detail_flag)
    write_to_csv(advisory_list)

if __name__ == "__main__":
    main()
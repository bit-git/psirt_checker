#!/usr/bin/env python3
# Author
__author__ = 'Omer Chohan'
__date__= 'Oct 2020'

import argparse
import requests
import urllib3
import json
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
        token = json.loads(response.text)["access_token"]
        print("Authentication Successful\n")
        return token
    return None


def get_advisories_by_release(token, ver):
    version_dict = {"release": ver, "advisories": []}
    # Uncomment to debug
    #print(version_dict)
    url = API_GET_ADVISORIES.format(ver)
    #print("<<<<<<<<<{}>>>>>>>>>>".format(url))
    response = requests.get(url, verify=False, headers={"Authorization": "Bearer {0}".format(token), "Accept": "application/json"})

    if response.status_code == 200:
        # Uncomment to see the full dict return by the API
        #print(json.loads(response.text))
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


def print_advisories(source_dict, detail=True):
    #print(">>>>>>>", type(source_dict))
    #print(len(source_dict["advisories"]))
    if len(source_dict["advisories"]) == 0:
            message = "openVuln API returned {0}. No advisories found.".format(source_dict["detail"]) if source_dict["state"] == "ERROR" \
                else "None found"

            print("    {0}".format(message))
    else:

        print("Advisories Published: {0}".format(len(source_dict["advisories"])))
     
        # Create a list of fixed releases
        fixed_releases = []
        for item in source_dict["advisories"]:
        #print(">>>>>>>", item)
        #print("Current Release: {0}".format(item["release"]))
        
        # Formatted text to print out
            formatted_text = ""

            if item is not None:
                formatted_text += DETAIL_TEXT.format(item["advisory_id"], 
                                                     item["advisory_title"],
                                                     item["firstPublished"],
                                           ", ".join(item["first_fixed"]), 
                                           ", ".join(item["bug_ids"]),
                                           ", ".join(item["cves"]),
                                                     item["cvssBaseScore"],
                                                     item["sir"],                                                                                                                                           
                                           )
                # Populated the list with fixed release in each advisory
                fixed_releases += item["first_fixed"]
                #print(fixed_releases)

                if detail:
                    print(formatted_text)
    
        print("Minimum Suggested Release: {0}".format(sorted(fixed_releases)[len(fixed_releases)-1]))


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    required_args = parser.add_argument_group('Required Arguments')
    required_args.add_argument('-v', '--version', type=str, dest="version", required=True, help='Valid IOSXE version.')
    parser.add_argument('-d', '--detail', dest="detail", action='store_true', help='Print Details.')
    args = parser.parse_args()

    version = args.version
    detail_flag = args.detail
     
    print()
    print("Cisco PSRIT openVuln API Query Engine Starting ...")

    if detail_flag == False:
        print("Use -d/--detail flag to print details.")    

    psirt_list = []
    token = get_api_token("https://cloudsso.cisco.com/as/token.oauth2")
   
    psirt_list = get_advisories_by_release(token, version)
    
    print_advisories(psirt_list, detail_flag)

if __name__ == "__main__":
    main()
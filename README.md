# psirt_checker
Simple Query Application for Cisco PSRIT openVuln API 

**Note:** Checks for IOS-XE

**Note:** There are 2 scripts.
1. psirt-check-csv.py 

**psirt-check-csv.py** - takes a text file as an intput with IOS-XE verion numbers. See [input.txt](https://gitlab.com/ochohan/ciscosupportapi/-/raw/master/psirt-checker/input.txt) for an example. </br>Prints summary and Saves details in a CSV file. **-d/--detail** flag can be set to print the detail output on the screen.

2. psirt-check-version.py

**psirt-check-version.py** - takes IOS-XE version number as a command line argument. </br>Prints summary. **-d/--detail** flag can be set to print the detail output on the screen.


## Requirements
This application requires access to the "Cisco Support API" provided at [https://apiconsole.cisco.com/](https://apiconsole.cisco.com/).  
Note, API access is granted by the SmartNet or PSS adminstrator.   

API documention: [https://developer.cisco.com/psirt/](https://developer.cisco.com/psirt/)

1. Ask SmartNet or PSS adminstrator to grant access to Cisco Support APIs. 
2. Register an app on the Cisco API Consoile and get client id and client secret.
3. Populate the [creds.py](https://gitlab.com/ochohan/ciscosupportapi/-/raw/master/psirt-checker/creds.py) file with the CLIENT_ID and CLIENT_SECRET

Example:
```
CLIENT_ID = mxxgwertsps7ry9zsdkk7r3
CLIENT_SECRET = adqB3jegsvbYbJfcx27As5au
```

4. Python requests module to query the API. 

   `pip install requests`

5. Create a text file with all the versions to check in the same folder. See [input.txt](https://gitlab.com/ochohan/ciscosupportapi/-/raw/master/psirt-checker/input.txt) for an example.

## Usage - psirt-check-csv.py 
psirt-check-csv.py allows you to query the Cisco PSRIT openVuln and save the output in a CSV file.</br>**-d/--detail** flag can be set to print the detail output on the screen.
```
$ python psirt-checker/psirt-check-csv.py 
usage: psirt-check-csv.py [-h] -f FILE [-d]
psirt-check-csv.py: error: argument -f/--file is required
```

Example:
```
$ python3 psirt-check-csv.py -f input.txt

Cisco PSRIT openVuln API Query Engine Starting ...
Use -d/--detail flag to print details.
Authentication Successful

Current Release: 16.12.3s
Advisories Published: 12
Minimum Suggested Release: 16.12.4a

Current Release: 16.12.4
Advisories Published: 5
Minimum Suggested Release: 16.12.4a
```

Output Saved CSV File Example 
```
version,advisory_id,advisory_title,first_fixed,bug_ids
16.12.3s,cisco-sa-splitdns-SPWqpdGW,Cisco IOS and IOS XE Software Split DNS Denial of Service Vulnerability,16.12.4,CSCvt78186
16.12.3s,cisco-sa-le-drTOB625,Cisco IOS XE Software Ethernet Frame Denial of Service Vulnerability,16.12.4,CSCvu30597
16.12.3s,cisco-sa-esp20-arp-dos-GvHVggqJ,Cisco IOS XE Software for Cisco ASR 1000 Series 20-Gbps Embedded Services Processor IP ARP Denial of Service Vulnerability,16.12.4,CSCva53392/CSCvu04413
16.12.3s,cisco-sa-iosxe-rsp3-rce-jVHg8Z7c,Cisco IOS XE Software for Cisco ASR 900 Series Route Switch Processor 3 Arbitrary Code Execution Vulnerabilities,16.12.4,CSCvr69196/CSCvs62410
16.12.3s,cisco-sa-iosxe-dhcp-dos-JSCKX43h,Cisco IOS XE Software for Cisco cBR-8 Converged Broadband Routers DHCP Denial of Service Vulnerability,16.12.4,CSCvr70940
16.12.3s,cisco-sa-iox-usb-guestshell-WmevScDj,Cisco IOS XE Software IOx Guest Shell USB SSD Namespace Protection Privilege Escalation Vulnerability,,CSCvr50406
16.12.3s,cisco-sa-ios-xe-webui-multi-vfTkk7yr,Cisco IOS XE Software Web Management  Framework Vulnerabilities,16.12.4,CSCvs40364/CSCvs40405
16.12.3s,cisco-sa-zbfw-94ckG4G,Cisco IOS XE Software Zone-Based Firewall Denial of Service Vulnerabilities,16.12.4,CSCvs71952/CSCvt52986
16.12.3s,cisco-sa-telnetd-EFJrEzPx,Telnet Vulnerability Affecting Cisco Products: June 2020,16.12.4a,CSCvu66723
16.12.3s,cisco-sa-20170726-anicrl,Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation Vulnerability,,CSCvd22328
16.12.3s,cisco-sa-20170726-aniacp,Cisco IOS and IOS XE Software Autonomic Control Plane Channel Information Disclosure Vulnerability,,CSCvd51214
16.12.3s,cisco-sa-20170726-anidos,Cisco IOS and IOS XE Software Autonomic Networking Infrastructure Denial of Service Vulnerability,,CSCvd88936
16.12.4,cisco-sa-iox-usb-guestshell-WmevScDj,Cisco IOS XE Software IOx Guest Shell USB SSD Namespace Protection Privilege Escalation Vulnerability,,CSCvr50406
16.12.4,cisco-sa-telnetd-EFJrEzPx,Telnet Vulnerability Affecting Cisco Products: June 2020,16.12.4a,CSCvu66723
16.12.4,cisco-sa-20170726-anicrl,Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation Vulnerability,,CSCvd22328
16.12.4,cisco-sa-20170726-aniacp,Cisco IOS and IOS XE Software Autonomic Control Plane Channel Information Disclosure Vulnerability,,CSCvd51214
16.12.4,cisco-sa-20170726-anidos,Cisco IOS and IOS XE Software Autonomic Networking Infrastructure Denial of Service Vulnerability,,CSCvd88936
```

## Usage - psirt-check-version.py
psirt-check-version.py allows you to query the Cisco PSRIT openVuln with a version number.
```
$ python psirt-checker/psirt-check-version.py 
usage: psirt-check-version.py [-h] -v VERSION [-d]
psirt-check-version.py: error: argument -v/--version is required
```

Example:
```
$ python3 psirt-checker/psirt-check-version.py -v 16.12.4

Cisco PSRIT openVuln API Query Engine Starting ...
Use -d/--detail flag to print details.
Authentication Successful

Advisories Published: 5
  Minimum Suggested Release: 16.12.4a
```

## Credits
https://github.com/CiscoPSIRT/openVulnAPI

https://community.cisco.com/t5/services-documents/using-the-psirt-api-with-python/ta-p/3834849

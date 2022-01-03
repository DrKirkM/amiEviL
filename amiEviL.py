#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

'''
author: Kirk Mutafopulos, PhD
version: 1.0a

About: 
This program uses the Virus Total API to determine if your suspicious file 
is malicious or not. The program requests the hash of the file and outputs 
information (if any). This version will output: the file type, names seen 
in the wild, the number of security vendors that have flagged it as 
malicicious, undetected, and unable to process the file. 

############################## IMPORTANT ##########################################
This program requires you have an API key from Virus Total. Go to line 68
and edit the line to include your API key. 

This program is designed to work with either the free or paid version of 
the VT API. This program does not use functions only availible for the paid version.

Special thanks:
Virus Total (https://developers.virustotal.com/reference/overview)

'''

import sys
if sys.version_info < (3, 7):
    sys.stdout.write("Sorry, amiEviL requires Python 3.7 or higher\n")
    sys.exit(1)
import requests
import json
import re


print('\033[91m'+"""

 (`-')  _ <-. (`-')        _          (`-')  _      (`-')  _                  ,------.  
 (OO ).-/    \(OO )_      (_)         ( OO).-/     _(OO ) (_)      <-.       /  .--.  ' 
 / ,---.  ,--./  ,-.)     ,-(`-')    (,------.,--.(_/,-.\ ,-(`-'),--. )      |  |  |  | 
 | \ /`.\ |   `.'   |     | ( OO)     |  .---'\   \ / (_/ | ( OO)|  (`-')    `--'__.  | 
 '-'|_.' ||  |'.'|  |     |  |  )    (|  '--.  \   /   /  |  |  )|  |OO )       |   .'  
(|  .-.  ||  |   |  |    (|  |_/      |  .--' _ \     /_)(|  |_/(|  '__ |       |___|   
 |  | |  ||  |   |  |     |  |'->     |  `---.\-'\   /    |  |'->|     |'       .---.   
 `--' `--'`--'   `--'     `--'        `------'    `-'     `--'   `-----'        `---'   

"""+'\033[39m')


####################################### API KEY MUST GO BELOW #####################################################
headers = {                                                                                                       #
    "Accept": "application/json",                                                                                 #
    "x-apikey": "API KEY GOES HERE" #Api-Key Goes Here. If you do not put a valid key here the program will fail. #             
}                                                                                                                 #
###################################################################################################################


file_id = str(input("[+] Please input the file hash (SHA-256, SHA-1, or MD5): \n"))

def get_vt_info(url):
    response = requests.request("GET", url, headers=headers)
    data_1 = response.text
    result = json.loads(data_1)
    print("\033[92m"+"\n[+] File types it might be: \n"+"\033[39m"+ json.dumps(result['data']['attributes']['trid'], indent=2).replace("[","").replace("]","").replace("{","").replace("}","").replace(",","").replace("\"",""))
    print("\033[92m"+"[+] Here are the names with which this file has been submitted or seen in the wild: \n"+"\033[39m" + json.dumps(result['data']['attributes']['names'], indent=2).replace('[','').replace(']','').replace(',','').replace('\"',''))

    analysis_reports = json.dumps(result['data']['attributes']['last_analysis_results'])
    mal_count = analysis_reports.count("malicious")
    undetect_count = analysis_reports.count("undetected")
    unsupp_count = analysis_reports.count("type-unsupported")

    print("\033[92m"+"[+] Here are the number of security vendors that flagged this as malicious: \n"+"\033[39m"+ "\n" + str(mal_count) + "\n")
    print("\033[92m"+"[+] Here are the number of security vendors that flagged this as undetected: \n" + "\033[39m"+"\n" + str(undetect_count) + "\n")
    print("\033[92m"+"[+] Here are the number of security vendors that are unable to process the file: \n" + "\033[39m"+"\n" + str(unsupp_count) + "\n")

def user_submission(user_file_id):
    
    md5_valid = re.findall(r"([a-fA-F\d]{32})", user_file_id)
    sha1_valid = re.findall(r"([a-fA-F\d]{40})", user_file_id)
    sha256_valid = re.findall(r"([a-fA-F\d]{64})", user_file_id)

    if user_file_id in md5_valid:
        print("[+] A MD5 hash was submitted.")
        url_append = user_file_id
        url = "https://www.virustotal.com/api/v3/files/" + url_append
        get_vt_info(url)

    elif user_file_id in sha1_valid:
        print("[+] A SHA-1 hash was submitted.")
        url_append = user_file_id
        url = "https://www.virustotal.com/api/v3/files/" + url_append
        get_vt_info(url)

    elif user_file_id in sha256_valid:
        print("[+] A SHA-256 has was submitted.")
        url_append = user_file_id
        url = "https://www.virustotal.com/api/v3/files/" + url_append
        get_vt_info(url)

    else:
        print("[+] Invalid submission or Not Recognized! \n EXITING...\n")

user_submission(file_id)
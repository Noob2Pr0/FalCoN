import random
import os, sys, platform
import argparse
import requests
from colorama import Fore
import nmap3
import json
import urllib.request
import re

def clear():
    plat=platform.system()
    if plat == "Windows":
        os.system('cls')
    else:
        os.system("clear")

def banner():
    print('''
  ______    _  _____      _   _ 
 |  ____|  | |/ ____|    | \ | |
 | |__ __ _| | |     ___ |  \| |
 |  __/ _` | | |    / _ \| . ` |
 | | | (_| | | |___| (_) | |\  |
 |_|  \__,_|_|\_____\___/|_| \_| v.01 (Beta)
     OmidNasiri.P@Gmail.COM  
            ''')

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='URL Address [Example: site.com | DONT USE HTTPS://site.com]')
parser.add_argument('-s', help='Output without banner')
#parser.add_argument('', help='')
parser.add_argument('--update', help='Check for new version')
args = parser.parse_args()

target = args.u


####### CREATE TARGET DIRECTORY #######
def target_mkdir():
    try:
        os.makedirs(target)
    except:
        print(Fore.RED+"Target Directory Already Exists\n"+Fore.WHITE)

############# CHECK TARGET IS UP + Print HTTP HEADER ############
def target_check():
    curl_response = requests.get('https://'+target)
    #print(target)
    if curl_response.status_code in range(200,350):
        print(Fore.YELLOW+'CHECK TARGET',Fore.WHITE)
        print(Fore.GREEN+'Target',target,'respose code is',curl_response.status_code,Fore.WHITE)
        print(Fore.YELLOW+'\nHTTP RESPONSE HEADERS',Fore.WHITE)
        headers = curl_response.headers
        readable_headers = "\n".join([f"{key}: {value}" for key, value in headers.items()])
        f = open(target+"\\HEADERS.txt", "w")
        f.write(readable_headers)
        f.close()
        print(readable_headers)
    else:
        print(Fore.YELLOW+'Target',target,'respose code is',curl_response.status_code)
    print(Fore.WHITE)


############## GET HEADERS ##############
def nmap():
    print(Fore.YELLOW+'Nmap:')
    print(Fore.WHITE)
    command=target,'-v -Pn'
    nmap = nmap3.Nmap()
    target_addr=target+r"\\Nmap.txt"
    results = nmap.scan_top_ports(target, args="-Pn -v -oN "+target_addr)
    #print(results)
    f = open(target_addr, 'r')
    file_contents = f.read()
    print (file_contents)
    f.close()

########### Quick Backupfile Check ###########
def backup_file():
    print(Fore.YELLOW+'BACKUP CHECK'+Fore.WHITE)
    backup_file_list = ['wp-config.zip','wp-config.bak','wp-config.txt','wp-config.php.zip','wp-config.php.bak','wp-config.php.txt']
    for bak in backup_file_list:
        backup_url = 'https://'+target+"/"+bak
        #print(Fore.CYAN+'CHECK :',backup_url+Fore.WHITE)
        curl_response = requests.get(backup_url)
        if curl_response.status_code is 200:
            print(Fore.CYAN+backup_url,":",Fore.GREEN+str(curl_response.status_code)+Fore.WHITE)
            response = urllib.request.urlopen(backup_url)
            data = response.read()      # a `bytes` object
            backup_data = data.decode('utf-8')
            #print(backup_data)
            f = open(target+"\\"+bak+".txt", "w")
            f.write(backup_data)
            f.close()
        else:
            print(Fore.CYAN+backup_url,":",Fore.RED+str(curl_response.status_code)+Fore.WHITE)

###### WORDPRESS USER ENUMERATION #####
def wp_user_enum():
    print(Fore.YELLOW+'WORDPRESS USER ENUMRATION'+Fore.WHITE)
    curl_response = requests.get('https://'+target)
    #print(curl_response)
    if "WordPress" in str(curl_response.content):
        print(target,'Using WordPress')
        user_id_list = ['/?author=0','/?author=1','/?author=2','/?author=3','/?author=4']
        for user_list in user_id_list:
            if curl_response.status_code == 200:
                user_check = 'https://'+target+"/"+user_list
                curl_response = requests.get(user_check)
                #print(curl_response.content)
                

                match = re.search(r'<span class="comment-author-link">(.*?)</span>', str(curl_response._content))
                if match:
                    value = match.group(1)
                    print(value)
                else:
                    print("No match found")


                print(Fore.CYAN,user_check,Fore.GREEN+'FOUND',Fore.WHITE)
            else:
                print(Fore.CYAN,user_check,Fore.RED+'Not Found',Fore.WHITE)
    else:
        print('Customized CMS')


#clear()
banner()
target_mkdir()
#target_check()
#nmap()
#backup_file()
wp_user_enum()
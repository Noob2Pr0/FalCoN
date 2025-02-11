import os, sys, subprocess, platform
from colorama import Fore
import nmap3, socket
import json, re, requests, argparse
import urllib.request, urllib3
from bs4 import BeautifulSoup

########## Ctrl+C Signal #########
def signal_handler(sig, frame):
    print(Fore.YELLOW+'You pressed Ctrl+C!'+Fore.WHITE)
    sys.exit(0)


def clear():
    plat=platform.system()
    if plat == "Windows":
        os.system('cls')
    else:
        os.system("clear")

def banner():
    print(Fore.GREEN+"""
  ______    _  _____      _   _ 
 |  ____|  | |/ ____|    | \ | |
 | |__ __ _| | |     ___ |  \| |"""+Fore.WHITE+"""
 |  __/ _` | | |    / _ \| . ` |
 | | | (_| | | |___| (_) | |\  |"""+Fore.RED+"""
 |_|  \__,_|_|\_____\___/|_| \_| """+Fore.YELLOW+"""v 0.2 (Beta)
     """+Fore.CYAN+"""OmidNasiri.P@Gmail.COM  
"""+Fore.WHITE)

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
        print(Fore.RED+"Target Directory Already Exists, \nBe careful, the files will be overwritten."+Fore.WHITE)
        q = input(Fore.YELLOW+'Do you agree to overwrite the files? (Y/N): '+Fore.WHITE)
        l = ['y','yes','Y','YES']
        if q in l:
            pass
        else:
            quit()

############# CHECK TARGET IS UP + Print HTTP HEADER ############
def target_check():
    curl_response = requests.get('https://'+target,verify=False)
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
    target_nodomain = target.split('.')[0]
    backup_file_list = ['wp-config.zip','wp-config.bak','wp-config.txt','wp-config.php.zip','wp-config.php.bak','wp-config.php.txt','error_log','public_html.zip',target_nodomain+'.zip','backup.zip','backup.tar.gz'
    ,'backup.sql',target_nodomain+'.sql','wp-content-backup.zip','database-backup.sql','backup-website.zip','backup-'+target_nodomain+'.zip','fullbackup.zip','full-'+target_nodomain+'.zip','wp-db.zip'
    ,'public_html-backup.tar.gz','public_html-backup.zip','backup.bak','backup.7z','full_backup.tar.gz']
    for bak in backup_file_list:
        backup_url = 'https://'+target+"/"+bak
        #print(Fore.CYAN+'CHECK :',backup_url+Fore.WHITE)
        curl_response = requests.get(backup_url,verify=False)
        if curl_response.status_code == 200:
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
    global value
    print(Fore.YELLOW+'\nWORDPRESS USER ENUMERATION'+Fore.WHITE)
    if os.path.exists(target+"\\USER_ENUM.txt"):
        os.remove(target+"\\USER_ENUM.txt")
    f = open(target+"\\USER_ENUM.txt", "a", encoding="utf-8")
    url_list = ['','/readme.html','/license.txt']
    for url_item in url_list:
        curl_response = requests.get('https://'+target+url_item,verify=False)
        #print(str(curl_response.content))
        if "wp-" in str(curl_response.content):
            print(target,'Using WordPress')
            print(Fore.YELLOW+'\nMETHOD 1'+Fore.WHITE)
            user_id_list = ['/?author=0','/?author=1','/?author=2','/?author=3','/?author=4','?author=5']
            # target want to fool us ?
            user_check = 'https://'+target+'/?author=1000000000000'
            curl_response = requests.get(user_check,verify=False)
            if curl_response.status_code == 200:
                print(Fore.RED+'Target Status code is 200 for 1,000,000,000,000 Author code, so target trying to fool us!'+Fore.WHITE)
            else:
                for user_list_item in user_id_list:
                    user_check = 'https://'+target+user_list_item
                    curl_response = requests.get(user_check,verify=False)
                    #print(Fore.CYAN+str(curl_response.status_code)+Fore.WHITE)
                    if curl_response.status_code in range (300,304):
                        location = curl_response.headers.get('Location')
                        f.write('method 1:\n'+str(location)+'\n')
                        print(Fore.GREEN+location+Fore.WHITE)
                    if curl_response.status_code == 200:
                        match = re.search(r'<span class="comment-author-link">(.*?)</span>', str(curl_response._content))
                        if match:
                            value = match.group(1)
                            #f.write('\nmethod 1:\n'+str(value))
                            #f.write('\nmethod 1 content: \n'+str(curl_response.content))
                        else:
                            pass
                        match2 = re.search(r'<title>(.*)<\/title>', str(curl_response._content))
                        if match2:
                            value = match2.group(1)
                            print(Fore.CYAN,user_check,Fore.GREEN,str(curl_response.status_code),'FOUND',Fore.WHITE)
                            try:
                                f.write('method 1:\n'+str(value)+'\n')
                                print(str(value))
                            except:
                                print(Fore.RED+'Somting Wrong'+Fore.WHITE)
                        else:
                            print("No match found")
                    else:
                        print(Fore.CYAN,user_check,Fore.RED,str(curl_response.status_code),'NOT FOUND',Fore.WHITE)
                        break
            print(Fore.YELLOW+'\nMETHOD 2'+Fore.WHITE)
            curl_response = requests.get('https://'+target+'/wp-json/wp/v2/users',verify=False)
            if curl_response.status_code == 200:
                json_data = json.loads(curl_response.content)
                for json_item in json_data:
                    #print(json_item)
                    enum=str(Fore.GREEN+'FOUND '+Fore.GREEN+' NAME: '+Fore.WHITE+json_item['name']+Fore.GREEN+' USERNAME: '+Fore.WHITE+json_item['slug']+Fore.GREEN+' URL: '+Fore.WHITE+json_item['link'])
                    f.write('\nmethod 2: \n'+'NAME: '+json_item['name']+' USERNAME: '+json_item['slug']+' URL: '+json_item['link'])
                    print(enum)
            if curl_response.status_code in range (200,399):
                print(Fore.RED+'Trying to Bypass...',Fore.WHITE)
                curl_response2 = requests.get('https://'+target+'/?rest_route=/wp/v2/usErs',verify=False)
                if curl_response2.status_code == 200:
                    json_data = json.loads(curl_response2.content)
                    for json_item in json_data:
                        enum=str(Fore.GREEN+'FOUND '+Fore.GREEN+' NAME: '+Fore.WHITE+json_item['name']+Fore.GREEN+' USERNAME: '+Fore.WHITE+json_item['slug']+Fore.GREEN+' URL: '+Fore.WHITE+json_item['link'])
                        f.write('\nmethod 2: \n'+'NAME: '+json_item['name']+' USERNAME: '+json_item['slug']+' URL: '+json_item['link'])
                        print(enum)
                else:
                    curl_response3 = requests.get('https://'+target+'/section/news?rest_route=/wp/v2/usErs',verify=False)
                    if curl_response3.status_code == 200:
                        json_data = json.loads(curl_response3.content)
                    for json_item in json_data:
                        enum=str(Fore.GREEN+'FOUND '+Fore.GREEN+' NAME: '+Fore.WHITE+json_item['name']+Fore.GREEN+' USERNAME: '+Fore.WHITE+json_item['slug']+Fore.GREEN+' URL: '+Fore.WHITE+json_item['link'])
                        f.write('\nmethod 2: \n'+'NAME: '+json_item['name']+' USERNAME: '+json_item['slug']+' URL: '+json_item['link'])
                        print(enum)
                    else:
                        print(Fore.RED+'The target is not responding to this method.'+Fore.WHITE)
            else:
                print(Fore.RED+'Target Hide Author, FalCon Cannot Enummeration'+Fore.WHITE)
                        ######
            print(Fore.YELLOW+'\nMETHOD 3'+Fore.WHITE)
            curl_response = requests.get('https://'+target+'/author-sitemap.xml',verify=False)
            curl_response2 = requests.get('https://'+target+'/wp-sitemap-users-1.xml',verify=False)
            if curl_response.status_code == 200:
                match3 = re.search(r'<loc>(.*)<\/loc>', str(curl_response._content))
                print(Fore.GREEN+'Sitemap.xml is Enable'+Fore.WHITE)
                if match3:
                    value = match3.group(1)
                    try:
                        f.write('method 3:\n'+str(value)+'\n')
                        print(str(value))
                    except:
                        print(Fore.RED+'Somting Wrong'+Fore.WHITE)
                    if curl_response2.status_code == 200:
                        match3 = re.search(r'<loc>(.*)<\/loc>', str(curl_response._content))
                        if match3:
                            value = match3.group(1)
                        try:
                            f.write('method 3:\n'+str(value)+'\n')
                            print(str(value))
                        except:
                            print(Fore.RED+'Somting Wrong'+Fore.WHITE)
                        else:
                            print(Fore.RED+'Somting Wrong'+Fore.WHITE)
                else:
                    print("No match found")
            else:
                print(Fore.RED+'Sitemap.xml is DISABLE'+Fore.WHITE)
            break
        else:
            print(Fore.YELLOW+'Trying to find Signatures...'+Fore.WHITE)
            print(Fore.RED+'Is Target using another content management system or is it trying to fool us!!!'+Fore.WHITE)
    f.close()



def dir_browse():
    print(Fore.YELLOW+'\nDirectory Browsing Check'+Fore.WHITE)
    curl_css = requests.get('https://'+target,verify=False)
    if curl_css.status_code == 403:
        print(Fore.RED+'\nTarget is not responding!!!'+Fore.WHITE)
    else:
        css_pattern = re.compile(r"http[^']*\.css")
        css_urls = css_pattern.findall(str(curl_css.content))
        #print(css_urls[0])
        single_css = re.compile(r"http.*\/")
        css_urls = single_css.findall(str(css_urls[0]))
        curl_css_response = requests.get(css_urls[0],verify=False)
        print(Fore.CYAN+'URL CHECK: '+Fore.WHITE+str(css_urls))
        if "Index of" in str(curl_css_response.content):
            print('\nDirectory Browsing is '+Fore.GREEN+' ENABLE\n'+Fore.WHITE)
            if os.path.exists(target+"\\DIR_BROWSE.txt"):
                os.remove(target+"\\DIR_BROWSE.txt")
            f = open(target+"\\DIR_BROWSE.txt", "a", encoding="utf-8")
            f.write(str(css_urls[0])+'\n')
            url_list = ['/wp-content/uploads/']
            for url_item in url_list:
                curl_response = requests.get('https://'+target+url_item,verify=False)
                if curl_response.status_code == 200:
                    f.write('https://'+target+url_item+"\n")
                    print(Fore.GREEN+'https://'+target+url_item+Fore.WHITE)
                    f.write('\n\n\n'+str(curl_response.content))
                else:
                    print('https://'+target+url_item)
                    print(Fore.RED+'Maybe target using Custome CMS!'+Fore.WHITE)
            f.close()
        else:
            print('Directory Browsing is '+Fore.RED+' DISABLE'+Fore.WHITE)

def wp_scan():
    print(Fore.YELLOW+'\nWP SCAN'+Fore.WHITE)
    subprocess('wpscan -u https://'+target+' --api jEjWaAIEbuFUwbsgc12sMZClFWk3DVlapg5m9pIDBnU -o '+target+'\\WP_SCAN.txt')

def ipinfo():
    print(Fore.YELLOW+'\nIP INFO'+Fore.WHITE)
    f = open(target+"\\IP_INFO.txt", "w", encoding="utf-8")
    ip_address = socket.gethostbyname(target)
    print(target+Fore.YELLOW+' IP '+Fore.GREEN+ip_address+Fore.WHITE)
    f.write(target+' IP '+ip_address)
    curl_response = requests.get('https://ipinfo.io/widget/demo/'+ip_address,verify=False)
    if curl_response.status_code == 200:
        f.write('\n\n'+str(curl_response.content))
        print(str(curl_response.content))
    else:
        f.write('\nhttps://ipinfo.io/widget/demo/'+ip_address+'  YOUR REGION HAVE BEEN BOCKED!!!')
        f.write('\nHTTP STATUS CODE: '+str(curl_response.status_code))
        print('HTTP STATUS CODE:',Fore.YELLOW,curl_response.status_code)
        print(Fore.RED+'YOUR REGION HAVE BEEN BOCKED!!!'+Fore.WHITE)
    f.close()


def wayback():
    print(Fore.YELLOW+'\nWayBack Machine'+Fore.WHITE)
    wayback_curl_response = requests.get('http://web.archive.org/cdx/search/cdx?url='+target+'/*&limit=5&output=json',verify=False)
    wayback_curl_response2 = [
    ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
    ["ir,n-moj)/", "20161026215747", "http://n-moj.ir:80/", "text/html", "200", "DGCR5S73SH42VMACNQ3J5YF74M5TVIAC", "2370"],
    ["ir,n-moj)/", "20170108094820", "http://www.n-moj.ir:80/", "text/html", "200", "BY4GHTMO5BVSP4ILJKO7SRPHBNN2B322", "2368"],
    ["ir,n-moj)/", "20170214164442", "http://n-moj.ir:80/", "text/html", "200", "BY4GHTMO5BVSP4ILJKO7SRPHBNN2B322", "2369"]
]

    #for row in wayback_curl_response[1:]:  # Skip the header row
        #print(f"Original: {row[2]}, , "+)
        #print(Fore.YELLOW+f"Time Stamp: {row[1]}"+Fore.CYAN+f" StatusCode: {row[4]}"+Fore.WHITE+f" URL: {row[2]}")
    if wayback_curl_response.status_code == 200:
        #print(Fore.YELLOW+f"Time Stamp: {row[1]}"+Fore.CYAN+f" StatusCode: {row[4]}"+Fore.WHITE+f" URL: {row[2]}")
        json_data = json.loads(wayback_curl_response.content)
        if json_data and isinstance(json_data[0], dict):
            print('URL: ' + json_data[0]['original'], 'Status Code: ' + json_data[0]['statuscode'], 'Time Stamp: ' + json_data[0]['timestamp'])
        else:
            print(Fore.RED+"\nArchive.org BLOCKED OUR REGION!!!"+Fore.WHITE)
        #print('URL: '+json_data[0]['original'],'Status Code: '+json_data[0]['statuscode'],'Time Stamp: '+json_data[0]['timestamp'])
        f = open(target+"\\WAY_BACK.txt", "w", encoding="utf-8")
        f.write(str(wayback_curl_response.content))
        f.close()
    else:
        print('Status Code: '+Fore.YELLOW+str(wayback_curl_response.status_code)+Fore.RED+'\nArchive.org BLOCKED OUR REGION!!!'+Fore.WHITE)

def subfinder():
    print(Fore.YELLOW+'SUBDOMAIN FINDER'+Fore.WHITE)
    try:
        subdomain = subprocess('subfinder ')
    except:
        print(Fore.RED+'This tool requires prerequisites for some sections. Please install the subfinder tool.'+Fore.WHITE)
        print(Fore.CYAN+'Installation Command : go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'+Fore.WHITE)
        print('Github : https://github.com/projectdiscovery/subfinder/tree/dev')

def wafw00f():
    print(Fore.YELLOW+'WAF DETECTION'+Fore.WHITE)
    waf_cmd = ['-f', 'text', '-o', target + '/WAF.txt']
    waf_target = "https://" + target + "/"
    command = ["wafw00f", waf_target] + waf_cmd
    ans = subprocess.run(command, capture_output=True, text=True)
    print(ans.stdout)
    if ans == 0:
        pass
    else:
        print("wafw00f Command failed.")

def wp_register():
    print(Fore.YELLOW+'WORDPRESS USER REGISTER'+Fore.WHITE)
    f = open(target+"\\WP_REGISTER.txt", "w", encoding="utf-8")
    curl_response = requests.get('https://'+target+'/wp-login.php?action=register')
    if curl_response.status_code == 200:
        if 'login_error' in str(curl_response.content):
            print(Fore.RED+'WP Register is DISABLE'+Fore.WHITE)
            f.write('WP Register is DISABLE\n')
        else:
            print(Fore.GREEN+'WP Register is ENABLE'+Fore.WHITE)
            print('URL : https://'+target+'/wp-login.php?action=register')
            f.write('WP Register is ENABLE \nURL : https://'+target+'/wp-login.php?action=register')
    else:
            print('Status Code: '+Fore.RED+str(curl_response.status_code))
            print('WP Register is DISABLE'+Fore.WHITE)
    f.close()

def wp_install():
    f = open(target+"\\WP_INSTALL.txt", "w", encoding="utf-8")
    print(Fore.YELLOW+'WORDPRESS INSTALL PAGE'+Fore.WHITE)
    curl_response = requests.get('https://'+target+'/wp-admin/install.php')
    if curl_response.status_code == 200:
        print(Fore.GREEN+'WP Install page : '+Fore.WHITE+'https://'+target+'/wp-admin/install.php')
        f.write('WP Install page : \nhttps://'+target+'/wp-admin/install.php')
    else:
        print('WP Install Not Found'+Fore.WHITE)
    f.close()

def wp_install():
    f = open(target+"\\WP_VERSION.txt", "w", encoding="utf-8")
    print(Fore.YELLOW+'WORDPRESS VERSION DISCOVERY'+Fore.WHITE)
    try:
        response = requests.get('https://'+target)
        if response.status_code != 200:
            print(f"Error: Unable to access the URL. Status code: {response.status_code}")
            return
        soup = BeautifulSoup(response.content, 'html.parser')
        version_meta = soup.find('meta', attrs={'name': 'generator'})
        if version_meta:
            version = version_meta.get('content', 'Version not found')
            print(Fore.GREEN+f"WordPress Version: {Fore.WHITE+version}")
            f.write('WP version : \n'+version)
        else:
            print("WordPress version not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    f.close()



clear()
banner()
urllib3.disable_warnings()
target_mkdir()
target_check()
nmap()
backup_file()
wp_user_enum()
dir_browse()
wp_register()
wp_install()
wp_scan()
ipinfo()
wayback()
wafw00f()

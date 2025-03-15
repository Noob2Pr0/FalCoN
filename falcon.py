import os, sys, subprocess, platform
from colorama import Fore, init
import nmap3, socket
import json, re, requests, argparse
import urllib.request, urllib3
from bs4 import BeautifulSoup
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

falcon_version=0.4

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
 |  ____|  | |/ ____|    | \\ | |
 | |__ __ _| | |     ___ |  \\| |"""+Fore.WHITE+"""
 |  __/ _` | | |    / _ \\| . ` |
 | | | (_| | | |___| (_) | |\\  |"""+Fore.RED+"""
 |_|  \\__,_|_|\\_____\\___/|_| \\_| """+Fore.YELLOW+"""v0.4a (Beta)
     """+Fore.CYAN+"""OmidNasiri.P@Gmail.COM  
"""+Fore.WHITE)

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='URL Address [Example: site.com | DONT USE HTTPS://site.com]')
parser.add_argument('-s', help='Output without banner')
parser.add_argument('--all', help='test all pentest cases')
parser.add_argument('--debug', help='Print Miss logs. For Debuging')
parser.add_argument('--mode', help='Check Specific Cases, Example: --mode a,b,c,d,e,f')
#parser.add_argument('', help='')
parser.add_argument('--update', help='Check for new version')
args = parser.parse_args()

target = args.u
debug = args.debug
all = args.all
mode = args.mode


target_https='https://'+target
target_http='http://'+target
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0 Safari/537.36'
}

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
def target_check(headers):
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = target_http
    try:
        http_response = requests.get(target_url,verify=False,headers=headers)
        final_url = http_response.url
        if final_url.startswith("https"):
            print("\n"+Fore.MAGENTA+"[HTTPS]"+Fore.WHITE,http_response.status_code)
        elif final_url.startswith("http"):
            print(Fore.GREEN+"\n[FOUND]","[HTTP]"+Fore.WHITE,http_response.status_code)
            target_https = target_http

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")







"""
    curl_response = requests.get(target_https,verify=False,headers=headers)
    curl_response2 = requests.get(target_http,verify=False,headers=headers,allow_redirects=False) 
    #print(target)
    if curl_response.status_code in range(200,350):
        target_path = os.path.join(target, "HEADERS.txt")
        f=  open(target_path, "w", encoding="utf-8")
        print(Fore.YELLOW+'\nCHECK TARGET',Fore.WHITE)
        print(Fore.YELLOW+'[HTTPS]'+Fore.GREEN+' ENABLE '+Fore.WHITE)
        if curl_response2.status_code in range(200,250):
            if 'https' in curl_response2:
                print(Fore.YELLOW+'[HTTP]'+Fore.RED+' DISABLE '+Fore.WHITE)
        else:
            print(Fore.YELLOW+'[HTTP]'+Fore.GREEN+' ENABLE '+Fore.WHITE)
            print(Fore.YELLOW+'\nHTTP RESPONSE HEADERS',Fore.WHITE)
            print(Fore.GREEN+'Target',target,'respose code is',curl_response2.status_code,Fore.WHITE)
            http_headers = curl_response2.headers
            http_readable_headers = "\n".join([f"{key}: {value}" for key, value in http_headers.items()])
            f.write(http_readable_headers)
        print(Fore.GREEN+'Target',target,'respose code is',curl_response.status_code,Fore.WHITE)
        print(Fore.YELLOW+'\nHTTPS RESPONSE HEADERS',Fore.WHITE)
        headers = curl_response.headers
        readable_headers = "\n".join([f"{key}: {value}" for key, value in headers.items()])
        
        f.write(readable_headers)
        f.close()
        print(readable_headers)
    else:
        print(Fore.YELLOW+'Target',target,'respose code is',curl_response.status_code+Fore.WHITE)
"""

############## NMAP ##############
def nmap():
    #f=  open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW+'Nmap:')
    print(Fore.WHITE)
    command=target,'-v -Pn'
    nmap = nmap3.Nmap()
    target_addr=target+r"\\Nmap.txt"
    results = nmap.scan_top_ports(target, args="-Pn -v -oN "+target_addr)
    #print(results)
    #f = open(target_addr, 'r')
    #file_contents = f.read()
    #print (file_contents)
    #f.close()

########### Quick Backupfile Check ###########
def backup_file(headers):
    print(Fore.YELLOW + '\n[BACKUP]' + Fore.WHITE)
    try:
        target_nodomain = target.split('.')[0]
        backup_file_list = [
            'wp-config.zip', 'wp-config.bak', 'wp-config.txt', 'wp-config.php.zip', 'wp-config.php.bak', 'wp-config.php.txt',
            'error_log', 'public_html.zip', target_nodomain + '.zip', 'backup.zip', 'backup.tar.gz', 'backup.sql', 
            target_nodomain + '.sql', 'wp-content-backup.zip', 'database-backup.sql', 'backup-website.zip', 
            'backup-' + target_nodomain + '.zip', 'fullbackup.zip', 'full-' + target_nodomain + '.zip', 'wp-db.zip', 
            'public_html-backup.tar.gz', 'public_html-backup.zip', 'backup.bak', 'backup.7z', 'full_backup.tar.gz'
        ]
        def check_and_save_backup(bak):
            backup_url = 'https://' + target + "/" + bak
            curl_response = requests.get(backup_url, verify=False, headers=headers)
            if curl_response.status_code == 200:
                print(Fore.GREEN+'[FOUND]'+Fore.WHITE,backup_url)
                global bkfound
                bkfound = True
                #print(Fore.CYAN + backup_url, ":", Fore.GREEN + str(curl_response.status_code) + Fore.WHITE)
                response = urllib.request.urlopen(backup_url)
                data = response.read()  # a `bytes` object
                backup_data = data.decode('utf-8')
                target_path = os.path.join(target, bak)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(backup_data)
            else:
                if all != None:
                    print(Fore.MAGENTA+'[MISS]'+Fore.WHITE,backup_url)
                    #print(Fore.CYAN + backup_url, ":", Fore.RED + str(curl_response.status_code) + Fore.WHITE)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_and_save_backup, bak) for bak in backup_file_list]
            for future in concurrent.futures.as_completed(futures):
                future.result()
    except:
        if bkfound != True:
            print(Fore.RED + 'Not Found' + Fore.WHITE)



#### Wordpress User Enumeration with 5 Methods
def wp_user_enum(headers):
    global username_list
    username_list = []
    print(Fore.YELLOW + '\n' + '[User Enumeration]' + Fore.WHITE)
    curl_response = requests.get(target_https,verify=False,headers=headers,timeout=30)
    if 'wp-' in str(curl_response.content):
        target_path = os.path.join(target, "USER_ENUM.txt")
        f=  open(target_path, "w", encoding="utf-8")
        ##### User Enum by Author ID
        autor_list_id = ['/?author=0', '/?author=1', '/?author=2', '/?author=3', '/?author=4', '/?author=5']
        f.write('\n AuthorID Method \n')
        print(Fore.CYAN +'[ID]' + Fore.WHITE)

        curl_response_test = requests.get(target_https + '/?author=1000000000000', verify=False, allow_redirects=False, headers=headers, timeout=30)
        if curl_response_test.status_code in range(200, 399):
            print(Fore.RED + 'Target trying to fool us!' + Fore.WHITE)
            f.write('\n'+'Target trying to fool us!'+'\n')
        def fetch_author(author_item):
            curl_response = requests.get(target_https + author_item, verify=False, allow_redirects=False, headers=headers, timeout=30)
            if curl_response.status_code in range(300, 399):
                location = curl_response.headers.get('Location')
                return f"{Fore.GREEN}[FOUND]{Fore.WHITE} {location}"
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(fetch_author, autor_list_id))

        for result in results:
            if result:
                print(result)
                f.write(result+'\n')


        ##### User Enum by Sitemap
        sitemap_list = ['/author-sitemap.xml', '/wp-sitemap-users-1.xml', '/sitemap.xml']
        f.write('\n SiteMap Method \n')
        print(Fore.CYAN + '\n' + '[SITEMAP]' + Fore.WHITE)
        for sitemap_item in sitemap_list:
            curl_response = requests.get(target_https + sitemap_item, verify=False, allow_redirects=False, headers=headers, timeout=30)
            pattern = r'<loc>(.*?)</loc>'
            matches = re.findall(pattern, str(curl_response.content))
            for match in matches:
                # Extract username from the URL (assuming it is the last part of the URL)
                if '/author/' in match:
                    username = match.split('/author/')[-1].strip('/')
                    # Add the username to the set if it's unique
                    if username not in username_list:
                        username_list.append(username)
                        print(Fore.GREEN + '[FOUND]' + Fore.WHITE, username)
                        f.write(username + '\n')

        ##### User Enum by WP-JSON
        json_list = ['/wp-json/wp/v2/users', '/?rest_route=/wp/v2/usErs', '/section/news?rest_route=/wp/v2/usErs']
        print(Fore.CYAN + '\n' + '[WP-JSON]' + Fore.WHITE)
        f.write('\n [WP-JSON] \n')

        for json_item in json_list:
            curl_response = requests.get(target_https + json_item, verify=False, allow_redirects=False, headers=headers, timeout=30)
            if curl_response.status_code == 200:
                json_data = json.loads(curl_response.content)
                for json_data_item in json_data:
                    link = json_data_item['link']
                    # Extract username from the link (assuming the username is the last part of the URL)
                    username = link.rstrip('/').split('/')[-1]
                    # Add the username to the list if it's not already there
                    if username not in username_list:
                        username_list.append(username)
                        print(Fore.GREEN + '[FOUND]' + Fore.WHITE, username)
                        f.write(username + '\n')
        #print("\nCollected Usernames:", username_list)

        """
        ##### User Enum by WP-JSON
        json_list = ['/wp-json/wp/v2/users','/?rest_route=/wp/v2/usErs','/section/news?rest_route=/wp/v2/usErs']
        print(Fore.CYAN+'\n'+'[WP-JSON]'+Fore.WHITE)
        f.write('\n [WP-JSON] \n')
        for json_item in json_list:
            curl_response = requests.get(target_https+json_item,verify=False,allow_redirects=False,headers=headers,timeout=30)
            if curl_response.status_code == 200:
                json_data = json.loads(curl_response.content)
                for json_data_item in json_data:
                    print(Fore.GREEN+'[FOUND]',Fore.WHITE+json_data_item['link'])
                    f.write(json_data_item['link']+'\n')
        """


        ##### User Enum by rss/feed
        rss_list = ['/rss', '/feed']  # ,'/comments/feed/']
        f.write('\n [RSS/FEED] \n')
        print(Fore.CYAN + '\n' + '[RSS/feed]' + Fore.WHITE)
        unique_matches = set()
        max_checks = 150
        total_checks = 0
        def is_persian(text):
            return any('\u0600' <= char <= '\u06FF' for char in text)
        for rss_item in rss_list:
            curl_response = requests.get(target_https + rss_item, verify=False, headers=headers, timeout=30)
            pattern = r'<dc:creator><!\[CDATA\[(.*?)\]\]></dc:creator>'
            matches = re.findall(pattern, curl_response.content.decode('utf-8'))  # Decode UTF-8 content

            if matches:
                for match in matches:
                    if match not in unique_matches and total_checks < max_checks:  # Check if match is unique and within max_checks limit
                        unique_matches.add(match)
                        if is_persian(match):
                            processed_match = match[::-1]  # Reverse the text for Persian
                        else:
                            processed_match = match
                        print(Fore.GREEN + '[FOUND] ', Fore.WHITE + processed_match)
                        f.write(match+'\n')
                        total_checks += 1
                    if total_checks >= max_checks:
                        break  # Stop if max_checks is reached

        ##### User Enum Other Method
        other_list = ['/wp-json/oembed/1.0/embed?url='+target_https+'/&format=json']
        f.write('\n Other Method \n')
        print(Fore.CYAN+'\n'+'[OtherMethods]'+Fore.WHITE)
        for other_item in other_list:
            curl_response = requests.get(target_https+other_item,verify=False,allow_redirects=False,headers=headers,timeout=30)
            if curl_response.status_code == 200:
                other_data = json.loads(curl_response.content)
                author_url = other_data.get("author_url")
                if author_url:
                    if 'author' in author_url:
                        print(Fore.GREEN+'[FOUND] ',Fore.WHITE+author_url)
                        f.write(author_url+'\n')
                    else:
                        pass
        f.close()
    else:
        print(Fore.RED+'[WARNING]',Fore.WHITE+'Target not using wordpress')
        




##### Directory Browsing
def dir_browse(headers):
    print(Fore.YELLOW+'\n[Directory Browsing]'+Fore.WHITE)
    try:
        curl_css = requests.get('https://'+target,verify=False,headers=headers)
        if curl_css.status_code == 403:
            print(Fore.RED+'\nTarget is not responding!!!'+Fore.WHITE)
        else:
            css_pattern = re.compile(r"http[^']*\.css")
            css_urls = css_pattern.findall(str(curl_css.content))
            #print(css_urls[0])
            single_css = re.compile(r"http.*\/")
            css_urls = single_css.findall(str(css_urls[0]))
            curl_css_response = requests.get(css_urls[0],verify=False,headers=headers)
            print(Fore.CYAN+'[URL]',Fore.WHITE+str(css_urls[0]))
            if "Index of" in str(curl_css_response.content):
                print('\nDirectory Browsing '+Fore.GREEN,'[ENABLE]\n'+Fore.WHITE)
                if os.path.exists(target+"\\DIR_BROWSE.txt"):
                    os.remove(target+"\\DIR_BROWSE.txt")
                target_path = os.path.join(target, "DIR_BROWSE.txt")
                f=  open(target_path, "a", encoding="utf-8")
                f.write(str(css_urls[0])+'\n')
                url_list = ['/wp-content/uploads/']
                for url_item in url_list:
                    curl_response = requests.get('https://'+target+url_item,verify=False,headers=headers)
                    if curl_response.status_code == 200:
                        f.write('https://'+target+url_item+"\n")
                        print(Fore.GREEN+'https://'+target+url_item+Fore.WHITE)
                        f.write('\n\n\n'+str(curl_response.content))
                    else:
                        print('https://'+target+url_item)
                        print(Fore.RED+'Maybe target using Custome CMS!'+Fore.WHITE)
                f.close()
            else:
                print(Fore.CYAN+'[Dir Browsing]'+Fore.RED,'DISABLE'+Fore.WHITE)
    except:
        print('[Dir Browsing]'+Fore.RED,'Failed'+Fore.WHITE)

def wp_scan(headers):
    print(Fore.YELLOW+'\n[WP SCAN]'+Fore.WHITE)
    subprocess('wpscan -u https://'+target+' --api jEjWaAIEbuFUwbsgc12sMZClFWk3DVlapg5m9pIDBnU -o '+target+'\\WP_SCAN.txt')

def ipinfo(headers):
    print(Fore.YELLOW+'\n[IP]'+Fore.WHITE)
    target_path = os.path.join(target, "IP_INFO.txt")
    f=  open(target_path, "w", encoding="utf-8")
    ip_address = socket.gethostbyname(target)
    print(target+Fore.YELLOW+' IP '+Fore.GREEN+ip_address+Fore.WHITE)
    f.write(target+' IP '+ip_address)
    curl_response = requests.get('https://ipinfo.io/widget/demo/'+ip_address,verify=False,headers=headers)
    if curl_response.status_code == 200:
        f.write('\n\n'+str(curl_response.content))
        print(str(curl_response.content))
    else:
        f.write('\nhttps://ipinfo.io/widget/demo/'+ip_address+'  YOUR REGION HAVE BEEN BOCKED!!!')
        f.write('\nHTTP STATUS CODE: '+str(curl_response.status_code))
        print('HTTP STATUS CODE:',Fore.YELLOW,curl_response.status_code)
        print(Fore.RED+'YOUR REGION HAVE BEEN BOCKED!!!'+Fore.WHITE)
    f.close()


def wayback(headers):
    print(Fore.YELLOW+'\n[WayBack Machine]'+Fore.WHITE)
    wayback_curl_response = requests.get('https://web.archive.org/cdx/search/cdx?url='+target+'/*&limit=5&output=json',verify=False,headers=headers)

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
        target_path = os.path.join(target, "WAY_BACK.txt")
        f=  open(target_path, "w", encoding="utf-8")
        f.write(str(wayback_curl_response.content))
        f.close()
    else:
        print('Status Code: '+Fore.YELLOW+str(wayback_curl_response.status_code)+Fore.RED+'\nArchive.org BLOCKED OUR REGION!!!'+Fore.WHITE)

def subfinder():
    print(Fore.YELLOW+'\n[SUBDOMAIN]'+Fore.WHITE)
    try:
        subdomain = subprocess('subfinder -t '+target)
    except:
        print(Fore.RED+'This tool requires prerequisites for some sections. Please install the subfinder tool.'+Fore.WHITE)
        print(Fore.CYAN+'Installation Command : go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'+Fore.WHITE)
        print('Github : https://github.com/projectdiscovery/subfinder/tree/dev')

def wafw00f():
    print(Fore.YELLOW+'\n[WAF]'+Fore.WHITE)
    waf_cmd = ['-f', 'text', '-o', target + '/WAF.txt']
    waf_target = "https://" + target + "/"
    command = ["wafw00f", waf_target] + waf_cmd
    ans = subprocess.run(command, capture_output=True, text=True)
    print(ans.stdout)
    if ans == 0:
        pass
    else:
        print("wafw00f Command failed.")



##### REGISTER
def wp_register(headers):
    print(Fore.YELLOW+'\n[WP REGISTER]'+Fore.WHITE)
    target_path = os.path.join(target, "WP_REGISTER.txt")
    f=  open(target_path, "w", encoding="utf-8")
    register_list=['/wp-signup.php','/wp-register.php','/wp-login.php?action=register']
    for register_item in register_list:
        curl_response = requests.get('https://'+target+register_item,verify=False,headers=headers)
        if curl_response.status_code == 200:
            if 'login_error' in str(curl_response.content):
                print(Fore.RED+'[Disable]',Fore.CYAN+target_https+register_item,Fore.WHITE,'Status Code: '+Fore.RED+str(curl_response.status_code)+Fore.WHITE)
            else:
                print(Fore.GREEN+'[URL]'+Fore.CYAN+target_https+target+register_item,Fore.WHITE,'Status Code: '+Fore.GREEN+str(curl_response.status_code)+Fore.WHITE)
                f.write('URL : https://'+target+str(register_item)+'\n')
        else:
                print(Fore.RED+'[Disable]',Fore.CYAN+target_https+register_item,Fore.WHITE,'Status Code: '+Fore.RED+str(curl_response.status_code)+Fore.WHITE)
    f.close()


##### WP INSALL PAGE
def wp_install(headers):
    default_pages=['/wp-admin/upgrade.php','/wp-admin/install.php'] # Next Version Improvement
    target_path = os.path.join(target, "WP_INSTALL.txt")
    f=  open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW+'\n[WP Default Pages]'+Fore.WHITE)
    curl_response = requests.get('https://'+target+'/wp-admin/install.php',verify=False,headers=headers)
    if curl_response.status_code == 200:
        print(Fore.GREEN+'WP Install page : '+Fore.WHITE+'https://'+target+'/wp-admin/install.php')
        f.write('WP Install page : \nhttps://'+target+'/wp-admin/install.php')
    else:
        print('WP Install Not Found'+Fore.WHITE)
    f.close()


##### WP VERSION DISCOVERY
def wp_version(headers):
    f = open(target+"\\WP_VERSION.txt", "w", encoding="utf-8")
    print(Fore.YELLOW+'\nWORDPRESS VERSION DISCOVERY'+Fore.WHITE)
    try:
        response = requests.get('https://'+target,verify=False,headers=headers)
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



##### WP PLUGIN + VERSION DISCOVERY
def wp_plugin(headers):
    target_path = os.path.join(target, "WP_PLUGINS.txt")
    
    try:
        with open(target_path, "w", encoding="utf-8") as f:
            print(Fore.YELLOW + '\n[WP Plugin Version]' + Fore.WHITE)
            response = requests.get('https://' + target, verify=False, headers=headers)
            
            if response.status_code != 200:
                print(Fore.RED + f"Failed to fetch data from {target}, status code: {response.status_code}" + Fore.WHITE)
                return
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            regex = r'/plugins/([^/]+)'
            regex2 = r'\?ver=(.*)'
            
            plugins = {}

            # Process <link> tags
            for link_tag in soup.find_all('link', href=True):
                if '/plugins/' in link_tag['href']:
                    match = re.search(regex, link_tag['href'])
                    match2 = re.search(regex2, link_tag['href'])
                    if match and match2:
                        plugin_name = match.group(1)
                        plugin_version = match2.group(1)
                        if plugin_name not in plugins:
                            plugins[plugin_name] = []
                        plugins[plugin_name].append((plugin_version, link_tag['href']))

            # Process <script> tags
            for script_tag in soup.find_all('script', src=True):
                if '/plugins/' in script_tag['src']:
                    match = re.search(regex, script_tag['src'])
                    match2 = re.search(regex2, script_tag['src'])
                    if match and match2:
                        plugin_name = match.group(1)
                        plugin_version = match2.group(1)
                        if plugin_name not in plugins:
                            plugins[plugin_name] = []
                        plugins[plugin_name].append((plugin_version, script_tag['src']))

            # Output results
            if not plugins:
                print(Fore.RED + "No plugins found!" + Fore.WHITE)
                return

            for plugin_name, versions in plugins.items():
                # Determine the most frequent version
                version_counter = Counter([v[0] for v in versions])
                most_common_version = version_counter.most_common(1)[0][0]

                # Find the URL corresponding to the most common version
                url = next(v[1] for v in versions if v[0] == most_common_version)

                print(Fore.GREEN+'[FOUND]'+Fore.WHITE,plugin_name,':', most_common_version)#, Fore.CYAN + url + Fore.WHITE)
                f.write(plugin_name + ' ' + most_common_version + ' ' + url + '\n')

    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Fore.WHITE)















"""
    target_path = os.path.join(target, "WP_PLUGINS.txt")
    f=  open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW+'\n[WP Plugin Version]'+Fore.WHITE)
    response = requests.get('https://'+target, verify=False,headers=headers)
    soup = BeautifulSoup(response.content, 'html.parser')
    print(Fore.CYAN+'     [Link-TAG]'+Fore.WHITE)
    f.write('###### Link Tag href Value ######'+'\n')
    regex = r'\/plugins\/([^\/]+)'
    regex2 = r'\?ver=(.*)'
    for link_tag in soup.find_all('link', href=True):
        if '/plugins/' in link_tag['href']:
            #print(link_tag['href']) 
            match = re.search(regex, link_tag['href'])
            match2 = re.search(regex2, link_tag['href'])
            if match:
                if match2:
                    with open(target_path, "r", encoding="utf-8") as file:
                        content = file.read()
                        #### BADAN BAYAD DOROSTESH KONAM TEKRARI PRINT NAKONE
                        if str(match.group(1)) in content:
                            pass
                        else:
                            print(match.group(1),Fore.GREEN,match2.group(1)+Fore.WHITE)
                            f.write(match.group(1)+' '+match2.group(1)+'\n')
    print(Fore.CYAN+"\n     [Script-TAG]"+Fore.WHITE)
    f.write('\n##### Script Tag src Value #####'+'\n')
    for script_tag in soup.find_all('script', src=True):
        if '/plugins/' in script_tag['src']:
            match = re.search(regex, script_tag['src'])
            match2 = re.search(regex2, script_tag['src'])
            if match:
                if match2:
                    with open(target_path, "r", encoding="utf-8") as file:
                        content = file.read()
                        #### BADAN BAYAD DOROSTESH KONAM TEKRARI PRINT NAKONE
                        if str(match.group(1)) in content:
                            pass
                        else:
                            print(match.group(1),Fore.GREEN,match2.group(1)+Fore.WHITE)
                            f.write(match.group(1)+' '+match2.group(1)+'\n')
            #print(script_tag['src'])
            #f.write(script_tag['src']+'\n')
    f.close()
 """


##### FILE + DIR FUZZ
def ffuf(headers):
    print(Fore.YELLOW+'\nCreate ffuf command list'+Fore.WHITE)

    target_path = os.path.join(target, "SUB_DOMAIN.txt")
    with open(target_path, "r", encoding="utf-8") as file:

        for line in file:
            print(line, end='ss')
            print('ffuf -u https://'+line+'/FUZZ -w wordlist/files/all_files.txt')
            print('ffuf -u https://'+line+'/FUZZ -w wordlist/dir/raf_dir.txt')
            print('ffuf -u https://'+line+'/FUZZ -w wordlist/api/api.txt')

   # with open('README.md', 'r') as file:
        # Print the contents of README.md with the "echo" message
    #    print("\n[Echo]: End of sub.txt, here comes README.md:")
     #   print(file.read())  # Print the entire content of README.md
    print(Fore.GREEN+'\nSave in '+target+'\\ffuf.txt'+Fore.WHITE)


##### ERROR DISCOVERY
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor
import os
import requests

def error(headers):
    # Initialize colorama for color formatting
    init(autoreset=True)
    target_path = os.path.join(target, "ERRORS.txt")
    f = open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW + '\n[ERRORS]' + Fore.WHITE)

    url_list = [
        '/FAL_CON.php', '/FAL_CON.aspx', '/?FAL_CON=FAL_CON', '/verylongpathnameexceedinglengthncaslcnaslkamcs',
        '/../../../../etc/passwd', '/uploads/', '/wp-content/uploads/', '/?id="order by 1=1--',
        '/?id=<script>alert(1)</script>', '/admin/', '/api/v1/', '/api/v2/', '/api/users/', '/api', '/wp-admin',
        '/maintenance-mode', '/overloaded', '/api/v1/resource', '/400.shtml', '/cgi-bin/test-cgi', '/cgi-bin/',
        '/server-info', '/server-status', '/phpmyadmin/setup/lib/configfile.class.php','/pma'
    ]

    data = {
        'id': 'value1',
        'search': 'value2',
        'username': 'namekarbari',
        'password': 'value2',
        'user': 'ramz',
        'pass': 'ramz',
        'q': """joste jooo' order by 1=1-- " order by 1=1""",
        's': """joste jooooooo'"--#,//\\"""
    }

    # Dictionary to store the first occurrence of each status code
    printed_status_codes = {}

    # Request task for multithreading
    def request_task(method, url_item):
        try:
            # Send requests based on the HTTP method
            if method == 'GET':
                curl_response = requests.get(target_https + url_item, verify=False, headers=headers)
            elif method == 'POST':
                curl_response = requests.post(target_https + url_item, json=data, verify=False, headers=headers)
            elif method == 'PUT':
                curl_response = requests.put(target_https + url_item, json=data, verify=False, headers=headers)

            # Extract status code
            curl_st = str(curl_response.status_code)

            # Check if this status code is already printed
            if curl_st not in printed_status_codes:
                printed_status_codes[curl_st] = url_item  # Save the URL for the status code
                # Check for relevant status codes to display
                if int(curl_st) in [200, 404, 401, 403] or 500 <= int(curl_st) <= 599:
                    color = {
                        '200': Fore.MAGENTA,
                        '404': Fore.GREEN,
                        '401': Fore.GREEN,
                        '403': Fore.GREEN,
                        '500': Fore.GREEN,
                        '501': Fore.GREEN,
                        '502': Fore.GREEN,
                        '503': Fore.GREEN,
                        '504': Fore.GREEN,
                    }.get(curl_st, Fore.YELLOW)  # Default to Yellow for 5xx errors
                    print(f"{color}[{method}] [{curl_st}] {Fore.WHITE}{target_https + url_item}")
                    # Write to file
                    f.write(f"Method: {method} Status Code: {curl_st} URL: {target_https + url_item}\n")

        except Exception as e:
            # Handle request errors
            print(Fore.RED + f"Error during {method} request for {url_item}: {str(e)}" + Fore.WHITE)

    # Multithreading with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=5) as executor:
        for method in ['GET', 'POST', 'PUT']:
            for url_item in url_list:
                executor.submit(request_task, method, url_item)

    # Close the file
    f.close()





##### LOGIN PAGE FINDER
def login(headers):
    target_path = os.path.join(target, "LOGIN.txt")
    f=  open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW + '\n[Login Page]' + Fore.WHITE)
    try:
        login_list = ['/wp-login.php', '/login', '/signin', '/access', '/authenticate', '/account/login', '/user/login',
                    '/member/login', '/dashboard/login', '/secure/login', '/portal/login', '/entry', '/gateway', '/entrypoint',
                    '/signin', '/credential', '/loginpage', '/logon', '/authentication', '/useraccess', '/weblogin', '/admin.asp',
                    '/admin.aspx', '/admin.jsp', '/admin.php', '/admin', '/admin/', '/admin-login', '/admin-login/', '/administrator',
                    '/administrator/', '/administrator.asp', '/administrator.aspx', '/administrator.php', '/auth', '/auth/',
                    '/authentication', '/authentication/', '/backend', '/backend/', '/cgi-bin/sqwebmail?noframes=1', '/cms', '/cms/',
                    '/cpanel', '/cpanel/', '/default.asp', '/dotAdmin', '/exchange/logon.asp', '/gs/admin/', '/login/', '/login',
                    '/logon.php', '/login.asp', '/login.aspx', '/login.html', '/login.php', '/login.jsp', '/logon.asp', '/logon.aspx',
                    '/logon.jsp', '/phpmyadmin', '/phpmyadmin/', '/phpmyadmin/index.php', '/signin', '/signin/', '/webeditor.php',
                    '/wp-admin', '/wp-admin/', '/wp-login.php','/pma','/webmail','/roundcube','/auth/admin-controlpanel/login',
                    '/admin-controlpanel/login','/auth/admin-controlpanel/','/admin-controlpanel/',':2222']

        def check_login_page(login_item):
            curl_response = requests.get(target_https + login_item, verify=False, headers=headers)
            if curl_response.status_code == 200:
                print(Fore.GREEN+'[FOUND]'+Fore.WHITE,target_https + login_item)
                #print('URL: ' + Fore.CYAN + target_https + login_item + Fore.WHITE + ' Status Code:' + Fore.GREEN + str(curl_response.status_code) + Fore.WHITE)
                f.write(target_https + login_item + '\n')
                global loginfound
                loginfound=True
            else:
                if all != None:
                    print(Fore.MAGENTA+'[MISS]'+Fore.WHITE,target_https + login_item)
                    #print('URL: ' + Fore.CYAN + target_https + login_item + Fore.WHITE + ' Status Code:' + Fore.RED + str(curl_response.status_code) + Fore.WHITE)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_login_page, login_item) for login_item in login_list]
            for future in concurrent.futures.as_completed(futures):
                future.result()
    except:
        if loginfound != True:
            print(Fore.RED + '\nNot Found' + Fore.WHITE)



##### Check Security Headers
def target_http_header(headers):
    target_path = os.path.join(target, "SEC-HEADERS.txt")
    f=  open(target_path, "w", encoding="utf-8")
    print(Fore.YELLOW+'\n'+'[HEADERS]'+Fore.WHITE)
    header_list=['Server','X-Powered-By','X-AspNet-Version','X-AspNetMvc-Version']
    security_headers=['X-Frame-Options','X-XSS-Protection','Referrer-Policy','Feature-Policy','Expect-CT','Cache-Control','Permissions-Policy','X-Content-Type-Options','Strict-Transport-Security','Content-Security-Policy']
    try:
        curl_response = requests.get(target_https,verify=False,headers=headers, timeout=30)
        for header_item in header_list:
            header_value = curl_response.headers.get(header_item.lower())
            if header_value is None or header_value == '':
                print(Fore.RED+'[FAILD]'+Fore.WHITE,header_item)
                #print(header_item+': '+Fore.RED+' Hidden'+Fore.WHITE)
                f.write(header_item+': '+' Hidden\n')
            else:
                print(Fore.GREEN+'[FOUND]'+Fore.WHITE,header_item+' : '+str(header_value))
                #print(header_item+': '+Fore.GREEN+str(header_value)+Fore.WHITE)
                f.write(header_item+': '+str(header_value)+'\n')
        print(Fore.YELLOW+'\n'+'[SECURITY HEADERS]'+Fore.WHITE)
        for security_header_item in security_headers:
            header_value = curl_response.headers.get(security_header_item.lower())
            if header_value is None or header_value == '':
                print(Fore.RED+'[FAILD]'+Fore.WHITE,security_header_item)
                #print(Fore.WHITE+security_header_item+': '+Fore.RED+'Missing'+Fore.WHITE)
                f.write(security_header_item+': '+'Missing\n')
            else:
                print(Fore.GREEN+'[FOUND]'+Fore.WHITE,header_item+' : '+str(header_value))
                #print(header_item+': '+Fore.GREEN+str(header_value)+Fore.WHITE)
                f.write(header_item+': '+str(header_value)+'\n')
    except:
        print(Fore.RED+'Connection Lost'+Fore.WHITE)
    f.close()



##### Nuclei Tool
def nuclei():
    print(Fore.YELLOW+'\n'+'NUCLEI'+Fore.WHITE)
    nuclei_cmd = ['-f', 'text', '-o', target + '/NUC.txt']
    command = ["nuclei", target_https] + nuclei_cmd
    nuc = subprocess.run(command, capture_output=True, text=True)
    print(nuc)
    print(nuc.stdout)
    if nuc == 0:
        print("Nuclei Command failed.")
    else:
        pass



### SSLSCAN Tool
def sslscan():
    print(Fore.YELLOW+'\nSSL SCANING'+Fore.WHITE)
    sslscan_cmd = ['--xml='+ target + '/SSL.xml',target]
    command = ["sslscan"] + sslscan_cmd
    ans = subprocess.run(command, capture_output=True, text=True)
    print(ans.stdout)
    if ans == 0:
        print("SSLSCAN Command failed.")
    else:
        pass



##### CMS Detection
def cms(headers):
    global cms_detect
    cms_detect=''
    print(Fore.YELLOW+'\n'+'[CMS]')
    wp_list=['wordpress','wp-content','wp-','wp-includes','wp-admin']
    joom_list=['/components/com_', 'index.php?option=com_', 'Joomla','joomla']
    drupal_list=['sites/default', 'drupal']
    magneto_list=['skin/frontend', 'Mage.Cookies.path'] 
    Squarespace_list = ['squarespace']
    wix_list = ['wix']
    Shopify_list = ['shopify']
    found = False
    curl_response = requests.get(target_https,verify=False,headers=headers)
    ### Wordpress
    print(Fore.CYAN+'[WORDPRESS]')
    for wp_item in wp_list:
        if wp_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+wp_item)
            found = True            
            cms_detect='wordpress'
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+wp_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',Fore.CYAN,target,'Using Wordpress'+Fore.WHITE)
        return
    

    ### Joomla
    print(Fore.CYAN+'[JOOMLA]')
    for joom_item in joom_list:
        if joom_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+joom_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+joom_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Joomla')
        return
    

    ### Drupal
    print(Fore.CYAN+'[DRUPAL]')
    for drupal_item in drupal_list:
        if drupal_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+drupal_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+drupal_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Drupal')
        return
    

    ### Magento
    print(Fore.CYAN+'[MAGNETO]')
    for magneto_item in magneto_list:
        if magneto_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+magneto_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+magneto_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Magento')
        return
    

    ### Squarespace
    print(Fore.CYAN+'[SQUARESPACE]')
    for Squarespace_item in Squarespace_list:
        if Squarespace_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+Squarespace_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+Squarespace_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Squarespace')
        return
    

    ### Wix
    print(Fore.CYAN+'[WIX]')
    for wix_item in wix_list:
        if wix_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+wix_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+wix_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Wix')
        return
    

    ### Shopify
    print(Fore.CYAN+'[SHOPIFY]')
    for Shopify_item in Shopify_list:
        if Shopify_item in str(curl_response.content):
            print(Fore.GREEN+'[FOUND]',Fore.WHITE+Shopify_item)
            found = True
        else:
            print(Fore.MAGENTA+'[MISS]',Fore.WHITE+Shopify_item)
    if found is True:
        print(Fore.GREEN+'[VERIFY]',target,'Using Shopify')
        return
    

     ### Custome CMS       
    if found is False:
        print(Fore.GREEN+'[FOUND]','Target Using Custome CMS')


##### Screenshot of the Target
def screenshot():
    # Set up the Chrome driver service
    service = Service(ChromeDriverManager().install())

    # Initialize the Chrome driver
    driver = webdriver.Chrome(service=service)

    # Open the website
    driver.get('https://'+target)

    # Give the page some time to load (you can adjust this as needed)
    time.sleep(3)

    # Take a screenshot and save it to the specified folder
    screenshot_path = '\\'+target+'\\screenshot.png'
    driver.save_screenshot(screenshot_path)

    # Close the browser
    driver.quit()

    print(f"Screenshot saved to {screenshot_path}")



##### Google Dork
def dork():
    print(Fore.YELLOW+'\n'+'[DORK]'+Fore.WHITE)
    target_path = os.path.join(target, "DORKS.txt")
    f=  open(target_path, "w", encoding="utf-8")
    f.write('Google Dorks \n')
    headers2={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/314.0 Safari/537.36',
        'Cookie':'''SOCS=CAESHAgCEhJnd3NfMjAyNTAxMjMtMF9SQzEaAmRlIAEaBgiA9tW8Bg; HSID=A61i5BuL-9Nmcx3bg; SSID=ALz6HBWGvyf03vIgT; APISID=wwMyJ6fvYSaX4I6s/Ar5YFvlBwfZ1BCktR; SAPISID=ouVLpcyKjRsNp_XE/AVDVJwI1GIx7JbGkE; __Secure-1PAPISID=ouVLpcyKjRsNp_XE/AVDVJwI1GIx7JbGkE; __Secure-3PAPISID=ouVLpcyKjRsNp_XE/AVDVJwI1GIx7JbGkE; SID=g.a000swjD_yjlrLgsMmi0fF6nRETTUcI12Bq49ogKJQPH1Zw19DYeYSV9RAoPc65eQXn2HiWWAgACgYKAUQSARcSFQHGX2MiyFFYQaKlW87-FaotTSYqTxoVAUF8yKq-y_Py0ybf6J5EA7BGWIRD0076; __Secure-1PSID=g.a000swjD_yjlrLgsMmi0fF6nRETTUcI12Bq49ogKJQPH1Zw19DYe01oRkbc4ldLQBObNBTCQwwACgYKAYsSARcSFQHGX2MimWorUC9_LwiIVEZyAbQYzxoVAUF8yKoaBT4xcdStDihxF7Vd_C6O0076; __Secure-3PSID=g.a000swjD_yjlrLgsMmi0fF6nRETTUcI12Bq49ogKJQPH1Zw19DYeZxYZtO8c849nGeBno30vdwACgYKAXESARcSFQHGX2Mi19IcpSlUZpZMaaVofZRoIRoVAUF8yKp0aiZ8QMxtreh_8emGL48W0076; SEARCH_SAMESITE=CgQIk50B; AEC=AVcja2cEwbE1FPkCDH_BXSQLIGzE7KWjGUOvmJJryEHuNv4zZn84pnzM8w; __Secure-ENID=25.SE=DqPjUH7DoWm5k1L3S7Dl-3mFBYk9CxHCM9-5kf_CJW98s0ghMT8KtCt_7g8VvWbr_BBs7DxUok8vQmsueSNxtS8pqVPYg09BaOoNJkJh-enjdsmA1AKSyBLgSqBumFKZRUGGGbjlta4l31pjMSMyQh7zJQlrKp7DjKcHN6DMCNvGmd21KZXTd8jzdBUdknlQyLYBMlH--PnDvkHrUkjuSLc5rsqt-085N0QuUXln3xtOIv5mwGSSzk19_Ihmx9HXXf00h3UkDPBzHbaT0FEZOYYoKsgawUJ0wURqMKNe34n1b8CzDzQ2P8bEI0NP-cD7jF01cpNaOh5W0fWcI9raov3szM854bLR9uRCvWtf5DM8H20Ocd_vIfZzD1Pf_Qo; NID=521=RIFaZ5QY4JrZLrqN3OHcWQRjcDpesNUovtwsWShDw7x77X8g6Zro5ZvgperprxV6VbImSFnJkKtBN0uLSyiV9qYQDMtozgir-syaxZPB7Q54TAmwstksdPI8vw8B0T5XZ_GTu32npVCcGzBPT-5X_17F1ymeIJlOAJBHag_7eM-4HM_hTZFheCrsZz23Lhjil0MuOzM9mjThqnfhBserrIungLIQq3NAwbG__gRsodRro8O483rZWILjoS89GJedDCxFtxejCLH78eW2rIpK3jAX-1WgABeIA6NyxAYsL8Km0TTVC1aZI0LNHkMVEj7-_XhL-ZTgJEqAfjIJ_pCvM9KYLCRwnTOAnVpChwfYrXXLW9AqvZSuz_fTztJ4WwC2DiHg3hIrNehxZxkcWPV_eSfHDIdjQdpMtS9hjTdSo2mAJ1OkUWSB3iIjnqDjhUFhxBBKTejSPXM1JJwY4OeW1dku; GOOGLE_ABUSE_EXEMPTION=ID=975c0da5dffe57ab:TM=1740222163:C=r:IP=81.90.146.58-:S=SsDcFLJI12GdJR9PlLhWKjs; __Secure-1PSIDTS=sidts-CjEBEJ3XVx38A_zj5tzWD8iev_v_nammePzymrNJI9aTgxRhykHXJpnnZL0f77WXZgRuEAA; __Secure-3PSIDTS=sidts-CjEBEJ3XVx38A_zj5tzWD8iev_v_nammePzymrNJI9aTgxRhykHXJpnnZL0f77WXZgRuEAA; DV=swJAuEW27TtWIBy4P1MyROtQEQnWUhmI-LVhLnx5NgMAAMDXZOvQycoVzwAAALDxvkO948-MTAAAAB7d8Xg8VY-nFAAAAA; SIDCC=AKEyXzUyghkBcRFU8_WKQMqN4blxwL1U87Bm5BD4lpViOLDnF7N4L8eYLAxEj9wIRq1wUMlCu8Y; __Secure-1PSIDCC=AKEyXzWupMlXLflxsoZshYFUPA-ycopeV55FYGiWc4DMJiu4EEpgUA6dGWvq4qyJKih_eyvz0vA; __Secure-3PSIDCC=AKEyXzVMsaw_eFyqN6I9jko72rDlstrdBczw44sj9X3zy_IXXxHow5Qk_fehAuOLdbC1rH88u8U'''}
    #dork_list=' filetype:pdf'
    dork_list=' filetype:pdf | filetype:xls | filetype:xlsx | filetype:doc | filetype:docx | filetype:log | filetype:bak | filetype:conf | filetype:rar | filetype:zip | filetype:pass | filetype:mdb | filetype:accdb | filetype:sql | filetype:txt | filetype:dbs | filetype:xml'
    dork_ext=['.pdf','.xls','.xslx','.log','.doc','.docx','.bak','.conf','.rar','.zip','.pass','.mdb','.sql','.accdb','.xml','.txt','.dbs','.db']
    #print('https://www.google.com/search?q=site:'+target+dork_list)
    #print(curl_response.content)

    ### Cookie Grab
    google_cookie = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/314.0 Safari/537.36',}
    curl_response = requests.get('https://www.google.com/search?q=site:'+target,headers=google_cookie)

    # Grab the Set-Cookie header from the response
    set_cookie = curl_response.headers.get('Set-Cookie')

    # Parse the cookie value
    if set_cookie:
        cookie_value = set_cookie.split(';')[0]
        cookie_value2 = set_cookie.split(';')[6]

        # Prepare the headers for the next request with the cookie
        headers3 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/314.0 Safari/537.36',
        'Cookie': cookie_value+'; '+cookie_value2+';'}
    print(headers3)

    for page in range(1, 4):
        curl_response = requests.get('https://www.google.com/search?q=site:'+target+'+'+dork_list+'&start='+str(page),headers=headers3)
        #print(curl_response.status_code)
        #print(curl_response.headers)
        #print()
        soup = BeautifulSoup(curl_response.text, 'html.parser')
        print(Fore.CYAN+'[PAGE '+str(page)+']'+Fore.WHITE)
        if curl_response.status_code == 429:
            print(Fore.RED+'[WARNING]'+Fore.WHITE+'Google To many Request...'+Fore.YELLOW+'  Try 1h later'+Fore.WHITE)
        else:
            if curl_response.status_code in range(300,404):
                print(Fore.RED+'[WARNING]'+Fore.WHITE+'Google Detect Our Bot')
            else:
                for a_tag in soup.find_all('a'):
                    if target in str(a_tag.get('href')):
                        if '.pdf' in str(a_tag.get('href')):
                            url  = a_tag.get('href')
                            if any(url.endswith(ext) for ext in dork_ext):
                                print(url)
                                #print(a_tag.get('href'))
                                f.write(url+'\n')
    f.close()



##### Becuse of Dependensies and Platform this part of code check the OS platform and deside to execute the test cases or NOT
def more_test_case(headers):
    plat=platform.system()
    #print(plat)
    if plat == "Linux":
        sslscan()
        #wafw00f(headers)
        ##nmap()
        #subfinder(headers)
        #ffuf()
        #wp_scan(headers)
        #nuclei()



def wp_bruteforce_task(username, bfheaders, url_list, proxies):
    try:
        # Dynamically generate the passwords list for each username
        passwords = [
            '123456', '123456789', '12345678', 'password', 'P@ssword', 'p@ssw0rd',
            'P@ssw0rd', 'qwerty', 'qwerty123', 'qwerty12345', 'qwerty1', '111111', '12345', 'secret', '123123',
            '000000', username + '123', username + '12345', username + '0912', username + username, username + '001'
        ]

        for password in passwords:
            payload = {
                "log": username,
                "pwd": password,
                "wp-submit": "%D9%88%D8%B1%D9%88%D8%AF",
                "redirect_to": target_https + "%2Fwp-admin%2F",
                "testcookie": "1"
            }

            # Send the POST request through the proxy
            for url in url_list:
                response = requests.post(url, data=payload, headers=bfheaders, verify=False, allow_redirects=False)#, proxies=proxies)

                if b'BitNinja' in response.content:  # Byte string comparison
                    print(Fore.RED + f"[{username}] BitNinja Stop us! Use ProxyIP Changer" + Fore.WHITE)
                    return
                else:
                    if "Location" in response.headers:
                        if '/wp-admin/' in response.headers["Location"]:
                            print(Fore.CYAN + "[URL]" + Fore.WHITE, url)
                            print(Fore.GREEN + "[SUCCESS]" + Fore.CYAN, "[USERNAME]" + Fore.WHITE, username, Fore.CYAN + "[PASSWORD]" + Fore.WHITE, password)
                            return  # Exit the function on success
                    else:
                        print(Fore.RED + "[Failed]" + Fore.CYAN, "[USERNAME]" + Fore.WHITE, username, Fore.CYAN + "[PASSWORD]" + Fore.WHITE, password)
    except Exception as e:
        print(Fore.RED + 'Error:' + Fore.WHITE, str(e))

def wp_bruteforce(username_list, headers):
    print(Fore.YELLOW + '\n' + '[WP BruteForce]' + Fore.WHITE)
    bfheaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0 Safari/537.36',
        'Cookie': 'wordpress_test_cookie=WP%20Cookie%20check; path=/; secure'
    }
    
    # Define the proxy
    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    }

    url_list = [target_https + "/wp-login.php"]

    # Use ThreadPoolExecutor for multithreading
    with ThreadPoolExecutor(max_workers=10) as executor:
        for username in username_list:
            executor.submit(wp_bruteforce_task, username, bfheaders, url_list)#, proxies)





def wordpress_case(headers,cms_detect):
    if cms_detect == 'wordpress':
        wp_version(headers)
        wp_register(headers)
        wp_install(headers)
        wp_plugin(headers)
        wp_user_enum(headers) # need to clean code and improvment with [list]
        wp_bruteforce(username_list,headers)

def info_ga(headers):
    if all != None:
        dork()
        ipinfo(headers)
        wayback(headers)

clear()
banner()
urllib3.disable_warnings()
target_mkdir()
target_check(headers)
target_http_header(headers)
cms(headers)
backup_file(headers)
login(headers)
wordpress_case(headers,cms_detect)
dir_browse(headers)
info_ga(headers)
error(headers)   #need to improve and use real url of the target
more_test_case(headers)


# ['release_log.html','readme.txt','changes.txt','readme.md','README.md','README.txt','Readme.txt','Readme.md','README']






##### For Next Versions
#webserver_discovery()
#screenshot()
#tech_discovery()
#http_smugling
#host_header_injection







#### Version 0.3 (Beta)
# add nuclei,sslscan,cms_discovery
# Improve Code of User Enumeration with 5 Method
# detect windows/linux platform and deside to test more pentest case

#### Version 0.2 (Beta)
# add login,register,install,ffuf,wp-plugin,
# add version,ipinfo,wayback,wafw00f,subfinder,wpscan

#### version 0.1 (Beta)
# check http& https
# user enum with 2 method
# directory browsing

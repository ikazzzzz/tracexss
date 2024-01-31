from colorama import Fore
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor
import requests
import re
import json
import subprocess
import os
import time 
import errno
import random
import argparse
import secrets ###rev
import string ###rev


class tracexss:
    def __init__(self, domain=None, filename=None, url=None, output=None):
        print(Fore.LIGHTBLUE_EX + """
        _____ __      _   ____ _____   _     _ _______ _______ 
          |   |_|_   /_\  |    |____    \___/  |______ |______  
          |   |   | /   \ |___ |____   _/   \_ ______| ______| 
                              
                      #Author: Qori, Anwar, BP
            """ + Fore.WHITE)
             
        self.threads = 1
        self.filename = filename
        self.output = output
        self.url = url
        self.domain = domain
        self.result = []
        self.urls = []
        
        try:
            if filename == None:
                if url == None and not domain == None:
                    self.crawl(domain)
                    filename = f"output/crawl/{domain}.txt"
                    if os.path.exists(filename):
                        urls = self.read(filename)
                    else:
                        filename = f"results/crawl/{domain}.txt"
                        urls = self.read(filename)
                elif not url == None and domain == None:
                    self.scanner(url)
                    if self.result:
                        self.write(output,self.result[0])
                    exit()
            else:
                urls = self.read(filename)
            print(Fore.GREEN + f"[+] CURRENT THREADS: {self.threads}")
            if urls:
                '''
                for url in urls:
                    vuln = self.scanner(url)
                '''
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                     executor.map(self.scanner,urls)
                for i in self.result:
                    self.write(output,i)
            print(Fore.WHITE + "[+] COMPLETED")
        except Exception as e:
            print(e)
        
    def read(self,filename):
        '''
        Read & sort GET  urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        urls = subprocess.check_output(f"cat {filename} | grep '=' | sort -u",shell=True).decode('utf-8')
        if not urls:
            print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
        return urls.split()

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        subprocess.call(f"echo '{value}' >> {output}",shell=True)

    def replace(self,url,param_name,value):
        return re.sub(f"{param_name}=([^&]+)",f"{param_name}={value}",url)
        
    def bubble_sort(self, arr):
        '''
        For sorting the payloads
        '''
        a = 0
        keys = []
        for i in arr:
            for j in i:
                keys.append(j)
        while a < len(keys) - 1:
            b = 0
            while b < len(keys) - 1:
                d1 = arr[b]
                d2 = arr[b + 1]
                if len(d1[keys[b]]) < len(d2[keys[b+1]]):
                    d = d1
                    arr[b] = arr[b+1]
                    arr[b+1] = d
                    z = keys[b+1]
                    keys[b+1] = keys[b]
                    keys[b] = z
                b += 1
            a += 1
        return arr
    
    def crawl(self, domain):
        self.domain = domain
        '''
        Use this method to crawl the links using katana (return type: None)
        '''
        print(Fore.BLUE + "[+] CRAWLING DOMAIN")
        crawling = Crawler(domain)
        return None

    def parameters(self, url):
        '''
        This function will return every parameter in the url as dictionary.
        '''
        param_names = []
        params = urlparse(url).query
        print(params)
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            param_names.append(params[0])
        else:
            for param in params:
                param = param.split("=")
                param_names.append(param[0])
        return param_names

    def parser(self, url, param_name, value):
        '''
        This function will replace the parameter's value with the given value and returns a dictionary
        '''
        final_parameters = {}
        parsed_data = urlparse(url)
        params = parsed_data.query
        protocol = parsed_data.scheme
        hostname = parsed_data.hostname
        path = parsed_data.path
        params = params.split("&")
        if len(params) == 1:
            params = params[0].split("=")
            final_parameters[params[0]] = params[1]
        else:
            for param in params:
                param = param.split("=")
                final_parameters[param[0]] = param[1]
        final_parameters[param_name] = value
        return final_parameters

    def validator(self, danger_char, param_name, url):
        dic = {param_name: []}
        char = string.ascii_letters + string.digits ###rev
        randomstr = ''.join(secrets.choice(char) for _ in range (12)) ###rev
        try:
            for data in danger_char:
                final_parameters = self.parser(url,param_name,data + randomstr)
                new_url = urlparse(url).scheme + "://" + urlparse(url).hostname + "/" + urlparse(url).path
                response = requests.get(new_url,params=final_parameters,verify=False).text
                print(response)
                if data + randomstr in response:
                    print(Fore.GREEN + f"[+] {data} is reflecting in the response")
                    dic[param_name].append(data)
        except Exception as e:
            print(e)
        return dic

    def fuzzer(self, url):
        data = []
        dangerous_characters = [  # You can add dangerous characters here
            ">",
            "'",
            '"',
            "<",
            "/",
            ";"
        ]
        parameters = self.parameters(url)
        print(parameters)
        if '' in parameters and len(parameters) == 1:
            print(f"[+] NO GET PARAMETER IDENTIFIED...EXITING")
            exit()
        print(f"[+] {len(parameters)} parameters identified")
        for parameter in parameters:
            print(Fore.WHITE + f"[+] Testing parameter name: {parameter}")
            out = self.validator(dangerous_characters,parameter,url)
            data.append(out)
        print("[+] FUZZING HAS BEEN COMPLETED")
        return self.bubble_sort(data)

    def filter_payload(self,fuzz_char):
        payload_list = []
        size = int(len(fuzz_char) / 2)
        print(Fore.WHITE + f"[+] LOADING PAYLOAD FILE payloads.json")
        dbs = open("payloads.json")
        dbs = json.load(dbs)
        new_dbs = []
        for i in range(0,len(dbs)):
            if not dbs[i]['waf']:
                new_dbs.append(dbs[i])
        dbs = new_dbs
        for char in fuzz_char:
            for payload in dbs:
                attributes = payload['Attribute']
                if char in attributes:
                    payload['count'] += 1
        def fun(e):
            return e['count']
        dbs.sort(key=fun,reverse=True)
        for payload in dbs:
            if payload['count'] == len(fuzz_char) and len(payload['Attribute']) == payload['count'] :
                print(Fore.GREEN + f"[+] FOUND SOME PERFECT PAYLOADS FOR THE TARGET")
                payload_list.insert(0,payload['Payload'])
                continue
            if payload['count'] > size:
                payload_list.append(payload['Payload'])
                continue
        return payload_list

    def scanner(self,url):
        print(Fore.WHITE + f"[+] TESTING {url}")
        out = self.fuzzer(url)
        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key])
            for payload in payload_list:
                try:
                    data = self.parser(url,key,payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme +  "://" + parsed_data.netloc + parsed_data.path
                    response = requests.get(new_url, params=data,verify=False).text
                    if payload in response:
                        print(Fore.RED + f"[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLOAD USED: {payload}")
                        print(self.replace(url,key,payload))
                        self.result.append(self.replace(url,key,payload))
                        return True
                except Exception as e:
                    print(e)
        print(Fore.LIGHTWHITE_EX + f"[+] TARGET SEEMS TO BE NOT VULNERABLE")
        return None

class Crawler:
    def __init__(self, domain):
        self.domain=domain
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        retry = True
        retries = 0
        while retry == True and retries <= 3:
                 response, retry = self.connector(url)
                 retry = retry
                 retries += 1
        if response == False:
             return
        response = unquote(response)
        final_uris = self.param_extract(response)
        self.save_func(final_uris, domain)

        print(f"\n\u001b[32m[+] Total number of retries:  {retries-1}\u001b[31m")
        print(f"\u001b[32m[+] Total unique urls found : {len(final_uris)}\u001b[31m") 
        print(f"\u001b[32m[+] Crawling output is saved here   :\u001b[31m \u001b[36moutput/crawl/{domain}.txt\u001b[31m")
    
    def save_func(self, final_urls, domain):
        filename = f"output/crawl/{domain}.txt"
    
        if os.path.exists(filename):
            os.remove(filename)

        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise
    
        for i in final_urls:
            with open(filename, "a" , encoding="utf-8") as f:
                f.write(i+"\n")

    def param_extract(self, response):
        placeholder = "FUZZ"
        ''' 
        Function to extract URLs with parameters (ignoring the black list extention)
        regexp : r'.*?:\/\/.*\?.*\=[^$]'
    
        '''
        parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , response)))
        final_uris = []
        
        for i in parsed:
            delim = i.find('=')
            final_uris.append((i[:delim+1] + placeholder))
    
        return list(set(final_uris))
        
    def connector(self, url):
        result = False
        user_agent_list = [
        #Chrome
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
        #Firefox
        'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
        'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
        ]
        user_agent = random.choice(user_agent_list)
        headers = {'User-Agent': user_agent}
 
        try:
            # TODO control request headers in here
                response = requests.get(url,headers=headers ,timeout=30)
                result = response.text
                retry = False
                response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
                retry = False
                print("\u001b[31;1mCan not connect to server. Check your internet connection.\u001b[0m")
        except requests.exceptions.Timeout as e:
                retry = True
                print("\u001b[31;1mOOPS!! Timeout Error. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
        except requests.exceptions.HTTPError as err:
                retry = True
                print(f"\u001b[31;1m {err}. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
        except requests.exceptions.RequestException as e:
                retry = True
                print("\u001b[31;1m {e} Can not get target information\u001b[0m")
        except KeyboardInterrupt as k:
                retry = False
                print("\u001b[31;1mInterrupted by user\u001b[0m")
                raise SystemExit(k)
        finally:
                return result, retry
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument('-m', dest='module', help='Select the module to be used. Eg: 1, 2, 3, etc', type=int, required=True)
    parser.add_argument('-d', dest='domain', help='Scrapping url from domain name of the target [ex: hackerone.com]')
    parser.add_argument('-f', dest='filename', help='Specify Filename to scan. Eg: urls.txt etc')
    parser.add_argument('-u', dest='url', help='Scan a single URL. Eg: http://example.com/?id=2')
    parser.add_argument('-o', dest='output', help='Filename to store output. Eg: result.txt')

    args = parser.parse_args()

    #module= args.module
    domain = args.domain
    filename = args.filename
    url = args.url
    output = args.output

    module = tracexss(domain, filename, url, output)
    #python3 tracexss.py -d testphp.vulnweb.com 
    #python3 tracexss.py -f urls.txt
    #python3 tracexss.py -u http://testphp.vulnweb.com/pp=FUZZ
    #python3 tracexss.py -d testphp.vulnweb.com -o hasil.txt


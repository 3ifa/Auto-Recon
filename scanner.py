import json
import dns.resolver
import nmap
import requests
import pydig

# Nameservers Function 
def ns_enum(domain):

    """
    Query to get NS of the domain
    """
    data = ""

    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
        if data:
            s=""
            for ns in data:
                s+=(str(ns)+"\n")
            return s+"\n"
    except:
        return "Cannot find any name server\n"

    
       
        #############################################
# IPs discover Function
def ip_enum(domain):
    """
    Query to get ips
    """
    data = ""

    try:
        data = dns.resolver.resolve(f"{domain}", 'A')
        if data:
            s=""
            for ip in data:
                s+=(ip.to_text()+"\n")
            return s+"\n"
    except:
        return "no known IPs related\n "
        #################################
        
# Extra DNS info Function
def txt_enum(domain):

    """
    Query to get extra info about the dns
    """
    data = ""

    try:
        data = dns.resolver.resolve(domain, 'TXT')
        if data:
            s=""
            for info in data:
                s+=(info.to_text()+"\n")
            return s+"\n"
    except:
        return "No Txt information found\n"
        #######################
# Function to discover the IPv6 of the target
def ipv6_enum(domain):
    """
    Query to get ipv6
    """
    try:
        data = pydig.query(domain, 'AAAA')
        if data:
            s=""
            for info in data:
                s+=( info+"\n" )
        return s+"\n"
    except:
        return "No ipv6 related \n"
    
        #####################
# Mail servers Function
def mail_enum(domain):
    
    """
    Query to get mail servers
    """
    data = ""

    try:
        data = dns.resolver.resolve(f"{domain}", 'MX')
        if data:
            s=""
            for server in data:
                s+=(str(server).split(" ")[1]+"\n")
        return s+"\n"
    except:
        return "No mail server detected \n"

        ################
#Function to fuzz for a WAF
def checkwaf(url):
    """
    Query to check for WAF
    """
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    try:
        r = requests.get(f'http://{url}', headers=headers)
        if r.headers.get("server") in ["cloudflare","AWS Security Group","Incapsula","Sucuri/Cloudproxy","Imperva"]:
            return " The Server is Behind a Web Application Firewall"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    return " No WAF detected."
"""    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            return("[!] Error with statu code:", sc.status_code+"\n")
    except:
        return("[!] Error with the first request.\n")
        exit()
    r = requests.get(url)
    try:
        if r.headers["server"] == "cloudflare":
            return("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server.\n")
    except:
        pass

    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    waffd = requests.get(fuzz)
    if waffd.status_code == 406 or waffd.status_code == 501:
        return("[\033[1;31m!\033[0;0m] WAF Detected.\n")
    if waffd.status_code == 999:
        return("[\033[1;31m!\033[0;0m] WAF Detected.\n")
    if waffd.status_code == 419:
        return("[\033[1;31m!\033[0;0m] WAF Detected.\n")
    if waffd.status_code == 403:
        return("[\033[1;31m!\033[0;0m] WAF Detected.\n")
    else:
        return("[*] No WAF Detected.\n")"""
        ########################
# Function to enumerate github and cloud
def cloudgitEnum(domain):

    """
    Check if an github account or a repository the same name exists 
    """
    counter = 0
    s=''
    r = requests.get("https://" + domain + "/.git/")
    if r.status_code == 200 or r.status_code == 403 or r.status_code == 500:
        counter = 1
        s+=("Git repository found: https://" + domain + "/.git/ - \n")

    r = requests.get("https://" + domain + "/.dev/")
    if r.status_code == 200 or r.status_code == 403 or r.status_code == 500:
        counter = 1
        s+=("Possible dev directory found: https://" + domain + "/.dev/ - \n")

    r = requests.get("https://" + domain + "/dev/")
    if r.status_code == 200 or r.status_code == 403 or r.status_code == 500:
        counter = 1
        s+=("Possible dev directory found: https://" + domain + "/dev/ - \n")

    r = requests.get("https://github.com/" + domain.split(".")[0])
    if r.status_code == 200:
        counter = 1
        s+=("Github account found: https://github.com/" + domain.split(".")[0] + " - \n")

    r = requests.get("https://gitlab.com/" + domain.split(".")[0])
    if r.status_code == 200:
        counter = 1
        s+=("Gitlab account found: https://gitlab.com/" + domain.split(".")[0] + " - \n")

    if counter == 0:
        return("None\n")
    else:
        return s+"\n"

    ##################

# Query the domain
def whoisLookup(domain):
    import re
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.sendall((domain + "\r\n").encode())
    response = ""
    while True:
        data = s.recv(4096).decode()
        response += data
        if not data:
            break
    s.close()
    data = {}
    for line in response.split("\n"):
        match = re.search(r"(inetnum|organisation|status|whois|changed|source):\s+(.*)", line)
        if match:
            key, value = match.groups()
            data[key] = value
    inetnum = data.get('inetnum', '')
    org = data.get('organisation', '')
    status = data.get('status', '')
    whois = data.get('whois', '')
    changed = data.get('changed', '')
    source = data.get('source', '')
    output = f'inetnum:      {inetnum}\norganisation: {org}\nstatus:       {status}\nwhois:        {whois}\nchanged:      {changed}\nsource:       {source}'
    return output
"""    import whois
    try:
               
        return whois.query(domain)
    except:
        return("\nUnable to whois " + domain )
"""
#######
# Perform basic enumeration
def basicEnum(domain):

    """
    Use python-Wappalyzer
    """
    

    try:
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + domain)
        info = wappalyzer.analyze_with_versions(webpage)
        #return type(info)+"\n"
        return( json.dumps(info, sort_keys=True, indent=4))
    except:
        return("\n")

#################


def scannmap(target,args):  
    import nmap
    nm= nmap.PortScanner()
    nm.scan(hosts=target,arguments=args)
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    a=""
    for host in nm.all_hosts():
        a+=('Host : %s (%s)' % (host, nm[host].hostname())+'\n')
        a+=('State : %s' % nm[host].state()+'\n')
        for proto in nm[host].all_protocols():
            a+=('Protocol : %s' % proto +'\n')
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                a += 'port : %s\tstate : %s' % (port, nm[host][proto][port]['state']+'\n')       
       
    
    return a
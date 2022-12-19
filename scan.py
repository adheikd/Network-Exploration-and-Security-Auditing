import json
import time
import sys
import subprocess
import http.client
import requests
import socket

scan_time = "scan_time"
ipv4_address = "ipv4_addresses"
ipv6_address = "ipv6_addresses"
http_server = "http_server"
insecure_http = "insecure_http"
redirect_to_https = "redirect_to_https"
tls_versions = "tls_versions"
root_ca = "root_ca"
hsts = "hsts"
rtt_range = 'rtt_range'
ports = [80,22,443]

def getSocket():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def readInputFile(inputFileAddr, outputJson):
    inputFile = open(inputFileAddr)
    for val in inputFile:
        outputJson[val.strip()] = {}
        
def getResponse(val):
    return val.getresponse()

def setOutputFile(outputFileAddr, outputJson):
    with open(outputFileAddr, "w") as f:
        json.dump(outputJson, f, sort_keys=True, indent=4)

def stripSpace(val):
    return val.strip()
    
def getSubprocess(webLink, time, stderr, type):
    return subprocess.check_output(["nslookup", type, webLink, "8.8.8.8"], timeout=time, stderr=stderr).decode("utf-8")

def createHTTPCon(webLink):
    return http.client.HTTPConnection(webLink, timeout=2)

def getServer(webLink):
    try:
        obj = createHTTPCon(webLink)
        obj.request(webLink, "get")
        response = getResponse(obj)
    except:
        return None
    else:
        if(response.getheader("Server")):
            server = response.getheader("Server")
        else:
            server = response.getheader("server")
        obj.close()
        return(server)

def checkInsecureConnection(webLink, ports):
    sock = getSocket()
    for idx, port in enumerate(ports):
        try:
            sock.settimeout(2)
            tup = (webLink, port)
            sock.connect((webLink, port))
        except socket.timeout:
            return False
        else:
            sock.shutdown(2)
            return True
            
def checkRedirectToHttps(webLink):
    redirectToHttps = False
    hsts = False
    try:
        obj = requests.get("http://" + webLink, timeout=4)
    except:
        redirectToHttps = False
        hsts=False
    else:
        status_code = obj.status_code
        if (status_code == 200):
            redirectToHttps = False
        if (status_code in [301, 302]):
            i=0
            while(i<10):
                obj = requests.get(obj.url, timeout=4)
                if(obj.status_code == 200):
                    redirectToHttps = True
                    break
                i = i + 1
        try:
            obj.headers['strict-transport-security']
            obj.headers['Strict-Transport-Security']
        except:
            hsts = False
        else:
            hsts = True
    return redirectToHttps, hsts

def fetchIPAddress(webLink,version):
    addresses = []
    if(version == 'ptr'):
        try:
            result = getSubprocess(webLink, 2, subprocess.STDOUT, "-type=ptr")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            print("Error", error)
        else:
            for line in result.split("\n"):
                if(line.find("name = ")!=-1):
                    return(line[line.find("name = ") + len("name = "):])

    if(version == 4):
        try:
            result = getSubprocess(webLink, 2, subprocess.STDOUT, "-type=A")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            print("Error", error)
        else:
            for line in result.split("\n"):
                if(line.find("Address:") != -1):
                    if(line.split(":")[1].find("8.8.8.8") == -1):
                        addresses.append(stripSpace(line.split(":")[1]))
            return addresses

    if(version == 6):
        try:
            result = getSubprocess(webLink, 2, subprocess.STDOUT, "-type=AAAA")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            print("Error", error)
        else:
            for line in result.split("\n"):
                if(line.find("Address:") != -1):
                    if(line.split(":")[1].find("8.8.8.8") == -1):
                        addresses.append(line.split("Address:")[1])
            return addresses

def getSupportedTlsVersions(webLink):
    versions = []
    root_ca = ""
    try:
        result = subprocess.check_output(["nmap","--script","ssl-enum-ciphers","-p","443",webLink], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as error:
        print("Error", error)
        return versions, root_ca
    else:
        for line in result.split("\n"):
            if(line.find("|   T")!=-1):
                versions.append(stripSpace(line.strip("| :")))
            elif line.find("|   S")!=-1:
                versions.append(stripSpace(line.strip("| :")))        
        try:
            echo = subprocess.Popen(["echo"],shell=True,stdout=subprocess.PIPE)
            output = subprocess.check_output(["openssl","s_client","-connect",webLink+":443"],stdin=echo.stdout,timeout=2).decode('utf-8')
            echo.wait()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            print("Error", error)
        else:
            lines = output.split("---")
            for line in lines[1].split("\n"):
                if(line.find("   i") != -1):
                    root_ca = line[line.find("O = "):line.find(", OU = ")].split("=")[1].strip()
            return versions, root_ca
        return versions, ""

def fetchRDNSName(outputJson):
    for webLink in outputJson:
        outputJson[webLink]["rdns_names"] = []
        for idx, ipv4Addr in enumerate(outputJson[webLink][ipv4_address]):
            if fetchIPAddress(ipv4Addr,"ptr") != None :
                outputJson[webLink]["rdns_names"].append(fetchIPAddress(ipv4Addr, "ptr"))

def crawl(outputJson):
    for idx, webLink in enumerate(outputJson):
        print(idx)
        print(webLink)
        print('Fetching details')
        print("epoch time")
        outputJson[webLink][scan_time] = time.time()
        print("tls")
        outputJson[webLink][tls_versions], outputJson[webLink][root_ca] = getSupportedTlsVersions(webLink)
        print("ip6 addr")
        try:
            outputJson[webLink][ipv6_address] = fetchIPAddress(webLink, 6)
        except Exception:
            outputJson[webLink][ipv6_address] = []
        print("http redirect")
        outputJson[webLink][redirect_to_https], outputJson[webLink][hsts] = checkRedirectToHttps(webLink)
        print("server")
        outputJson[webLink][http_server] = getServer(webLink)
        print("insecure connection")
        outputJson[webLink][insecure_http] = checkInsecureConnection(webLink, [ports[0]])
        print("ip4 addr")
        try:
            outputJson[webLink][ipv4_address] = fetchIPAddress(webLink, 4)
        except Exception:
            outputJson[webLink][ipv4_address] = []
    print("rdns vals")
    fetchRDNSName(outputJson)
    print("rtt vals")

    for idx, webLink in enumerate(outputJson):
        print(webLink)
        outputJson[webLink][rtt_range] = []
        mini = float("inf")
        maxi = 0
        for idx, ipv4_addresses in enumerate(outputJson[webLink][ipv4_address]):
            start_timer = time.time()
            checkInsecureConnection(ipv4_addresses, ports)
            mini = min(mini, time.time() - start_timer)
            maxi = max(maxi, time.time() - start_timer)
        mini = int(mini*1000)
        maxi = int(maxi*1000)
        outputJson[webLink][rtt_range] = [mini, maxi]


def main(inputFileAddr,outputFileAddr):
    outputJson = {}
    readInputFile(inputFileAddr, outputJson)
    crawl(outputJson)
    setOutputFile(outputFileAddr, outputJson)
    return outputJson

if __name__ == '__main__':
    inputFileAddr = sys.argv[1]
    outputFileAddr = sys.argv[2]
    main(inputFileAddr, outputFileAddr)
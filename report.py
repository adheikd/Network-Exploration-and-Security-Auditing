import sys
from prettytable import PrettyTable as pt
import json

rttHeaderNames = ["Domain", "RTT"]
rootCaHeaderNames = ["CA Certificate","Events"]
httpServerHeaders = ["HTTP Server","Events"]
tablePercentageHeaders = ["Part 2 Section","Section Name","Percentage of Events"]

def addTableRw(val, Tablereport):
    Tablereport.add_row(val)

def finalizeReport(jsonObj,reportFileAddr):
    Tablereport = pt()
    Tablereport.title = "Report - Analysis"
    headerNames = list(jsonObj[list(jsonObj.keys())[0]].keys())
    headerNames.insert(0,"Domain")
    Tablereport.field_names = headerNames
    empList = []
    for idx, webLink in enumerate(jsonObj):
        empList.append(webLink)
        for idx, fields in enumerate(jsonObj[webLink]):
            empList.append(jsonObj[webLink][fields])
        addTableRw(empList, Tablereport)
        empList = []
    
    Tablertt = pt()
    Tablertt.title = "Table - RTT"
    Tablertt.field_names = rttHeaderNames
    empList = []
    for idx, webLink in enumerate(jsonObj):
        empList.append(webLink)
        empList.append(min(jsonObj[webLink]["rtt_range"]))
        addTableRw(empList, Tablertt)
        empList = []
    
    Tablepercentage = pt()
    Tablepercentage.title = "Events percentages for sections from Part 2"
    Tablepercentage.field_names = tablePercentageHeaders
    tlsList = {}
    counter = 0
    for idx, webLink in enumerate(jsonObj):
        for tls_version in jsonObj[webLink]['tls_versions']:
            tlsList[tls_version] = 0
        for idx, tls_version in enumerate(jsonObj[webLink]['tls_versions']):
            if(tls_version in tlsList):
                tlsList[tls_version] += 1

    for idx, tls_version in enumerate(tlsList):
        addTableRw(["TLS - Versions",tls_version,(tlsList[tls_version]/len(jsonObj))*100], Tablepercentage)

    for idx, webLink in enumerate(jsonObj):
        counter = counter + 1 if(jsonObj[webLink]['insecure_http']) else counter

    addTableRw(["Plain - HTTP","insecure_http",(counter/len(jsonObj))*100], Tablepercentage)

    Tablertt.sortby = "RTT"

    Tablehttp = pt()
    Tablehttp.title = "Table - HTTP Server Analysis"
    Tablehttp.field_names = httpServerHeaders
    overallList = {}
    for idx, webLink in enumerate(jsonObj):
        overallList[jsonObj[webLink]['http_server']] = 0
    for idx, webLink in enumerate(jsonObj):
        if(jsonObj[webLink]['http_server'] in overallList):
            overallList[jsonObj[webLink]['http_server']] += 1
    for idx, cert in enumerate(overallList):
        addTableRw([cert,overallList[cert]], Tablehttp)
    
    Tablehttp.sortby = "Events"
    Tablehttp.reversesort = True

    Tablerootc = pt()
    Tablerootc.title = "Table - Root CA" 
    Tablerootc.field_names = rootCaHeaderNames
    overallList = {}
    for idx, webLink in enumerate(jsonObj):
        overallList[jsonObj[webLink]['root_ca']] = 0
    for idx, webLink in enumerate(jsonObj):
        if(jsonObj[webLink]['root_ca'] in overallList):
            overallList[jsonObj[webLink]['root_ca']] += 1
    for idx, cert in enumerate(overallList):
        addTableRw([cert,overallList[cert]], Tablerootc)
    
    Tablerootc.sortby = "Events"
    Tablerootc.reversesort = True

    counter = 0

    for idx, webLink in enumerate(jsonObj):
        counter = counter + 1 if jsonObj[webLink]['redirect_to_https'] else counter

    addTableRw(["Redirecting to - HTTPS", "redirect_to_https", (counter/len(jsonObj))*100], Tablepercentage)
    counter = 0
    for idx, webLink in enumerate(jsonObj):
        if(jsonObj[webLink]['hsts']):
            counter = counter + 1
    addTableRw(["HOSTS","hsts",(counter/len(jsonObj))*100], Tablepercentage)
    counter = 0
    for idx, webLink in enumerate(jsonObj):
        if(len(jsonObj[webLink]['ipv6_addresses']) > 0):
            counter = counter + 1
    addTableRw(["IPV6 Address", "ipv6_addresses",(counter/len(jsonObj))*100], Tablepercentage)
    
    Tablepercentage.sortby = "Percentage of Events"
    Tablepercentage.reversesort = True

    with open(reportFileAddr,"w") as f:
        f.write(str(Tablereport))
        f.write(str(Tablerootc))
        f.write(str(Tablehttp))
        f.write(str(Tablepercentage))
        f.write(str(Tablertt))
    f.close()

def main(inputFileAddr,reportFileAddr):
    # jsonObj = scanner.main(inputFileAddr, "./output_file.json")
    f = open(inputFileAddr)
    # returns JSON object as 
    # a dictionary
    data = json.load(f)
    finalizeReport(data, reportFileAddr)

if __name__ == "__main__":
    inputFileAddr = sys.argv[1]
    reportFileAddr = sys.argv[2]
    main(inputFileAddr,reportFileAddr)
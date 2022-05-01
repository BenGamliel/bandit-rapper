
#https://github.com/BenGamliel/enso.security-home-Assignment-
import os
import json
import sys
import linecache
import hashlib

def hash(toHash):
	hash_object = hashlib.sha256()
	hash_object.update(toHash.encode('utf8'))
	hex_dig = hash_object.hexdigest()
	return hex_dig

def issueAttribute(i):
	issueAttributes=""
	filename = i["filename"]
	issueAttributes += filename
	testId = i["test_id"]
	issueAttributes += testId
	rawCode = i["code"]
	issueAttributes += rawCode
	lineRange = i["line_range"]
	for lineNumber in lineRange:
		codeExtract = linecache.getline(filename,lineNumber).rstrip().lstrip()
		issueAttributes += codeExtract
	return issueAttributes

def calculateIssueHash(i):
	return hash(issueAttribute(i))

def scanResult(issueFingerprint, i, issueSeverity):
	REDC = '\033[31m'
	YELC = '\033[33m'
	BLUC = '\033[36m'
	ENDC = '\033[0m'
	if(issueSeverity=="HIGH"):
		COLOR = REDC
	elif(issueSeverity=="MEDIUM"):
		COLOR = YELC
	else:
		COLOR = BLUC
	output = "--------------------------------------------------\n"
	output += COLOR + "Issue Fingerprint: " + issueFingerprint + "\n"
	output += COLOR + "Issue Severity: %s \t Confidence Level: %s" % (i["issue_severity"], i["issue_confidence"]) + "\n"
	output += COLOR + "Location: %s"  % i["filename"] + "\n"
	output += COLOR + "Issue: %s" % i["issue_text"] + "\n\n"
	output += "Code: \n%s" % i["code"]
	output += ENDC
	return output

def main(argv):
    print('running os.system')
    path = sys.argv[1]
    stream = os.popen('bandit -r -f json ' + path)
    data = json.load(stream)
    findings = []
    for i in data['results']:
        findings.append(i)
    issue_weight = dict(HIGH=0, MEDIUM=1, LOW=2)
    findings.sort(key=lambda x: issue_weight[x["issue_confidence"]])
    findings.sort(key=lambda x: issue_weight[x["issue_severity"]])
    for i in findings:
        issueFingerprint = calculateIssueHash(i)
        print(scanResult(issueFingerprint, i, i["issue_severity"]))
if __name__ == "__main__":
    main(sys.argv)



#https://github.com/pyupio/safety-db
#from bs4 import BeautifulSoup
#def getCVEIds(soup, cveArray):
#   table = soup.find('table', attrs={'class', 'searchresults'})
#    for a in table.find_all('a', href=True):
#        m = re.search("CVE-\d{4}-\d{4,7}", a['href'])
#        if m:
#            cveArray.append(m.group(0))


#def getCVEPages(soup):
#    cveIDPages = []
#    items = soup.find_all('div', class_="paging")
#    for item in items:
#        links = item.find_all('a')
#        for link in links:
#            cveIDPages.append("http://www.cvedetails.com/" + str(link['href']))
#    return cveIDPages




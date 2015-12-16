## this script finds and parses a set of vulnerability reports (all in XML) and 
## provides a list of the vulnerabilities with the key required info.

import os
import csv
import xml.etree.ElementTree as ET

def getVulnData(SRname, vulnfilepath): 
    root_tag='{https://www.veracode.com/schema/reports/export/1.0}dynamicflaws'
    tree = ET.ElementTree(file=vulnfilepath)
    root = tree.getroot()
    for dynamicflaws in root.iter(tag=root_tag):
        for child in dynamicflaws:
            fields = [ child.get('severity'), child.get('url'), child.get('type'), child.get('description')]
            ## print '\t'.join([SRname] + fields)
            outputcsv.writerow([SRname] + fields)

#this is the root directory all the xml files are stored underneath
rootdir = 'C:\Vulnerability results\syn_vulnerabilities'

outputfilename = 'results.csv'

fieldnames = ['SR','severity','url','type','description']

# open csv file for output
outputfile = open(outputfilename,'w+')
outputcsv = csv.writer(outputfile, lineterminator='\n')

# add the fieldnames to the csv
## print '\t'.join(fieldnames)
outputcsv.writerow(fieldnames)


# change to the chosen directory
os.chdir('C:\Vulnerability results')

# walk through directories
for subdir, dirs, files in os.walk(rootdir):
     for file in files:
        fullpath = os.path.join(subdir, file)
        subdirname = os.path.split(subdir)[1]
        if file.endswith('txt'):
            ## a few of the files are text files which we cant parse with elementTree
            ## print subdirname + " is text"
            outputcsv.writerow([subdirname + ' is text'])
        else:
            ## call function scan xml file for data and output
            getVulnData(subdirname, fullpath)

outputfile.close()

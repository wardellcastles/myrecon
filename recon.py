################################################################
##  This script performs initial reconnaissance of a TLD     ##
##                                                            ##
##  Usage:                                                    ##
##    Input: Top Level Domain to be analyzed. i.e. foobar.com ##
##           Directory for output files                       ##
##           Which tools to run                               ##
##                                                            ##
##   Copyright(c) 2020, 2021 Wardell Castles                  ##
##                http://red7en.com                           ##
################################################################

## This function gets the IP address from a dig output
def getIP(aLine):
   lineLength = len(aLine)
   ipAddress = ""
   end = lineLength
   beg = end - 1  
   while True: 
      char = aLine[beg:end]
      if char in ('\t', " "):
         return ipAddress
      ipAddress = char + ipAddress 
      end = end - 1
      beg = end - 1

from genericpath import exists
import subprocess
import os
import sys

#Welcome Banner
print(" ")
print(" ")
print("Welcome to Red7en Reconnaissance Toolset")
print("*********************************")
print(" ")

###### HOUSEKEEPING #################################
## All text files will be placed in a directory on the Desktop

print(" ")
domain = input("Domain to be analyzed - ")

rootDirIn = input("Directory for files - ")
rootDir = "/home/red7en/Desktop/Recon/" + rootDirIn + "/"
pathSubDomains = rootDir + "amassSubDomains.txt"
prePendsubDomains = rootDir + "prePendSubDomains.txt"
pathmasscan = rootDir + "masscan.txt"

print (" ")
print ("Steps to execute")
print("1 - Amass")
print("2 - Dig ")
print("3 - Masscan")
print("4 - EyeWitness")
print("8 - STOP")
print("9 - All")

while (True):
   print(" ")
   steps = input()
   if (steps == "8"):
      print("Execution Halted")
      print (" ")
      sys.exit()
   if (steps == "1" or steps == "2" or steps == "3" or steps == "4" or steps == "9"):
      break

#Make directories if they don't exist
if not (os.path.exists("/home/red7en/Desktop/Recon/" + rootDirIn)):
   os.popen("mkdir /home/red7en/Desktop/Recon/" + rootDirIn)  
if not (os.path.exists("/home/red7en/Desktop/Recon/" + rootDirIn + "/Eye")):    
   os.popen("mkdir /home/red7en/Desktop/Recon/" + rootDirIn + "/Eye")

if (steps == "1" or steps == "9"):
#### BEGIN AMASS #####################################################
## amass enum searches for subdomains of a top level domain
## The following code writes the output to a text file for later analysis
   subDomains_file = open(pathSubDomains,'w+')
   print("Starting amass enum")
   amassCmd = "amass enum -min-for-recursive 2 -r 8.8.8.8,1.1.1.1,64.6.64.6 -d " + domain
   amassit = os.popen(amassCmd).read()
   print ("amass enum Completed")
   subDomains_file.write(amassit)
   subDomains_file.close()
#########################################################

if (steps == "2" or steps == "9"):
#### BEGIN DIG #####################################################
# Run dig against all subdomains found abve and get the IP address.   Store in text file
   print("Starting Dig for IP addresses")
   ips=set()
   subDomains_file = open(pathSubDomains,"r")
   oneLine = subDomains_file.readline().rstrip()
   while oneLine:
      runit = subprocess.run(['dig', oneLine],stdout=subprocess.PIPE, text=True)
      digOut = runit.stdout
      digTable=digOut.splitlines()
      printIt = False
      for ii in range(len(digTable)):
          if printIt == True: 
              if digTable[ii].find("CNAME") == -1:
                 ips.add(getIP(digTable[ii]))
                 printIt = False
          if digTable[ii] == ";; ANSWER SECTION:":
              printIt = True
      oneLine = subDomains_file.readline().rstrip()
   subDomains_file.close()

#Write all the ip addresses
   pathIP = rootDir + "ips.txt"
   ip_file = open(pathIP, 'w')
   for ip in ips:
     ip_file.write(ip+"\r\n")
   ip_file.close()
   print("Dig completed")
#########################################################
if (steps == "3" or steps == "9"):
#### BEGIN MASSCAN ############################chim#########################
## Run masscan against all ip addresses from above to get all open ports 
##  for later manual analysisif (steps == "2" or steps == "9"):w')
   print("Starting masscan")
   masscan_file = open(pathmasscan, 'w')
   masscanCmd = "sudo masscan -p 0-65535 --rate 100000 -iL " + rootDir + "ips.txt"
   masscan = os.popen(masscanCmd).read()
   print ("masscan Completed")
   masscan_file.write(masscan)
   masscan_file.close()
### Sort masscan.txt
   sortCmd = "sort " + rootDir + "masscan.txt"
   sortedMass = os.popen(sortCmd).read()
   pathsort = rootDir + "masscanSorted.txt"
   masscanSorted_file = open(pathsort, 'w')
   masscanSorted_file.write(sortedMass)
   masscanSorted_file.close()
if (steps == "4" or steps == "9"):   
#########################################################
## Run Eyewitness to look for websites using the subdomains found above.
## Prepending the amassSubdomains
#Open the file and read the first line of subdomains
    print("Starting Prepend of " + pathSubDomains)    
    domains_file = open(pathSubDomains,'r')
    prePendsubDomains_file = open(prePendsubDomains,'w+')
    oneLine = domains_file.readline().rstrip()
    while oneLine:
        prePendsubDomains_file.writelines("https://" + oneLine + "\n")
        oneLine = domains_file.readline().rstrip()
    domains_file.close()
    prePendsubDomains_file.close()
    print("Starting EyeWitness")
    eyeWitnessCmd = "python3 /home/red7en/Desktop/kali/Tools/EyeWitness/EyeWitness.py --max-retries 1 --no-prompt -f " + prePendsubDomains + " -d " + rootDir + "Eye"
    os.popen(eyeWitnessCmd).read()
    print("EyeWitness Completed")
###########################################################################

print(" ")
print("****** End of Run ******")
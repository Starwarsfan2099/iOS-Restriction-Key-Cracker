# -*- coding: utf-8 -*-
import os
from glob import glob
import linecache
import base64
from time import time
from passlib.utils.pbkdf2 import pbkdf2  # pip install pbkdf2, pip install passlib
windows = False
devices = {}

# Search a device plist and return a line
def returnPlistString(path, searchString, linesBelow):
    if windows == True:
        with open(path) as devicePlist:
            for num, line in enumerate(devicePlist, 1):
                if searchString in line:
                    return linecache.getline(path,num + linesBelow)
    else:   # Mac has to different...
        foundLine = 0
        with open(os.path.expanduser(path)) as devicePlist:
            for num, line in enumerate(devicePlist, 1):
                if searchString in line:
                    foundLine = num + 1
                if num == foundLine:
                    return line

# Crack the restrictions key
def crackRestrictionsKey(base64Hash, base64Salt):
    secret = base64.b64decode(base64Hash)
    salt = base64.b64decode(base64Salt)
    startTime = time()
    for i in range(10000):
        key = "%04d" % (i)
        out = pbkdf2(key, salt, 1000)
        if out == secret:
            print "[+] Passcode: ", key
            duration = time() - startTime
            print "[*] %f seconds" % (duration)
            return key
    return False

# Get OS and set backup path based on it
operatingSystem = os.name
if operatingSystem == "nt":
    windows = True
    windowsUser = os.path.expanduser('~').split("\\")[2]
    print "[+] User: %s " % windowsUser
    backupPath = "C:\\Users\\%s\\AppData\\Roaming\\Apple Computer\\MobileSync\\Backup" % windowsUser
    print "[+] Backup path: %s" % backupPath
    backups = glob(backupPath + "\\*\\")
else:
    backupPath = "~/Library/Application Support/MobileSync/Backup/"
    print "[+] Backup path: %s" % backupPath
    backups = os.listdir(os.path.expanduser(backupPath))

# Generate a list of valid backups, grab device info, and store them in a dictionary
print "[+] Generating list of valid backups..."
item = 1
for backup in backups:
    try:
        if windows == True:
            backupDevice = backup + "Info.plist"
            deviceID = backupDevice.split("\\")[8]
        else:
            deviceID = backup
            backupDevice = backupPath + backup + "/" + "Info.plist"
        deviceName = returnPlistString(backupDevice, "Device Name", 1)
        deviceLastBackup = returnPlistString(backupDevice, "Last Backup Date", 1)
        deviceiOSVersion = returnPlistString(backupDevice, "Product Version", 1)
        devices.setdefault(item, [])
        devices[item].append(deviceName.strip().strip("<string>").strip("</string>"))
        devices[item].append(deviceLastBackup.strip().strip("<date>").strip("</date>"))
        devices[item].append(deviceiOSVersion.strip().strip("<string>").strip("</string>"))
        devices[item].append(deviceID)
        item = item + 1
    except IOError as e:
        print "[*] Passing over non-backup file"

# Print the backups and a number option
print "\n[+] Device Backups:\n"
for item, deviceData in devices.iteritems():
    print "%d: %s (%s) - %s" % (item, deviceData[0], deviceData[2], deviceData[1])

# Let the user enter a coice
length = len(devices)
userChoice = int(raw_input("Backup: "))
if (userChoice < 1) or (userChoice > length):
    print "Invalid Choice"
    exit()

# Check iOS version
if (int(devices[userChoice][2][:2].strip(".")) < 7) or (int(devices[userChoice][2][:2].strip(".")) >= 12):
    print "[-] This program is not compatible with iOS %s" % devices[userChoice][2]
    exit()

print "\n[+] Device: %s - %s [%s] (%s)" % (devices[userChoice][0], devices[userChoice][1], devices[userChoice][2], devices[userChoice][3])

# Get the hash and salt from the appropriate file for the apropriate system
if windows == True:
    deviceRestrictionsPlist = backupPath + "\\" + devices[userChoice][3] + "\\39\\398bc9c2aeeab4cb0c12ada0f52eea12cf14f40b"
else:
    deviceRestrictionsPlist = backupPath + "/" + devices[userChoice][3] + "/39/398bc9c2aeeab4cb0c12ada0f52eea12cf14f40b"
try:
    deviceRestrictionsKey = returnPlistString(deviceRestrictionsPlist, "RestrictionsPasswordKey", 2)
    deviceRestrictionsSalt = returnPlistString(deviceRestrictionsPlist, "RestrictionsPasswordSalt", 2)
except IOError:
    print "[-] Device chosen does not have a restrictions key set"
    exit()

if (deviceRestrictionsKey == None) or (deviceRestrictionsSalt == None):
    print "[-] Device had a restrictions key set at one point, but not at the time of backup."
    exit()

if (deviceRestrictionsKey == "") or (deviceRestrictionsSalt == "19"):
    print "[-] Unknown error retrieving hash or salt from file."
    exit()

# Crack it
print "\n[+] Hash: %s\n[+] Salt: %s" % (deviceRestrictionsKey.strip(), deviceRestrictionsSalt.strip())
print "\n[*] Bruteforcing key..."
deviceKey = crackRestrictionsKey(deviceRestrictionsKey, deviceRestrictionsSalt)
if not deviceKey:
    print "[-] Unknown error, key not found"
    exit()

print "\n[+] Key for %s is: %s" % (devices[userChoice][0], deviceKey)

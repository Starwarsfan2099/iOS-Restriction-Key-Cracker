import os
from glob import glob
import linecache
import base64
from time import time
from passlib.utils.pbkdf2 import pbkdf2  # pip install pbkdf2, pip install passlib

devices = {}


def returnPlistString(path, searchString, linesBelow):
    with open(path) as devicePlist:
            for num, line in enumerate(devicePlist, 1):
                if searchString in line:
                    return linecache.getline(path,num + linesBelow)


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


windowsUser = os.path.expanduser('~').split("\\")[2]
print "[+] User: %s " % windowsUser

backupPath = "C:\\Users\\%s\\AppData\\Roaming\\Apple Computer\\MobileSync\\Backup" % windowsUser
print "[+] Backup path: %s" % backupPath


backups = glob(backupPath + "\\*\\")

print "[+] Generating list of valid backups..."
item = 1
for backup in backups:
    try:
        backupDevice = backup + "Info.plist"
        deviceID = backupDevice.split("\\")[8]
        deviceName = returnPlistString(backupDevice, "Device Name", 1)
        deviceLastBackup = returnPlistString(backupDevice, "Last Backup Date", 1)
        deviceiOSVersion = returnPlistString(backupDevice, "Product Version", 1)
        devices.setdefault(item, [])
        devices[item].append(deviceName.strip().strip("<string>").strip("</string>"))
        devices[item].append(deviceLastBackup.strip().strip("<date>").strip("</date>"))
        devices[item].append(deviceiOSVersion.strip().strip("<string>").strip("</string>"))
        devices[item].append(deviceID)
        item = item + 1
    except IOError:
        print "[*] Passing over non-backup file"

print "\n[+] Device Backups:\n"
for item, deviceData in devices.iteritems():
    print "%d: %s (%s) - %s" % (item, deviceData[0], deviceData[2], deviceData[1])

length = len(devices)
userChoice = int(raw_input("Backup: "))
if (userChoice < 1) or (userChoice > length):
    print "Invalid Choice"
    exit()

print devices[userChoice][2][:2]
if devices[userChoice][2][0] < 7:
    if devices[userChoice][2][:2] > 1:
        print "[-] This program is not compatible with iOS %s" % devices[userChoice][2]
        exit()

print "\n[+] Device: %s - %s [%s] (%s)" % (devices[userChoice][0], devices[userChoice][1], devices[userChoice][2], devices[userChoice][3])
deviceRestrictionsPlist = backupPath + "\\" + devices[userChoice][3] + "\\39\\398bc9c2aeeab4cb0c12ada0f52eea12cf14f40b"
try:
    deviceRestrictionsKey = returnPlistString(deviceRestrictionsPlist, "RestrictionsPasswordKey", 2).strip()
    deviceRestrictionsSalt = returnPlistString(deviceRestrictionsPlist, "RestrictionsPasswordSalt", 2).strip()
except IOError:
    print "[-] Device chosen does not have a restrictions key set"
    exit()
if (deviceRestrictionsKey == "") or (deviceRestrictionsSalt == "19"):
    print "[-] Error retrieving hash or salt."
    exit()
print "[+] Hash: %s \n[+] Salt: %s" % (deviceRestrictionsKey, deviceRestrictionsSalt)
print "\n[*] Bruteforcing key..."
deviceKey = crackRestrictionsKey(deviceRestrictionsKey, deviceRestrictionsSalt)
if not deviceKey:
    print "[-] Unknown error, key not found"
    exit()
print "\n[+] Key for %s is: %s" % (devices[userChoice][0], deviceKey)

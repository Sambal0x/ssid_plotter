#!/usr/bin/env python3

import csv
import os
import sys
import gpsd
import argparse
from scapy.all import *
from multiprocessing import Process, current_process, Value

### Global Declaration ###
BANNER ="""
_, _, ___, ,_      ,_ ,    _,  ___,___,_,,_   
 (_,(_,' |   | \,    |_)|   / \,' | ' | /_,|_)  
  _) _) _|_,_|_/    '| '|__'\_/   |   |'\_'| \  
 '  '  '   '         '    ' '     '   '   `'  `
v0.1
"""

filename = "out.csv"
ssids = set() # for testing purpose to store values locally instead of csv file
channel = Value('i',0)  # needed for shared state between multiprocessors
power = Value('i',0)  # needed for shared variable between function (not sure how to pass argument to prn in sniff(), scapy)
SIG_THRESHOLD = -80   # signal threshold before storing value (in dB)


def parse_arguments():
    """
    Handle user-supplied arguments
    """
    desc =('tool to generate a csv file containing '
            'SSIDs, BSSID, signal strength & its location. The csv file can'
            'be uploaded to google maps/earth to plot the '
            'location of the access points - Requires the use of GPS dongle')
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-i','--interface', metavar="",type=str, help='wireless interface',required = True )
    parser.add_argument('-c','--count', metavar="", type=int, help='packets to sniff. Default = 10000', default=10000)
    parser.add_argument('-p','--power', metavar="", type=int, help='minimum SSID signal needs to be in dB, make sure its negative value', default=-100)
    parser.add_argument('-g','--gps', metavar="", type=int, help='Enable or disable GPS - [1]=enabled, [0]=disabled', default=1)
    args = parser.parse_args()

    return args



def PacketHandler(pkt) :
    if pkt.haslayer(Dot11Beacon) :
        if pkt.info:   # if not hidden SSID
            # check if pkt.info(SSID) or pkt.addr3 (BSSID) is already n csv_file
            if check(pkt.info,pkt.addr3,pkt.dBm_AntSignal) :
                write(pkt.info,pkt.addr3,pkt.dBm_AntSignal)     # write new found SSID + BSSID into csv
                #print (len(ssids), pkt.addr3, pkt.info)  #addr3 = BSSID 

def check(ssid, bssid, signal):
    
    ssid_exists = 0
    
    if (signal < power.value) :
        return 0

    with open("out.csv", "r") as file1:
        for line1 in file1: 
            if ssid.decode() in line1:    # search if SSID is in file
                ssid_exists = 1
        file1.close()

    if ssid_exists:

        with open("out.csv", "r") as file2:
            for line2 in file2: 
                if bssid in line2:    # search if BSSID is in file
                    file2.close()
                    return 0

    else :    # no SSID / BSSID found , must be new entry
        return 1

def write(ssid, bssid, signal):

    # write coordinates into file including SSID 
    try :
        packet = gpsd.get_current()
        coordinate = packet.position()
        # Separate latitude and longtitude
        latitude = coordinate[0]
        longitude = coordinate[1]

    except:
        latitude = ""
        longitude = ""

    print ("[+] Adding Entry:",ssid.decode(),bssid,"CH" + str(channel.value),str(signal)+"dB",latitude,longitude)
    with open (filename, mode='a') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=',')
        csv_writer.writerow([ssid.decode(),bssid,channel.value,signal,latitude,longitude])        

def channel_hop(interface):
    #process_id = os.getpid()
    while True:
        try:
            channel.value = random.randrange(1,15)
            os.system("iwconfig " + interface + " channel " + str(channel.value))
            time.sleep(1)
        except KeyboardInterrupt:
            break      

def main():
    #process_id1 = os.getpid()
    """Main Function"""
    print(BANNER + "\n\n")
    args = parse_arguments()

    # Start the channel hopper, creates a new process
    p = Process(target = channel_hop, args=(args.interface,))
    p.start()

    # To do: create new process for gpsd 


    #open newfile or existing file 
    exists = os.path.isfile(filename)
    if not exists:
        # if new file create fieldnames in csv file
        with open(filename, mode='w') as new_file:
            CSV_FIELDNAME = ['SSID','BSSID','channel','signal strength','latitude', 'longlitude']
            CSV_WRITER = csv.DictWriter(new_file, fieldnames=CSV_FIELDNAME, delimiter=",")
            CSV_WRITER.writeheader()
            new_file.close()

    # connect to the local gpsd . gpsd -N -n -D2 /dev/ttyACM0
    #start_gpsd = 'gpsd -N -n /dev/ttyACM0'
    #os.system(start_gpsd)
    if (args.gps):
        gpsd.connect()

    power.value = args.power   # used in check() function
    sniff(iface = args.interface, count = args.count, prn = PacketHandler)

if __name__ == "__main__":
    main()

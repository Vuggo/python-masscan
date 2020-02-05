import re
import io
import sys
import json
import masscan
import socket
from datetime import datetime

def log_time():
    #converts HH:MM:SS.MS => HH_MM_SS
    return str(datetime.now().time()).split('.',1)[0].replace(':','_')

def log_scan_json(scan_dict):

    json.dump(scan_dict, open("logs/json/" + log_time() +".json" , "w+") ,indent=4)
    return

def log_scan_flat(scan_str):
    with open("logs/flat_file/" + log_time() + ".txt","w+") as f:
        f.write(scan_str)
        return
        
#ports can be passed in 3 ways:
#1,2,3...
#1-10,11-12,23...
#1-10,11-12,23,49,U:161-191,172,U:12222...
#so this function will create a list to pass to the parser for output
#in order to generate a dictionary with all ports and protocols before parsing
# Returns a dictionary of protocol mapped to each port scanned
# {'tcp': {port:{}}, 'udp':{port:{}}} 
def port_dict(port_str):
    udp = []
    tcp = []

    #splits and matches all the hyphenated ports to create ranges out of them
    for i in re.split(',',port_str):
        match = re.search(r'((?P<udp>U:)*(?P<start_index>\d+)-(?P<end_index>\d+))',i)

        if match:
            start = int(match.group('start_index'))
            end = int(match.group('end_index'))

            if match.group('udp'):
                for n in range(start,end):
                    udp.append(n)
            else:
                for n in range(start,end):
                    tcp.append(n)
        else:
            if 'U:' in i:
                udp.append(i[2:])
            else:
                tcp.append(i)

    ports = {
        "tcp":{port:{} for port in tcp},
        "udp":{port:{} for port in udp}
    }
    
    return ports

#scan_result =  json serialized object
#port_str = str containing ports to be scanned - used to create proper dict structur#returns a json serialized object

def flat_file(scan_result):
    
    f = open('example_flat_file', 'w+')
    
    data = scan_result                                                       
    hosts = data['scan']
    
    for host in hosts:
        
        host_data = hosts[host]
        line += host + " "  
        #host_data's only key is a str representing the port's protocol                                                                                      
        #and host_data[protocol] = {port# :{more_content}}
        
        if 'tcp' in host_data.keys():
            protocol = 'tcp'
            port_data = host_data["tcp"]
        elif 'udp' in host_data.keys():
            protocol = 'udp'
            port_data = host_data["udp"]
            
        #this is the rest of the data associated w/ the port
        
        for port in port_data:            
            port_contents = port_data[port]
            port_state = port_contents['state']
            reason = port_contents['reason']
            services = port_contents['services']

            if services:
                service_name = services[0]['name']
                service_banner = services[0]['banner']
                line += port + " " + protocol + " " + service_banner + "\n"

            else:
                line += port + " " + protocol + " None\n"                
        
            
def parse_scan(scan_result,port_str):

    pd = port_dict(port_str)
    data = scan_result
    hosts = data['scan']

    #host: {protocol:{content}}
    for host in hosts:
        host_data = hosts[host]

        #host_data's only key is a str representing the port's protocol
        #and host_data[protocol] = {port# :{more_content}}
        if 'tcp' in host_data.keys():
            protocol = 'tcp'
            port_data = host_data["tcp"]
        elif 'udp' in host_data.keys():
            protocol = 'udp'
            port_data = host_data["udp"]

        #this is the rest of the data associated w/ the port#
        for port in port_data:
            port_contents = port_data[port]
            port_state = port_contents['state']
            reason = port_contents['reason']
            services = port_contents['services']

            if services:
                service_name = services[0]['name']
                service_banner = services[0]['banner']

            # pd structure is
            # protocol : {port :{dicts_of_hosts :{relevant_data} },...},...} for
            # all hosts detected with that port open
            
            current_key = pd[protocol][port]

            if protocol == 'tcp':
                if services:
                    current_key[host] = {
			'port_state':port_state,
			'confirmed_by':reason,
			'service':service_name,
			'banner':service_banner
		    }
                else:
                    current_key[host] = {
			'port_state':port_state,
			'confirmed_by':reason
		    }
                    
            elif protocol == 'udp':
                if services:
                    current_key[host] = {
			'port_state':port_state,
			'confirmed_by':reason,
			'service':service_name,
			'banner':service_banner
		    }
                else:
                    current_key[host] = {
		        'port_state':port_state,
			'confirmed_by':reason
		    }
			
    return pd
  
        
#cmd = 'sudo masscan -p80 185.0.0.0/8 --rate=1000000  --banner -oJ out.json'
def valid_ports(portstr):    
    #regex returns a list of each element in the list seperated
    for port in re.findall('((?:U:)*\d+|\d+-\d+,*)+',portstr):    
        if 'U:' in port:
            port = port[2:]
        if int(port) > 65535:
            return False    

    return True

def valid_ipv4(ipaddr):

    if not re.fullmatch('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?',ipaddr):
        return False    
    try:
        socket.inet_aton(ipaddr.split('/',1)[0])
        return True
    except:
        return False

def scan(hosts, ports, args):
    
    mas = masscan.PortScanner()
    mas.scan(hosts, ports=ports, arguments=args)
    scan_buffer = io.StringIO()
    json.dump(mas.scan_result, scan_buffer, indent=4)
    out_dict = json.loads(scan_buffer.getvalue())    
    scan_json = parse_scan(out_dict,ports)
    log_scan(scan_json)    
    return scan_json

def main():
    if len(sys.argv) < 3:
        return print('usage:\nmscan.py hosts/(optional subnet mask) ports extra_args\nexample: mscan.py 10.0.0.0/10 22-25,80,U:161 --rate=x --banner')
    
    #valid ip/subnet check
    if not valid_ipv4(sys.argv[1]):
        return print("Invalid host/subnet")
    if not valid_ports(sys.argv[2]):
        return print("Invalid ports")    

    args = " "
    for i in sys.argv[3:]:
        args += i + " "
        
    print(scan(sys.argv[1],sys.argv[2],args))
    #ports = '22,23,80,U:161,8000,8080,U:100-105'
    #hosts = '185.0.0.0/10'
    #rate = '10000000'

    
main()

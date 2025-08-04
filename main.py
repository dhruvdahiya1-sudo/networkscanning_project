import os
from scapy.all import *
import socket
import threading 
from netaddr import IPNetwork
import subprocess
import time

def ip_convert(domain):
        try:
            d = socket.gethostbyname(domain)    #getting host by name
            print(f"resolved ip is {d}")                      #target ip
            return d
        except Exception as e:
            print(f"error is {e}")


# host_scanning -------------------------------------------------

def host_scan():
    choice=int(input("enter ( 1 to enter target domain and 2 for target ip) :"))
    def insert_choice(choice):
        if choice==1:
            domain = input("enter the domain :")
            target_ip = ip_convert(domain)
            return target_ip
        if choice==2:
            target_ip=input("enter the target ip :")
            return target_ip
        else:
            print("invalid option selected\n")
            new_choice=int(input("enter (1 for domain and 2 for IPAddress) :"))
            return insert_choice(new_choice)
    ip = insert_choice(choice)
    ICMP_packet= IP(dst=str(ip))/ICMP()
    response = sr1(ICMP_packet,timeout=2,verbose=0)

    if response:
        print(f"{ip} is up")
        
    else:
        for port in [80,443,22]:

            s=socket.socket()
            s.settimeout(4)
            response = s.connect_ex((ip,port))
            if response==0:
                print(f"{ip} is up")
                s.close()
                break
            else:
                print(f"{ip} is down or firewall blocking the tcp/icmp request")
                s.close()

#subnet scanning --------------------------------------------------

def subnet_scan():
    subnet = input("enter the subnet :")
    up_ips=[]
    def ping(ip):
        o=os.system(f"ping -c 1 {ip} >/dev/null 2>&1")
        if o==0:
            print(f"{ip} is up")
            up_ips.append(str(ip))
        else:
            print(f"{ip} is down")
    threads=[]
    for ip in IPNetwork(subnet):
        t=threading.Thread(target=ping,args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(up_ips)
    print("scan complete")


#port scanning ----------------------------------------------------------

def port_scanner():

    
    def ip_convert(domain):
        try:
            d = socket.gethostbyname(domain)    #getting host by name
            print(f"resolved ip is {d}")                      #target ip
            return d
        except Exception as e:
            print(f"error is {e}")



    def port_range(start,end):
     
        if (start < 0 or end >65535):
            print("invalid port range please enter range between 0-65535")
        else:
            port_list=list(range(start,end+1))
        
            return port_list


    
    def specific_port(port_list):
        try:
            port_list=[int(p.strip()) for p in port_list.split(",")if p.strip().isdigit()and 0<= int(p.strip()) <=65535] #listing the int from string and storing in the list 
            print(f"port list is \n {port_list}")
            return port_list
        except Exception as e:
            print("invalid port input scanning default ports" )
            port_list = range(1,1025)
            return port_list


    open_port_list=[]
    def port_scan(ip,port,filename):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip,port))
            s.close()
            if  result == 0:
                with open(filename,"a") as f:
                    f.write(f"port {port} is open")
                print(f"{port} is open")
                open_port_list.append(port)
            else:
                print(f"port {port} is closed")
        except Exception as e:
            print(f"scanning error {e}")

    def thread_scan(ip,filename):
        global port_list
        thread=[]
        for p in port_list:
            t = threading.Thread(target=port_scan,args=(ip,p,filename))
            t.start()
            thread.append(t)

            while threading.active_count()>500:
                pass
        for t in thread:  
            t.join()

    print("select option : \n 1. if you have target domain \n 2. if you have target ip ")
    option=int(input("enter you option:"))
    
    def choose_option(option):
        
        if option == 1:
            domain = input("Enter domain name of target: ")
            return ip_convert(domain)
        elif option == 2:
            t_ip = input("Enter the IP address: ")
            return t_ip
        else:
            print("Invalid option. Please try again.")
            new_option = int(input("Enter your option (1 for domain, 2 for IP): "))
            return choose_option(new_option)

    t_ip = choose_option(option)
        

    filename=input("enter filename to save the data:")

    print("select anyone choice : \n 1. to scan port in any range between 0-65535 \n 2. to scan specific port")
    choice=int(input("enter your choice :"))
    port_list=[]
    def choose_choice(choice):
        global port_list
        if choice == 1:
            start = int(input("enter the first port :"))
            end = int(input("enter the last port :"))
            port_list = port_range(start,end)
        elif choice == 2:
            port_input=input("enter comma separated specific ports :")
            port_list = specific_port(port_input)
        else:
            print("invalid choice submitted please try again:")
            newchoice=int(input("enter the correct choice(1 for ports range and 2 for specific ports)"))
            choose_choice(newchoice)
    choose_choice(choice)

    thread_scan(t_ip,filename)
    print(f"open ports are {open_port_list}")



#service enumeration--------------------------------------------------------------

def service_ver_det():
    import socket
    import threading

    def port_range(start,end):
    
        if (start < 0 or end >65535):
            print("invalid port range please enter range between 0-65535")
            new_st=int(input("please enter the starting port again:"))
            new_end=int(input("please enter the ending port again:"))
            return port_range(new_st,new_end)
        else:
            port_list=list(range(start,end+1))
        
            return port_list

    
    def specific_port(port_list):
        try:
            port_list=[int(p.strip()) for p in port_list.split(",")if p.strip().isdigit()and 0<= int(p.strip()) <=65535] #listing the int from string and storing in the list 
            print(f"port list is \n {port_list}")
            return port_list
        except Exception as e:
            print("invalid port input scanning default ports" )
            port_list = range(1,1025)


    def service_detection(ip,port,filename):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)

            response = s.connect_ex((ip, port))  # ip: str, port: int

            if response == 0:
                try:
                    banner = s.recv(1024).decode().strip()
                except:
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    banner=s.recv(1024).decode().strip()

                try:
                    service_name = socket.getservbyport(port)
                except:
                    service_name = "not fetchable"

                print(f"[+] Port {port} -- Service: {service_name} | Version: {banner}")
                with open(filename,"a")as f:
                    f.write(f"\n port {port} --service: {service_name} | version:{banner}\n")
            

            s.close()

        except Exception as e:
            print(f"[!] Error on port {port}: {e}")


    def thread_scan(ip,filename):
        thread = []
        global port_list
        with open(filename,"a")as f:
            f.write("\n port service detection\n ================================\n")

        for port in port_list:
            t = threading.Thread(target=service_detection, args=(ip, port,filename))
            thread.append(t)
            t.start()

            while threading.active_count() > 500:
                pass

        for t in thread:
            t.join()

    target_ip = input("enter the taget IPaddress :")
    filename = input("enter filename to save the data:")
    print("select option by which you want to select the ports: \n 1. to enter specific ports for service detection : \n 2. to enter the range of port:")
    choice=int(input("enter your option"))
    def way_to_insertport(choice):
        global port_list
        if choice==1:
            port_input = input("enter the comma separated ports")
            port_list = specific_port(port_input)
        elif choice == 2:
            start = int(input("enter the first port to start the scanning:"))
            end = int(input("enter the last port to end the scanning:"))
            port_list=port_range(start,end)
        else:
            print("invalid option please insert again:")
            newchoice=int(input("enter your option (please insert 1 for specific ports and 2 for inserting range)"))
            way_to_insertport(newchoice)
    way_to_insertport(choice)
    thread_scan(target_ip,filename)

#os fingerprint ----------------------------------------------------------------------------


def os_det():

    def ip_convert(domain):
        try:
            d = socket.gethostbyname(domain)    #getting host by name
            print(f"resolved ip is {d}")                      #target ip
            return d
        except Exception as e:
            print(f"error is {e}")

    

    def send_probe(dst_ip,dst_port,flags):
        packet=IP(dst=dst_ip)/TCP(dport=dst_port,flags=flags)
        response = sr1(packet,timeout=2,verbose=0)
        return response


    def os_fingerprinting(dst_ip):

    

        print(f"[+] - os fingerprinting start on target - {dst_ip}")
        print("sending TCP and ICMP probes")

        os_data={}

        ''' sending TCP SYN probe'''
        SR_SYN = send_probe(dst_ip,80,"S")

        if SR_SYN:
            os_data["SYN_TTL"]=SR_SYN.ttl
            os_data["SYN_window"]=SR_SYN[TCP].window #determine the window size from tcp response
    
        else:
            print("[-] no response to SYN")

        time.sleep(1.1)

        #sending TCP ACK probe

        SR_ACK = send_probe(dst_ip,80,"A")

        if SR_ACK:
            os_data["ACK_TTL"]=SR_ACK.ttl
            os_data["ACK_WIN"]=SR_ACK[TCP].window
        else:
            print("[-] no response from TCP ACK probe")

        time.sleep(1.2)

        #sending TCP FIN probe

        SR_FIN = send_probe(dst_ip,80,"F")

        if SR_FIN:
            os_data["FIN_TTL"]=SR_FIN.ttl
            os_data["FIN_window"]=SR_FIN[TCP].window

        else:
            print("[-] no response from TCP_fin probe")

        time.sleep(1)

        #sendign ICMP echo request 

        ICMP_packet = IP(dst=dst_ip)/ICMP()
        ICMP_response = sr1(ICMP_packet,timeout=2,verbose=0)

        if ICMP_response:
            os_data["ICMP_TTL"]=ICMP_response.ttl
            os_data["ICMP_TYPE"]=ICMP_response.type #type shows what happens to icmp probe if 0 then request recieved if another then host might be down or firewall is present and blocking or IDS

        else:
            print("[-] no response from icmp echo request")

        # accessing the data from os_data dictionary
        for key in os_data:
            print(key," : ",os_data[key])
        
        ttl = os_data.get("SYN_TTL",0) or os_data.get("ACK_TTL") or os_data.get("FIN_TTL") or os_data.get("ICMP_TTL")
        window = os_data.get("SYN_window") or os_data.get("ACK_WIN") or os_data.get("FIN_window")
        
        if ttl==0 or window is None:
            print("[-] unable to detect the OS")
        if ttl<=64:
            if window in range(5840,14600):
                print(" --> linux (2.4 or 2.6)")
            elif window in range(29200,64240):
                print(" --> ubuntu/debian")
            elif window ==65535:
                print(" --> macos or BSD based os")
            else:
                print(" --> likely to be unix/linux variant")
        
        elif ttl<=128:
            if window in range(8192,65535):
                print(" --> likley to be window os")
            else:
                print(" --> possibly the window os")
        elif ttl>128:
            print(" --> possibly cisco/solaris/AIX")
        
        print("\n os fingerprinting completed ")
    
    print("\n select : \n 1. to enter target domain \n 2. to enter target ip\n")
    choice = int(input("enter the option (1 - domain and 2 - target ip)"))
    def insert_choice(choice):
        if choice==1:
            domain = input("enter the domain :")
            target_ip = ip_convert(domain)
            return target_ip
        if choice==2:
            target_ip=input("enter the target ip :")
            return target_ip
        else:
            print("invalid option selected\n")
            new_choice=int(input("enter (1 for domain and 2 for IPAddress) :"))
            return insert_choice(new_choice)
    
    target_ip = insert_choice(choice)
    os_fingerprinting(target_ip)



def network_scanning():

    print("select the scanning services provided from below options :\n 1. host scanning or ping \n 2. subnet scanning \n 3. port scanning \n 4. service enumeration \n 5. OS fingerprint \n")
    selected_service = int(input("enter the service you want to use : "))
    def sel_service(service):
        if service==1:
            host_scan()
        elif service==2:
            subnet_scan()
        elif service==3:
            port_scanner()
        elif service==4:
            service_ver_det()
        elif service==5:
            os_det()
        else:
            print("you enter wrong service (please enter the service between 1-5)\n")
            new_service=int(input("enter the service between(1-5) :"))
            return sel_service(new_service)
    sel_service(selected_service)

network_scanning()



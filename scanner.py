from os import system
import socket
import scapy.all as scapy
from termcolor import colored


def get_hostname(ip:str):
    """
    Returned de hostname die bij een opgegeven IP-adres hoort.

    Args:
        ip (str): Een string die het op te zoeken IP-adres voorstelt.

    Returns:
        str: De hostname die bij het opgegeven IP-adres hoort, of de string "Geen hostname" als er geen hostname is gevonden.

    Raises:
        Any: Elke uitzondering die wordt opgeworpen door de `gethostbyaddr` functie wordt afgehandeld door de string "Geen hostname" terug te geven.
    """

    try: # error handler toegevoegd zodat de loop niet stopt als er geen hostname bekend is
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        hostname = "No hostname"
        return hostname


def get_ports(ip:str):
    """
    Scan een IP-adres op open poorten en retourneer een lijst van de open poorten.

    Args:
        ip (str): Een string die het IP-adres voorstelt dat moet worden gescand.

    Returns:
        list: Een lijst van integers die de open poorten van het opgegeven IP-adres bevatten.

    Raises:
        Any: Er worden geen specifieke uitzonderingen opgevangen in deze functie.
    """
    # Scan voor open poorten
    open_ports = []
    for port in range(1, 1025): # loop door iedere (standaard) poort 1-1024 (geen development poorten)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # maak een socket object aan ...
        sock.settimeout(0.1)
        result = sock.connect_ex((ip, port)) # ... om te kijken welke poorten er open staan
        if result == 0:
            open_ports.append(port) 
        sock.close()

    return open_ports


def get_service_names(ports:list):
    """
    Retourneert de service namen die bij een opgegeven lijst van poortnummers horen.

    Args:
        ports (list): Een lijst van integers die de poortnummers bevatten waarvoor de service namen moeten worden opgehaald.

    Returns:
        list: Een lijst van strings die de bijbehorende service namen bevatten voor de opgegeven poortnummers.

    Raises:
        Any: Elke uitzondering die wordt opgeworpen door de `getservbyport` functie wordt afgehandeld door de string "Unknown" terug te geven.
    """
    service_names = [] 
    for port in ports: # voor iedere poort in alle poorten
        try: # error handler
            service_name = socket.getservbyport(port) # service naam op basis van poort nummer 
            service_names.append(service_name) # voeg toe aan de lijst
        except:
            service_names.append('Unknown') # unknown port
    return service_names # return de lijst


def get_os_name(ip:str):
    """
    Retourneert het besturingssysteem van een opgegeven IP-adres door verbinding te maken met poort 135 en een aanvraag te sturen voor informatie.

    Args:
        ip (str): Een string die het IP-adres voorstelt van het apparaat waarvan het besturingssysteem moet worden opgehaald.

    Returns:
        str: Een string die het besturingssysteem van het opgegeven IP-adres bevat.

    Raises:
        Any: Er worden geen specifieke uitzonderingen opgevangen in deze functie.
    """

    # creeër een socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # timeout = 1 seconde
    s.settimeout(1)
    
    try: # error handler
        # verbind met de host
        s.connect((ip, 135))
        
        # verzend een request naar de host om operating system informatie op te halen
        s.send(b'\x4e\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        
        # antwoord van de host
        response = s.recv(1024)
        
        # haal de operating system informatie uit de response
        os_name = response[53:].decode('utf-8').split('\x00')[0]
        
        return os_name
    except: # als er iets fout gaat, is er geen operating system gevonden
        return "No operating system found" 


def ip_range(ip_address1:str, ip_address2:str):
    """
    Berekent een lijst met IP-adressen binnen het opgegeven bereik en retourneert deze.

    Args:
        ip_address1 (str): Een string die het eerste IP-adres in het bereik voorstelt.
        ip_address2 (str): Een string die het laatste IP-adres in het bereik voorstelt.

    Returns:
        list: Een lijst met alle IP-adressen tussen de opgegeven IP-adressen, inclusief de opgegeven adressen zelf.

    Raises:
        None: Er worden geen specifieke uitzonderingen opgevangen in deze functie.
    """

    iplist = []

    ip_address1 = (ip_address1.split("."))
    ip_address2 = (ip_address2.split("."))

    if ip_address1[0] == ip_address2[0]: # eerste octet
        if ip_address1[1] == ip_address2[1]: # 2e octet
            if ip_address1[2] == ip_address2[2]: # 3e octet
                begin = int(ip_address1[3]) # 4e octet begin
                end = int(ip_address2[3]) # 4e octet eind
                if end <= begin: # als het eind kleiner is dan het begin ip, is er geen range te berekenen
                    print("IP range is not valid!")
                    return(0)
                else:
                    for i in range(begin, end+1): # voor iedere ip nummer tussen het 4e octet (begin) en 4e octet (eind)
                        ip_start = (ip_address1[0:3]) # 1e tot en met 3e octet
                        ip_start.append(str(i)) # voeg het nieuwe 4e octet toe
                        ip_start = '.'.join((i) for i in ip_start) # maak van de lijst een ip adres
                        iplist.append(ip_start) # voeg het uiteindelijke ip toe aan de lijst
                    return(iplist) # return de lijst
                

def devices(minIp:str, maxIp:str):
    """Maak een lijst van dictionaries met informatie over alle apparaten in het opgegeven IP-bereik.

    Args:
        minIp (str): Het laagste IP-adres in het bereik.
        maxIp (str): Het hoogste IP-adres in het bereik.

    Returns:
        list: Een lijst van dictionaries met informatie over alle apparaten in het opgegeven IP-bereik.
              Elke dictionary bevat de 'ip' en 'mac' van een apparaat.
    """
    print(colored(f"Creating IP range between: {minIp} - {maxIp} ...\n", "black", "on_blue"))
    ip_list = ip_range(minIp, maxIp) # ip range tussen de 2 ip's 
    # maak een list van dictionaries om alle informatie over alle devices op te slaan 
    devices_list = []

    for ip in ip_list: # voor ieder ip adres ...
        arp = scapy.ARP(pdst=ip) # ... voer een arp request uit
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # ... voer een ether request uit op het  broadcoast adres
        packet = ether/arp # delen door elkaar om de packet resultaat te krijgen
        result = scapy.srp(packet, timeout=3, verbose=0)[0] # resultaat is het eerste element in de lijst van het resultaat
        
        for element in result: # voor ieder element in het resultaat
            devices_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc} # voeg het ip en mac adres toe aan de dictionary
            devices_list.append(devices_dict) # voeg de dictionary toe aan de list

    return devices_list


def scan(ip:str, subnet:str, options:list=[], ip2:str=""):
    """
    Scant een netwerk op actieve apparaten en opent poorten. De functie neemt vier parameters:

    ip: str
        Het IP-adres van het netwerk om te scannen.

    subnet: str
        Het subnetmasker voor het netwerk.

    options: list (optioneel)
        Een optionele lijst met strings die bepalen welke informatie moet worden weergegeven voor elk apparaat op het netwerk.
        Geldige opties zijn: "-N" voor het weergeven van de apparaten in het netwerk, "-F" voor het scannen van het volledige netwerk en
        "-H", "-O", "-P" en "-PS" voor het weergeven van respectievelijk het hostname, het besturingssysteem, de open poorten en de
        service namen.

    ip2: str (optioneel)
        Een optionele parameter om een bepaald bereik van IP-adressen te scannen binnen het opgegeven netwerk.

    De functie retourneert geen waarde, maar toont de gevraagde informatie op de console.
    """
    try:
        if "-N" in options:
            if ip2 == "":
                network = '.'.join(ip.split('.')[:-1]) + f'.0/{subnet}'
                # verzend een arp request om de mac addressen te verkrijgen (met de ip addressen) van alle devices in het netwerk
                arp_request = scapy.ARP(pdst=network) 
                broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # broadcast message
                arp_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

                # maak een list van dictionaries om alle informatie over alle devices op te slaan 
                devices_list = []
                for element in answered_list:
                    devices_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
                    devices_list.append(devices_dict)
                print(colored(f'the following devices are on network {network}:', 'black', 'on_green'))
            else:
                devices_list = devices(ip, ip2)
                print(colored(f'the following devices are in network range: {ip} - {ip2}:', 'black', 'on_green'))
            
            for device in devices_list:
                print(f"{colored(device['ip'], 'green', attrs=['bold'])} with mac: {colored(device['mac'], 'green')}")
            print("\n")
        elif "-F" in options: # scan het volledige netwerk
            if ip2 == "":
                # netwerk range verkrijgen van het ip address en subnetmask /24 toevoegen
                network = '.'.join(ip.split('.')[:-1]) + f'.0/{subnet}'
                
                # verzend een arp request om de mac addressen te verkrijgen (met de ip addressen) van alle devices in het netwerk
                arp_request = scapy.ARP(pdst=network) 
                broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # broadcast message
                arp_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]


                # maak een list van dictionaries om alle informatie over alle devices op te slaan 
                devices_list = []
                for element in answered_list:
                    devices_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
                    devices_list.append(devices_dict)
            else:
                devices_list = []
                devices_list = devices(ip, ip2)

            print(colored('Scanning the following devices:', 'black', 'on_green'))
            for device in devices_list:
                print(f"{colored(device['ip'], 'green', attrs=['bold'])} with mac: {colored(device['mac'], 'green', attrs=['bold'])}")
            print("\n")

            # scan voor open ports en services voor elk apparaat op het netwerk
            for device in devices_list:
                ip_address = device['ip'] # ip address
                mac_address = device['mac'] # mac address
                print(f"\nNow scanning: {colored(ip_address, 'green')} with mac address {colored(mac_address, 'green')}")


                
                if len(options) > 1:
                    if "-H" in options:
                        print(colored("getting hostname ...", "black", "on_blue"))
                        hostname = get_hostname(ip_address)

                        print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                        print(f"\tHostname: {colored(hostname, 'blue')}\n")
                    elif "-O" in options:
                        print(colored("getting operating system ...", "black", "on_blue"))
                        operating_system = get_os_name(ip_address) # operating system van de host

                        print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                        print(f"\tOperating system: {colored(operating_system, 'blue')}\n")
                    elif "-P" in options:
                        print(colored("getting open ports ...", "black", "on_blue"))
                        open_ports = get_ports(ip_address)
                        
                        print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                        if open_ports != []:
                            print(f"\tOpen ports: {colored(open_ports, 'black', 'on_light_blue')}\n")
                        else:
                            print(colored(f"No open ports found!", "red", attrs=['bold']))
                    elif "-PS" in options:
                        print(colored("getting open ports ...", "black", "on_blue"))
                        open_ports = get_ports(ip_address)

                        print(colored("getting service names from open ports ...", "black", "on_blue"))
                        service_names = get_service_names(open_ports)

                        print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                        if open_ports != []:
                            print(colored(f"\tOpen ports:", "white", attrs=['bold']))
                            for i, port in enumerate(open_ports):
                                print(f"\t\t{colored(port, 'blue',)} ({colored(service_names[i], 'red')})")
                        else:
                            print(colored("No open ports found!", "red", attrs=['bold']))
                else: # als er geen opties gegeven zijn, laat alle informatie zien
                    print(colored("getting hostname ...", "black", "on_blue"))
                    hostname = get_hostname(ip_address) # hostname

                    print(colored("getting operating system ...", "black", "on_blue"))
                    operating_system = get_os_name(ip_address) # operating system van de host

                    print(colored("getting open ports ...", "black", "on_blue"))
                    open_ports = get_ports(ip_address) # open poorten

                    print(colored("getting service names from open ports ...", "black", "on_blue"))
                    service_names = get_service_names(open_ports) # service namen van de bijbehorende poorten
                    
                    print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                    print(f"\tHostname: {colored(hostname, 'black', 'on_light_blue')}\n\tOperating System: {colored(operating_system, 'black', 'on_light_blue')}\n\tOpen Ports: {colored(open_ports, 'black', 'on_light_blue')}\n\tService Names: {colored(service_names, 'black', 'on_light_blue')}\n")
        else:     
            arp_request = scapy.ARP(pdst=ip) 
            broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # broadcast message
            arp_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

            devices_list = []
            for element in answered_list:
                devices_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
                devices_list.append(devices_dict)

            for device in devices_list:
                ip_address = device['ip'] # ip address
                mac_address = device['mac'] # mac address
            
                 
            if len(options) > 0:
                if "-H" in options: # only hostname
                    print(colored("getting hostname ...", "black", "on_blue"))
                    hostname = get_hostname(ip_address)

                    print(colored(f"\ndata from {colored(ip_address, 'green')}:", "black", "on_green"))
                    print(f"\tMAC Address: {colored(mac_address, 'black', 'on_light_blue')}\n\tHostname: {colored(hostname, 'black', 'on_light_blue')}\n")
                elif "-O" in options: # operating system
                    print(colored("getting operating system ...", "black", "on_blue"))
                    operating_system = get_os_name(ip_address) # operating system van de host

                    print(colored(f"\ndata from {colored(ip_address, 'green')}:", "black", "on_green"))
                    print(f"\tMAC Address: {colored(mac_address, 'black', 'on_light_blue')}\n\tOperating system: {colored(operating_system, 'black', 'on_light_blue')}\n")
                elif "-P" in options: # open poorten
                    print(colored("getting open ports ...", "black", "on_blue"))
                    open_ports = get_ports(ip_address)

                    print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                    if open_ports != []:
                        print(f"\tOpen ports: {colored(open_ports, 'black', 'on_light_blue')}\n")
                    else:
                        print(colored(f"\tNo open ports found!", "red", attrs=['bold']))
                elif "-PS" in options: # open poorten en bijbehorende service namen
                    print(colored("getting open ports ...", "black", "on_blue"))
                    open_ports = get_ports(ip_address)

                    print(colored("getting service names from open ports ...", "black", "on_blue"))
                    service_names = get_service_names(open_ports)

                    print(colored(f"data from {colored(ip_address, 'green')}:", "black", "on_green"))
                    if open_ports != []:
                        print(colored(f"\tOpen ports:", "white", attrs=['bold']))
                        for i, port in enumerate(open_ports):
                            print(f"\t\t{colored(port, 'blue',)} ({colored(service_names[i], 'red')})")
                    else:
                        print(colored("\tNo open ports found!", "red", attrs=['bold']))
            else: # als er geen opties gegeven zijn, laat alle informatie zien
                print(colored("getting hostname ...", "black", "on_blue"))
                hostname = get_hostname(ip_address) # hostname

                print(colored("getting operating system ...", "black", "on_blue"))
                operating_system = get_os_name(ip_address) # operating system van de host

                print(colored("getting open ports ...", "black", "on_blue"))
                open_ports = get_ports(ip_address) # open poorten

                print(colored("getting service names from open ports ...", "black", "on_blue"))
                service_names = get_service_names(open_ports) # service namen van de bijbehorende poorten

                print(colored(f"\ndata from {colored(ip_address, 'green')}:", "black", "on_green"))
                print(f"\tMAC Address: {colored(mac_address, 'black', 'on_light_blue')}\n\tHostname: {colored(hostname, 'black', 'on_light_blue')}\n\tOperating System: {colored(operating_system, 'black', 'on_light_blue')}\n\tOpen Ports: {colored(open_ports, 'black', 'on_light_blue')}\n\tService Names: {colored(service_names, 'black', 'on_light_blue')}\n")
    except Exception as e: # laat de error zien als er een error optreed
        if type(e) == UnboundLocalError:
            print(colored(f"Error: no devices on this network!", 'red'))
        else:
            print(colored(f"Error: {e}", 'red'))
        pass


    


if __name__ == "__main__":
    while True: # loop
        print(colored("Netscan v1 ...", 'light_green', attrs=['bold']))
        print(colored(r'''
               __                               
  ____   _____/  |_  ______ ____ _____    ____  
 /    \_/ __ \   __\/  ___// ___\\__  \  /    \ 
|   |  \  ___/|  |  \___ \\  \___ / __ \|   |  \
|___|  /\___  >__| /____  >\___  >____  /___|  /
     \/     \/          \/     \/     \/     \/ 
        ''', 'green'))

        print(colored('''
options:
    scan {ip_address} {subnet_mask}  # scan an ip address network and print all information, ex: 'scan 192.168.1.1 24'
    scanrange {ip_address1} {ip_address2} {subnet_mask}  # scan an ip address network in range of ip1 and ip2 and print information about the host(s), ex: 'scanrange 192.168.1.1 192.168.1.20 24'

    advanced options:
        -F  # scan the full network
        -O  # get the operating system from the given ip address
        -H  # get hostname
        -P  # get open ports
        -PS # get open ports and related service names
        -N  # scan the network for ip addresses and mac addresses 
    ''', 'light_blue'))

        options = []
        userInput = input(colored("netscan > ", 'green', attrs=['bold']))
        commands = userInput.split(" ")
        commandOptions = ["scan", "scanrange"]

        while commands[0] not in commandOptions:
            system('cls')
            print(colored(f"'{commands[0]}' is not an option!", 'red', attrs=['bold']))
            print(colored('''
options:
    scan {ip_address} {subnet_mask}  # scan an ip address network and print information about the host(s), ex: 'scan 192.168.1.1 24'
    scanrange {ip_address1} {ip_address2} {subnet_mask}  # scan an ip address network in range of ip1 and ip2 and print information about the host(s), ex: 'scanrange 192.168.1.1 192.168.1.20 24'

    advanced options:
        -F  # scan the full network
        -O  # get the operating system from the given ip address
        -H  # get hostname
        -P  # get open ports
        -PS # get open ports and related service names  
        -N  # scan the network for ip addresses and mac addresses     
        ''', 'light_blue'))
            userInput = input(colored("netscan > ", 'green', attrs=['bold']))
            commands = userInput.split(" ")
    	
        command = commands[0]

        if command == "scan":
            ip = commands[1]
            subnetmask = commands[2]
            for option in commands[3::]:
                options += [option]

            system('cls')
            scan(ip, subnetmask, options)
        elif command == "scanrange":
            ip1 = commands[1]
            ip2 = commands[2]
            subnetmask = commands[3]
            for option in commands[4::]:
                options += [option]

            system('cls')
            scan(ip1, subnetmask, options, ip2)
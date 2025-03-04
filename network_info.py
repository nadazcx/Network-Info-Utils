
import platform
import socket
import subprocess
import re
import uuid
import shutil
import json
import os
import pywifi
from pywifi import const
import time

def get_hostname_ip():
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
        return hostname, ip_address
    except socket.gaierror:
        return hostname, "Could not retrieve IP address"

def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                    for elements in range(0, 8*6, 8)][::-1])
    return mac

def get_default_gateway_linux():
    """Get the default gateway and its MAC address on Linux (language-independent)."""
    try:
        gateway_ip = None
        
        # Try /proc/net/route
        if os.path.exists('/proc/net/route'):
            with open('/proc/net/route', 'r') as route_file:
                for line in route_file.readlines()[1:]:  # We will Skip the header here
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        destination = parts[1]
                        if destination == '00000000':  # Default route
                            # Gateway is in hex, little-endian
                            gateway_hex = parts[2]
                            # Convert to IP address
                            gateway_ip = '.'.join([
                                str(int(gateway_hex[6:8], 16)),
                                str(int(gateway_hex[4:6], 16)),
                                str(int(gateway_hex[2:4], 16)),
                                str(int(gateway_hex[0:2], 16))
                            ])
                            break
        
        # Try ip command with -j (json output) if available
        if not gateway_ip and shutil.which('ip'):
            try:
                # Try with JSON output
                output = subprocess.check_output(["ip", "-j", "route", "show", "default"], 
                                              stderr=subprocess.DEVNULL).decode().strip()
                routes = json.loads(output)
                if routes and len(routes) > 0 and 'gateway' in routes[0]:
                    gateway_ip = routes[0]['gateway']
            except (subprocess.CalledProcessError, json.JSONDecodeError, IndexError):
                # Last try
                output = subprocess.check_output(["ip", "route", "show", "default"], 
                                              stderr=subprocess.DEVNULL).decode().strip()
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
                if match:
                    gateway_ip = match.group(1)
        
        if not gateway_ip:
            return None, None
        
        # Get the gateway's MAC address from ARP cache
        gateway_mac = None
        if os.path.exists('/proc/net/arp'):
            with open('/proc/net/arp', 'r') as arp_file:
                for line in arp_file.readlines()[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] == gateway_ip:
                        gateway_mac = parts[3]
                        break
        
        # If it doesn't work, we'll use the arp command
        if not gateway_mac and shutil.which('arp'):
            try:
                arp_output = subprocess.check_output(["arp", "-n", gateway_ip], 
                                                  stderr=subprocess.DEVNULL).decode().strip()
                match = re.search(r'(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', arp_output)
                if match:
                    gateway_mac = match.group(1)
            except subprocess.CalledProcessError:
                pass
        
        if not gateway_mac:
            gateway_mac = "MAC address not available"
            
        return gateway_ip, gateway_mac
    except Exception as e:
        print(f"Linux gateway detection error: {e}")
        return None, None

def get_default_gateway_windows():
    """Get the default gateway and its MAC address on Windows"""
    try:
        gateway_ip = None
        
        # Try PowerShell
        if shutil.which('powershell'):
            try:
                # Trying with .NET Classes
                ps_cmd = "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"
                output = subprocess.check_output(["powershell", "-Command", ps_cmd], 
                                              stderr=subprocess.DEVNULL).decode().strip()
                if output:
                    gateway_ip = output
            except subprocess.CalledProcessError:
                pass
        
        # If it doesn't work, we'll try with netstat
        if not gateway_ip and shutil.which('netstat'):
            try:
                output = subprocess.check_output(["netstat", "-rn"], 
                                              stderr=subprocess.DEVNULL).decode()
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    if '0.0.0.0' in line and '0.0.0.0' not in lines[i-1]:
                        # Extracting the IP pattern from the line
                        match = re.search(r'0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            gateway_ip = match.group(1)
                            break
            except subprocess.CalledProcessError:
                pass
        
        if not gateway_ip:
            return None, None
        
        # Get MAC address using PowerShell
        gateway_mac = None
        if shutil.which('powershell'):
            try:
                # Get ARP table
                ps_cmd = f"Get-NetNeighbor -IPAddress '{gateway_ip}' | Select-Object -ExpandProperty LinkLayerAddress"
                output = subprocess.check_output(["powershell", "-Command", ps_cmd], 
                                              stderr=subprocess.DEVNULL).decode().strip()
                if output:
                    # Format might be different, so we will convert to standard MAC format
                    gateway_mac = ':'.join([output[i:i+2] for i in range(0, len(output), 2)])
            except subprocess.CalledProcessError:
                pass
        
        # If not then we will go back to using arp command
        if not gateway_mac and shutil.which('arp'):
            try:
                arp_output = subprocess.check_output(["arp", "-a", gateway_ip], 
                                                  stderr=subprocess.DEVNULL).decode()
                match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', arp_output)
                if match:
                    gateway_mac = match.group(1)
            except subprocess.CalledProcessError:
                pass
        
        if not gateway_mac:
            gateway_mac = "MAC address not available"
            
        return gateway_ip, gateway_mac
    except Exception as e:
        print(f"Windows gateway detection error: {e}")
        return None, None

def get_default_gateway_macos():
    """Get the default gateway and its MAC address on macOS."""
    try:
        gateway_ip = None
        
        # We try first by using netstat 
        if shutil.which('netstat'):
            try:
                output = subprocess.check_output(["netstat", "-nr"], 
                                              stderr=subprocess.DEVNULL).decode()
                lines = output.split('\n')
                for line in lines:
                    if 'default' in line:
                        parts = line.strip().split()
                        for part in parts:
                            if re.match(r'^\d+\.\d+\.\d+\.\d+$', part):
                                gateway_ip = part
                                break
                        if gateway_ip:
                            break
            except subprocess.CalledProcessError:
                pass
        
        # If it doesn't, we go back to route get command
        if not gateway_ip and shutil.which('route'):
            try:
                # We'll use -n flag for numeric output and grep for 'gateway'
                output = subprocess.check_output(["route", "-n", "get", "default"], 
                                              stderr=subprocess.DEVNULL).decode()
                # Looking for any IP address after 'gateway:'
                match = re.search(r'gateway:\s*(\d+\.\d+\.\d+\.\d+)', output)
                if match:
                    gateway_ip = match.group(1)
            except subprocess.CalledProcessError:
                pass
        
        if not gateway_ip:
            return None, None
        
        # Getting gateway MAC using arp command
        gateway_mac = None
        if shutil.which('arp'):
            try:
                arp_output = subprocess.check_output(["arp", "-n", gateway_ip], 
                                                  stderr=subprocess.DEVNULL).decode()
                match = re.search(r'(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', arp_output)
                if match:
                    gateway_mac = match.group(1)
            except subprocess.CalledProcessError:
                pass
        
        if not gateway_mac:
            gateway_mac = "MAC address not available"
            
        return gateway_ip, gateway_mac
    except Exception as e:
        print(f"macOS gateway detection error: {e}")
        return None, None

def get_default_gateway_mac():
    """Get the default gateway and its MAC address based on the OS."""
    system = platform.system()
    
    if system == "Windows": # For Windows
        return get_default_gateway_windows()
    elif system == "Darwin":  # For macOS
        return get_default_gateway_macos()
    else:  # For Linux and other Unix-like systems
        return get_default_gateway_linux()

# def get_ip_addresses():
    """Get all IP addresses on the system (language-independent)."""
    system = platform.system()
    addresses = []
    
    # Using socket to get all network interfaces
    try:
        # We will first try using socket module to get the addresses
        import socket
        import fcntl
        import struct
        import array
        
        if system != "Windows":  # For Unix-like systems
            try:
                max_possible = 128  # Number is arbitrary. we'll have to raise if needed.
                bytes = max_possible * 32
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                names = array.array('B', b'\0' * bytes)
                outbytes = struct.unpack('iL', fcntl.ioctl(
                    s.fileno(),
                    0x8912, 
                    struct.pack('iL', bytes, names.buffer_info()[0])
                ))[0]
                namestr = names.tobytes()
                
                for i in range(0, outbytes, 40):
                    name = namestr[i:i+16].split(b'\0', 1)[0]
                    if name != b'lo':  # Skipping the loopback
                        ip = socket.inet_ntoa(namestr[i+20:i+24])
                        if ip != '127.0.0.1':
                            addresses.append(ip)
            except (ImportError, IOError, AttributeError):
                pass
    except ImportError:
        pass
    
    # Else we can use these methods (one for each OS)
    try:
        if system == "Darwin":  # macOS
            if shutil.which('ifconfig'):
                output = subprocess.check_output(["ifconfig"], 
                                             stderr=subprocess.DEVNULL).decode()
                for line in output.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            addresses.append(match.group(1))
        elif system == "Windows":
            if shutil.which('powershell'):
                # Using PowerShell to get IP addresses
                ps_cmd = "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress"
                output = subprocess.check_output(["powershell", "-Command", ps_cmd], 
                                              stderr=subprocess.DEVNULL).decode()
                for line in output.split('\n'):
                    ip = line.strip()
                    if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        addresses.append(ip)
            else:
                # If not then we'll rely on ipconfig parsing but with IP pattern matching
                output = subprocess.check_output(["ipconfig"], 
                                               stderr=subprocess.DEVNULL).decode()
                for line in output.split('\n'):
                    # Looking for IPv4 pattern instead
                    match = re.search(r'IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match and '127.0.0.1' not in match.group(1):
                        addresses.append(match.group(1))
        else:  # Linux
            # Try using /proc/net/fib_trie
            if os.path.exists('/proc/net/fib_trie'):
                with open('/proc/net/fib_trie', 'r') as f:
                    content = f.read()
                    # Extract all IPs
                    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                    for ip in ips:
                        if ip != '127.0.0.1' and not ip.endswith('.0') and not ip.endswith('.255'):
                            addresses.append(ip)
            # if it doesn't work, we can just ip command with JSON output
            elif shutil.which('ip'):
                try:
                    # Try with JSON output
                    output = subprocess.check_output(["ip", "-j", "addr", "show"], 
                                                  stderr=subprocess.DEVNULL).decode()
                    interfaces = json.loads(output)
                    for interface in interfaces:
                        if 'addr_info' in interface:
                            for addr in interface['addr_info']:
                                if 'family' in addr and addr['family'] == 'inet' and 'local' in addr:
                                    if addr['local'] != '127.0.0.1':
                                        addresses.append(addr['local'])
                except (subprocess.CalledProcessError, json.JSONDecodeError):
                    # Or just regular ip command with pattern matching
                    output = subprocess.check_output(["ip", "addr", "show"], 
                                                  stderr=subprocess.DEVNULL).decode()
                    for line in output.split('\n'):
                        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                        if match and '127.0.0.1' not in match.group(1):
                            addresses.append(match.group(1))
    except subprocess.CalledProcessError:
        pass
    
    #Removing duplicates
    return list(set(addresses))

def get_all_network_info():
    # system = platform.system()
    hostname, ip_address = get_hostname_ip()
    # all_ips = get_ip_addresses()
    mac_address = get_mac_address()
    gateway_ip, gateway_mac = get_default_gateway_mac()

    """Print all network information"""
    # print(f"Operating System: {system}")
    print(f"Hostname: {hostname}")
    print(f"Primary IP Address: {ip_address}")    
    # if all_ips:
    #     print("All IP Addresses:")
    #     for ip in all_ips:
    #         print(f"  {ip}")
    network_info={
      "Host name":hostname if hostname else "N/A",
      "Host IP Address":ip_address if ip_address else "N/A",
      "Mac Address":mac_address if mac_address else "N/A",
      "Default Gateway IP": gateway_ip if gateway_ip else "N/A",
      "Default Gateway MAC": gateway_mac if gateway_mac else "N/A",
    }
    return network_info




def get_frequency_band(frequency):
    frequency_mhz = frequency / 1_000_000
    return "2.4 GHz" if frequency_mhz < 3000 else "5 GHz"

def get_security_type(akm):
    if const.AKM_TYPE_WPA2PSK in akm:
        return "WPA2"
    elif const.AKM_TYPE_WPAPSK in akm:
        return "WPA"
    elif const.AKM_TYPE_NONE in akm:
        return "Open"
    return "Unknown"

def scan_networks():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)  # Allow time for scanning
    results = iface.scan_results()
    
    networks = []
    for network in results:
        band = get_frequency_band(network.freq)
        security = get_security_type(network.akm)
        networks.append({
            "SSID": network.ssid,
            "Signal Strength": network.signal,
            "Security": security,
            "Band": band
        })
    return networks

def display_current_network():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    if iface.status() != const.IFACE_CONNECTED:
        return "No active Wi-Fi connection."

    scan_results = iface.scan_results()
    current_ssid = None

    for network in scan_results:
        if network.ssid:
            current_ssid = network.ssid
            break

    if not current_ssid:
        return "Connected, but SSID not found."

    for network in scan_results:
        if network.ssid == current_ssid:
            return {
                "SSID": network.ssid,
                "Signal Strength": network.signal,
                "Security": get_security_type(network.akm),
                "Band": get_frequency_band(network.freq)
            }

    return "Current network details not found in scan results."
  
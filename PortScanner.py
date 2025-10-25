"""Brennen McKenna

   Port Scanner Module

   Cyb: 333

    Date: 10/23/2025
"""

import socket

import subprocess

import sys

import time

import shutil

import traceback

"""Global modifiers"""

DEFAULT_TARGET = None

DEFAULT_PORTS = "1-1024"

default_timeout = 20

"""Functions"""

"""Parse ports from a string like "22,80,443,1000-2000" into a list of integers"""

def ports(ports_str):

    ports = []

    if not ports_str:

        return ports

    """Split by commas to handle individual ports and ranges"""

    parts = ports_str.split(',')

    """Process each part"""
   
    for p in parts:
   
        p = p.strip()
   
        if not p:
   
            continue
   
        if '-' in p:
   
            a, b = p.split('-', 1)
   
            a = int(a.strip()); b = int(b.strip())
   
            ports.extend(range(a, b + 1))
   
        else:
   
            ports.append(int(p))

    """"Remove duplicates and sort the ports"""
   
    ports = sorted(set(ports))
   
    return ports


"""Attempt to connect to a specific port on a host"""

def port_socket(host, port, timeout=1):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.settimeout(timeout)

    try:

        s.connect((host, int(port)))

        try:

            s.close()

        except Exception:

            pass

        return True
    
    except (socket.timeout, socket.error, OSError):
    
        try:
    
            s.close()
    
        except Exception:
    
            pass
    
        return False


"""Scan multiple ports on a host"""

def port_scan(host, ports, timeout=1):
    
    open_ports = []
    
    for port in ports:
    
        try:
    
            if port_socket(host, port, timeout):
    
                open_ports.append(port)
    
        except Exception:
        
            try:
    
                pass
    
            except Exception:
    
                pass
    
    return open_ports


"""Attempt to grab a banner from a specific port on a host"""

def grab_ports(host, port, timeout=1, recv_bytes=1024):
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    s.settimeout(timeout)
    
    try:
    
        s.connect((host, int(port)))
    
        try:
    
            data = s.recv(recv_bytes)
    
            if not data:
    
                return None
    
            return data.decode('utf-8', errors='ignore').strip()
    
        except Exception:
    
            return None
    
        finally:
    
            try:
    
                s.close()
    
            except Exception:
    
                pass
    
    except Exception:
    
        try:
    
            s.close()
    
        except Exception:
    
            pass
    
        return None


"""Quick scan function with timing"""

def quick(host, ports_list):

    print(f"Starting quick scan on {host}...")

    start_time = time.time()

    open_ports = port_scan(host, ports_list, timeout=0.5)

    end_time = time.time()

    print(f"Quick scan completed in {end_time - start_time:.2f} seconds.")

    if open_ports:

        print(f"Open ports on {host}: {', '.join(map(str, open_ports))}")

    else:

        print(f"No open ports found on {host}.")


def NMAP_run(host, open_ports, extra_args=None):

    if not open_ports:

        print("No open ports to scan with NMAP.")

        return None

    if not shutil.which("nmap"):

        print("NMAP is not installed or not found in PATH.")

        return None

    if extra_args is None:

        extra_args = []

    """ ensure proper nmap script argument if user passed a simple flag """

    normalized_args = []

    for a in extra_args:

        if a == "--script-vuln":

            normalized_args.append("--script=vuln")

        else:

            normalized_args.append(a)

    ports_arg = ','.join(map(str, open_ports))

    cmd = ["nmap", "-sV", "-p", ports_arg] + normalized_args + ["-Pn", host]

    print(f"Running NMAP command: {' '.join(cmd)}")

    try:

        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)

        print(proc.stdout)

        return proc.stdout

    except subprocess.CalledProcessError as e:

        print(f"Error running NMAP: {e}")

        if e.stdout:

            print("nmap result: ", e.stdout)

        return None

    except Exception as e:

        print("Unexpected error running nmap:", e)

        return None

"""Main function to handle user input and run scans"""

def main():

    target = DEFAULT_TARGET

    ports_str = DEFAULT_PORTS

    extra_nmap_args = []

    if len(sys.argv) > 1:

        for i in range(1, len(sys.argv)):

            arg = sys.argv[i]

            if arg.startswith("--target="):

                target = arg.split("=", 1)[1]

            elif arg.startswith("--ports="):

                ports_str = arg.split("=", 1)[1]

            elif arg.startswith("--script-vuln"):

                extra_nmap_args.append("--script-vuln")

            elif arg.startswith("--script="):

                extra_nmap_args.append(arg)

    if not target:

        try:

            target = input("Enter target IP or hostname: ").strip()

        except Exception:

            print("No target provided. Exiting.")

            return

    """ Prompt user for custom ports if default is set """

    if ports_str == DEFAULT_PORTS:

        try:

            want_custom = input(f"Use default ports ({DEFAULT_PORTS})? Type 'y' to use default, 'n' to enter custom ports: ").strip().lower()

            if want_custom in ("n", "no"):

                ports_input = input("Enter ports to scan (e.g. 22,80,443 or 1-1024): ").strip()

                if ports_input:

                    ports_str = ports_input

        except Exception:

            pass

    print("Scanning target:", target)

    print("Ports: ", ports_str)

    """Ports"""

    ports_list = ports(ports_str)

    if not ports_list:

        print("No valid ports specified.")

        return

    """Perform the port scan"""

    open_ports = port_scan(target, ports_list, timeout=1)

    """Display results"""

    if open_ports:

        print(f"Open ports on {target}: {', '.join(map(str, open_ports))}")

        """Attempt to grab banners from open ports"""

        for p in open_ports:
        
            try:
        
                b = grab_ports(target, p, timeout=0.6, recv_bytes=512)
        
                if b:
        
                    first_line = b.splitlines()[0] if b.splitlines() else b
        
                    print(f"  banner on {p}: {first_line}")
        
            except Exception:
        
                pass

        """If nmap is available, run a service scan on the open ports"""
        
        NMAP_run(target, open_ports, extra_args=extra_nmap_args)
    
    else:
    
        print(f"No open ports found on {target}.")

    print("Scan complete.")

"""Help function to display usage"""

def help():

    print("")

    print("Simple Port Scanner")

    print("Usage: python PortScanner.py [--target=<target>] [--ports=<ports>] [--script-vuln] [--script=vuln]")

    print("")

    print("You can edit the ports at the top of the script.")

    print("If nmap is installed, it will run an nmap service scan on the open ports found.")

    print("")

    print("DISCLAIMER: Use this tool only on systems you own or have permission to test. We are not responsible for any misuse.")

"""Entry point"""

if __name__ == "__main__":

    try:

        if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):

            help()

            sys.exit(0)

        main()

    except KeyboardInterrupt:

        print("\nUser aborted (CTRL+C). Exiting.")

    except Exception as e:

        print("Error:", e)

        traceback.print_exc()
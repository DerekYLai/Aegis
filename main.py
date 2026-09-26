import hashlib
import json
import platform
import socket
import psutil
import os
from datetime import datetime

findings = []


def add_finding(finding):
    if finding not in findings:
        findings.append(finding)

def get_system_info():
    print("\n" + "=" * 50)
    print("SYSTEM INFORMATION")
    print("=" * 50)

    print(f"Operating System : {platform.system()} {platform.release()}")
    print(f"OS Version       : {platform.version()}")
    print(f"Computer Name    : {socket.gethostname()}")
    print(f"Processor        : {platform.processor()}")

    print(
        f"CPU Cores        : {psutil.cpu_count(logical=False)} physical / "
        f"{psutil.cpu_count(logical=True)} logical"
    )

    memory = psutil.virtual_memory()

    print(f"Total RAM        : {memory.total / (1024 ** 3):.2f} GB")
    print(f"RAM Usage        : {memory.percent}%")

    disk = psutil.disk_usage(os.path.abspath(os.sep))

    print(f"Disk Total       : {disk.total / (1024 ** 3):.2f} GB")
    print(f"Disk Used        : {disk.percent}%")

    try:
        print(f"Current User     : {os.getlogin()}")
    except OSError:
        print(f"Current User     : {os.environ.get('USERNAME', 'Unknown')}")

    print(f"Scan Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def get_processes():
    print("\nPROCESS SECURITY ANALYSIS")
    print("=" * 100)

    print(
        f"{'PID':<8}"
        f"{'PROCESS':<25}"
        f"{'CPU %':<10}"
        f"{'RAM %':<10}"
        f"{'RISK':<15}"
        f"{'PATH':<35}"
    )

    print("-" * 100)

    for process in psutil.process_iter(
        ['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']
    ):
        try:
            pid = process.info['pid']
            name = process.info['name'] or "Unknown"
            cpu = process.info['cpu_percent'] or 0
            memory = process.info['memory_percent'] or 0
            path = process.info['exe']

            risk = "Normal"

            # High CPU usage
            if cpu > 80:
                risk = "Review"

                findings.append({
                    "type": "Process",
                    "issue": f"High CPU usage detected: {name}",
                    "severity": "MEDIUM",
                    "details": f"Process {pid} is using {cpu:.1f}% CPU."
                })

            # High memory usage
            elif memory > 20:
                risk = "Review"

                findings.append({
                    "type": "Process",
                    "issue": f"High memory usage detected: {name}",
                    "severity": "MEDIUM",
                    "details": f"Process {pid} is using {memory:.1f}% memory."
                })

            # Process running from temporary folder
            if path and (
                "\\temp\\" in path.lower()
                or "\\tmp\\" in path.lower()
            ):
                risk = "Suspicious"

                findings.append({
                    "type": "Process",
                    "issue": f"Process running from temporary directory: {name}",
                    "severity": "HIGH",
                    "details": f"Executable path: {path}"
                })

            print(
                f"{pid:<8}"
                f"{str(name)[:24]:<25}"
                f"{cpu:<10.1f}"
                f"{memory:<10.1f}"
                f"{risk:<15}"
                f"{str(path)[:34]:<35}"
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print("\nProcess analysis complete.")

def security_scan():
    print("\nSECURITY SCAN")
    print("=" * 50)

    # -----------------------------
    # Firewall Check
    # -----------------------------

    print("\n[1] Checking Windows Firewall...")

    firewall_command = (
        'powershell -Command "'
        'Get-NetFirewallProfile | '
        'Select-Object Name, Enabled | '
        'ConvertTo-Json"'
    )

    firewall_result = os.popen(firewall_command).read()

    if "False" in firewall_result:
        print("WARNING: A firewall profile may be disabled.")

        findings.append({
            "type": "Firewall",
            "issue": "A Windows Firewall profile may be disabled",
            "severity": "HIGH",
            "details": "Check Windows Firewall settings."
        })

    else:
        print("Firewall appears to be enabled.")

    # -----------------------------
    # Windows Defender Check
    # -----------------------------

    print("\n[2] Checking Windows Defender...")

    defender_command = (
        'powershell -Command "'
        'Get-MpComputerStatus | '
        'Select-Object AntivirusEnabled, RealTimeProtectionEnabled | '
        'ConvertTo-Json"'
    )

    defender_result = os.popen(defender_command).read()

    if '"AntivirusEnabled": false' in defender_result:
        print("WARNING: Windows Defender antivirus is disabled.")

        findings.append({
            "type": "Antivirus",
            "issue": "Windows Defender antivirus is disabled",
            "severity": "HIGH",
            "details": "Enable Windows Defender antivirus protection."
        })

    elif '"RealTimeProtectionEnabled": false' in defender_result:
        print("WARNING: Real-time protection is disabled.")

        findings.append({
            "type": "Antivirus",
            "issue": "Windows Defender real-time protection is disabled",
            "severity": "HIGH",
            "details": "Enable real-time protection."
        })

    else:
        print("Windows Defender appears to be enabled.")

    print("\nSecurity scan complete.")

def network_scan():
    print("\nNETWORK SECURITY SCAN")
    print("=" * 70)

    review_ports = {
        21: "FTP",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC"
    }

    found = False

    print(
        f"{'PORT':<10}"
        f"{'ADDRESS':<20}"
        f"{'PROCESS':<25}"
        f"{'RISK':<10}"
    )

    print("-" * 70)

    for connection in psutil.net_connections(kind="inet"):
        try:
            if connection.status == psutil.CONN_LISTEN:

                port = connection.laddr.port
                address = connection.laddr.ip

                process_name = "Unknown"

                if connection.pid:
                    try:
                        process_name = psutil.Process(
                            connection.pid
                        ).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                risk = "Normal"

                if port in review_ports:
                    risk = "Review"
                    found = True

                    findings.append({
                        "type": "Network",
                        "issue": f"Port {port} ({review_ports[port]}) is listening",
                        "severity": "MEDIUM",
                        "details": f"Process: {process_name}, Address: {address}"
                    })

                print(
                    f"{port:<10}"
                    f"{address:<20}"
                    f"{process_name:<25}"
                    f"{risk:<10}"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not found:
        print("\nNo review-level ports detected.")

    print("\nNetwork scan complete.\n")
def show_findings():
    print("\nAEGIS SECURITY FINDINGS")
    print("=" * 50)

    if not findings:
        print("No security findings detected.")
        return

    for number, finding in enumerate(findings, start=1):
        print(f"\nFinding #{number}")
        print(f"Type: {finding['type']}")
        print(f"Issue: {finding['issue']}")
        print(f"Severity: {finding['severity']}")
        print(f"Details: {finding['details']}")

def malware_scan():
    print("\nMALWARE SIGNATURE SCAN")
    print("=" * 60)

    signature_file = os.path.join(
        os.path.dirname(__file__),
        "signatures",
        "signatures.json"
    )

    try:
        with open(signature_file, "r") as file:
            signatures = json.load(file)

    except FileNotFoundError:
        print("\nERROR: Signature database not found.")
        print(f"Expected location: {signature_file}")
        return

    scan_locations = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop")
    ]

    files_scanned = 0
    threats_found = 0

    for folder in scan_locations:

        if not os.path.exists(folder):
            continue

        print(f"\nScanning: {folder}")

        for root, directories, files in os.walk(folder):

            for filename in files:

                file_path = os.path.join(root, filename)

                try:
                    sha256 = hashlib.sha256()

                    with open(file_path, "rb") as file:
                        while chunk := file.read(4096):
                            sha256.update(chunk)

                    file_hash = sha256.hexdigest()

                    files_scanned += 1

                    if file_hash in signatures:

                        threats_found += 1

                        signature = signatures[file_hash]

                        print("\nWARNING: Signature match detected")
                        print(f"File: {file_path}")
                        print(f"Name: {signature['name']}")
                        print(f"Severity: {signature['severity']}")
                        print(f"Description: {signature['description']}")

                        findings.append({
                            "type": "Malware",
                            "issue": f"Signature match detected: {filename}",
                            "severity": signature["severity"],
                            "details": (
                                f"File: {file_path}, "
                                f"SHA-256: {file_hash}, "
                                f"Description: {signature['description']}"
                            )
                        })

                except (PermissionError, OSError):
                    continue

    print("\n" + "-" * 60)
    print(f"Files scanned: {files_scanned}")
    print(f"Potential threats: {threats_found}")

    if threats_found == 0:
        print("No known signature matches detected.")

    print("\nMalware scan complete.")


def main():
    while True:
        print("\nAEGIS")
        print("[1] System Information")
        print("[2] Process Analysis")
        print("[3] Security Scan")
        print("[4] Network Scan")
        print("[5] Malware Scan")
        print("[6] Show Findings")
        print("[7] Exit")

        choice = input("\nSelect an option: ")

        print("YOU ENTERED:", repr(choice))

        if choice == "1":
            get_system_info()

        elif choice == "2":
            get_processes()

        elif choice == "3":
            security_scan()

        elif choice == "4":
            network_scan()

        elif choice == "5":
            malware_scan()

        elif choice == "6":
            show_findings()

        elif choice == "7":
            print("SEVEN")
            break

        else:
            print("INVALID OPTION")


if __name__ == "__main__":
    main()

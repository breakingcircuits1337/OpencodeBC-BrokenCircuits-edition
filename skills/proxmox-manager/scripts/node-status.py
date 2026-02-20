#!/home/sarah/.venvs/base/bin/python3
"""
Check Proxmox Node Status and Resources
Usage: python3 node-status.py
"""

import sys
import os
from proxmoxer import ProxmoxAPI

# Configuration
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.1.115")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASS = os.getenv("PROXMOX_PASS", "")

def format_bytes(bytes_val):
    """Format bytes to human readable."""
    if bytes_val == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"

def check_status():
    """Check node status and resources."""
    
    if not PROXMOX_PASS:
        print("❌ Error: PROXMOX_PASS environment variable not set")
        print("   Set it with: export PROXMOX_PASS='your-password'")
        sys.exit(1)
    
    try:
        proxmox = ProxmoxAPI(
            PROXMOX_HOST,
            user=PROXMOX_USER,
            password=PROXMOX_PASS,
            verify_ssl=False,
            port=int(PROXMOX_PORT)
        )
        
        print("📊 Proxmox Node Status")
        print("=" * 70)
        print()
        
        # Get version info
        version = proxmox.version.get()
        print(f"Proxmox Version: {version.get('version', 'Unknown')}")
        print(f"Server: {PROXMOX_HOST}")
        print()
        
        # Check each node
        for node in proxmox.nodes.get():
            node_name = node['node']
            print(f"🖥️  Node: {node_name}")
            print("-" * 70)
            
            # Get status
            try:
                status = proxmox.nodes(node_name).status.get()
                
                # CPU Info
                cpu_info = status.get('cpuinfo', {})
                cpu_cores = cpu_info.get('cores', 'N/A')
                cpu_model = cpu_info.get('model', 'Unknown')[:40]
                print(f"   CPU: {cpu_model}")
                print(f"   Cores: {cpu_cores}")
                
                # Memory
                memory = status.get('memory', {})
                mem_total = memory.get('total', 0)
                mem_used = memory.get('used', 0)
                mem_free = memory.get('free', 0)
                mem_percent = (mem_used / mem_total * 100) if mem_total > 0 else 0
                
                print(f"\n   💾 Memory:")
                print(f"      Total: {format_bytes(mem_total)}")
                print(f"      Used:  {format_bytes(mem_used)} ({mem_percent:.1f}%)")
                print(f"      Free:  {format_bytes(mem_free)}")
                
                # CPU Usage
                cpu_usage = status.get('cpu', 0) * 100
                print(f"\n   ⚡ CPU Usage: {cpu_usage:.1f}%")
                
                # Uptime
                uptime = status.get('uptime', 0)
                days = uptime // 86400
                hours = (uptime % 86400) // 3600
                minutes = (uptime % 3600) // 60
                print(f"\n   ⏱️  Uptime: {days}d {hours}h {minutes}m")
                
                # Load average
                loadavg = status.get('loadavg', ['N/A', 'N/A', 'N/A'])
                print(f"   Load Average: {loadavg[0]}, {loadavg[1]}, {loadavg[2]}")
                
            except Exception as e:
                print(f"   ❌ Could not get status: {e}")
            
            # Get storage info
            print(f"\n   💿 Storage:")
            try:
                storage_list = proxmox.nodes(node_name).storage.get()
                for storage in storage_list:
                    if storage.get('type') != 'dir' or storage.get('shared') == 1:
                        continue
                    
                    storage_name = storage.get('storage', 'Unknown')
                    total = storage.get('total', 0)
                    used = storage.get('used', 0)
                    avail = storage.get('avail', 0)
                    
                    if total > 0:
                        percent = (used / total * 100)
                        print(f"      {storage_name:<15} {format_bytes(used):>10} / {format_bytes(total):<10} ({percent:.1f}%)")
            except Exception as e:
                print(f"      Could not get storage info: {e}")
            
            print()
        
        print("=" * 70)
        print("\n🌐 Web Interface: https://192.168.1.115:8006")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    check_status()

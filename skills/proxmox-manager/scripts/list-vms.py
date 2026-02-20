#!/usr/bin/env python3
"""
List all VMs and Containers on Proxmox
Usage: python3 list-vms.py
"""

import sys
import os
from proxmoxer import ProxmoxAPI

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.1.115")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASS = os.getenv("PROXMOX_PASS", "")

def list_vms():
    """List all VMs and containers."""
    
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
        
        print("🖥️  Virtual Machines & Containers")
        print("=" * 60)
        print()
        
        for node in proxmox.nodes.get():
            node_name = node['node']
            print(f"📍 Node: {node_name}")
            print("-" * 60)
            
            vms = proxmox.nodes(node_name).qemu.get()
            if vms:
                print(f"\n   Virtual Machines ({len(vms)}):")
                print(f"   {'VMID':<8} {'Name':<20} {'Status':<10} {'CPU':<6} {'Memory':<10}")
                print(f"   {'-'*60}")
                for vm in vms:
                    vmid = vm.get('vmid', 'N/A')
                    name = vm.get('name', 'unnamed')[:18]
                    status = vm.get('status', 'unknown')
                    cpu = f"{vm.get('cpu', 0)*100:.1f}%" if 'cpu' in vm else 'N/A'
                    mem = f"{vm.get('mem', 0)/1024/1024/1024:.1f}GB" if 'mem' in vm else 'N/A'
                    
                    status_icon = "🟢" if status == "running" else "🔴"
                    print(f"   {vmid:<8} {name:<20} {status_icon} {status:<8} {cpu:<6} {mem:<10}")
            
            containers = proxmox.nodes(node_name).lxc.get()
            if containers:
                print(f"\n   Containers ({len(containers)}):")
                print(f"   {'VMID':<8} {'Name':<20} {'Status':<10}")
                print(f"   {'-'*60}")
                for ct in containers:
                    vmid = ct.get('vmid', 'N/A')
                    name = ct.get('name', 'unnamed')[:18]
                    status = ct.get('status', 'unknown')
                    status_icon = "🟢" if status == "running" else "🔴"
                    print(f"   {vmid:<8} {name:<20} {status_icon} {status:<8}")
            
            if not vms and not containers:
                print("   No VMs or containers found")
            
            print()
        
        print("=" * 60)
        print("\nLegend: 🟢 Running | 🔴 Stopped")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    list_vms()

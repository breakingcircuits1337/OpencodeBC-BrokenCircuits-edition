#!/home/sarah/.venvs/base/bin/python3
"""
Proxmox Connection Test - Verify connectivity to Dell R720 XD
Usage: python3 test-connection.py
"""

import sys
import os
from proxmoxer import ProxmoxAPI

# Configuration
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.1.115")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASS = os.getenv("PROXMOX_PASS", "")

def test_connection():
    """Test connection to Proxmox server."""
    
    if not PROXMOX_PASS:
        print("❌ Error: PROXMOX_PASS environment variable not set")
        print("   Set it with: export PROXMOX_PASS='your-password'")
        sys.exit(1)
    
    try:
        print(f"🔌 Connecting to Proxmox at {PROXMOX_HOST}:{PROXMOX_PORT}...")
        
        # Connect to Proxmox
        proxmox = ProxmoxAPI(
            PROXMOX_HOST,
            user=PROXMOX_USER,
            password=PROXMOX_PASS,
            verify_ssl=False,  # For local/self-signed certs
            port=int(PROXMOX_PORT)
        )
        
        # Test connection by getting version
        version = proxmox.version.get()
        
        print("✅ Successfully connected to Proxmox!")
        print(f"   Version: {version.get('version', 'Unknown')}")
        print(f"   Host: {PROXMOX_HOST}")
        print(f"   User: {PROXMOX_USER}")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\nTroubleshooting:")
        print("   - Verify Proxmox is running: https://192.168.1.115:8006")
        print("   - Check username/password")
        print("   - Ensure firewall allows connections")
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)

#!/home/sarah/.venvs/base/bin/python3
"""
Proxmox Connection Test - Verify connectivity to Dell R720 XD
Usage: python3 test-connection.py

Supports both:
- Password auth: PROXMOX_PASS
- API token: PROXMOX_TOKEN_SECRET (preferred)
"""

import sys
import os
from proxmoxer import ProxmoxAPI

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.1.115")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "sarah@pam")
PROXMOX_PASS = os.getenv("PROXMOX_PASS", "")
PROXMOX_TOKEN_SECRET = os.getenv("PROXMOX_TOKEN_SECRET", "")

def test_connection():
    """Test connection to Proxmox server."""
    
    if not PROXMOX_PASS and not PROXMOX_TOKEN_SECRET:
        print("❌ Error: No authentication method set")
        print("   Set password:  export PROXMOX_PASS='password'")
        print("   Or token:     export PROXMOX_TOKEN_SECRET='token'")
        sys.exit(1)
    
    try:
        print(f"🔌 Connecting to Proxmox at {PROXMOX_HOST}:{PROXMOX_PORT}...")
        
        # Try API token first (preferred method)
        if PROXMOX_TOKEN_SECRET:
            # proxmoxer 2.x uses password field for token with special prefix
            token_id = os.getenv("PROXMOX_TOKEN_ID", "sarah@pam@pam")
            proxmox = ProxmoxAPI(
                PROXMOX_HOST,
                user=PROXMOX_USER,
                password=f"PVEAPIToken={token_id}={PROXMOX_TOKEN_SECRET}",
                verify_ssl=False,
                port=int(PROXMOX_PORT)
            )
            auth_method = "API Token"
        else:
            # Fallback to password
            proxmox = ProxmoxAPI(
                PROXMOX_HOST,
                user=PROXMOX_USER,
                password=PROXMOX_PASS,
                verify_ssl=False,
                port=int(PROXMOX_PORT)
            )
            auth_method = "Password"
        
        version = proxmox.version.get()
        
        print("✅ Successfully connected to Proxmox!")
        print(f"   Version: {version.get('version', 'Unknown')}")
        print(f"   Host: {PROXMOX_HOST}")
        print(f"   User: {PROXMOX_USER}")
        print(f"   Auth: {auth_method}")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        
        if "Authentication" in str(e):
            print("\nTroubleshooting:")
            print("   - Verify user exists in Proxmox")
            print("   - Check password/token is correct")
            print("   - Ensure user has permissions (Datacenter > Permissions)")
        
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)

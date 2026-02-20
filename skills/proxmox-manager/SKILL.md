---
name: proxmox-manager
description: Manage Proxmox VE virtualization platform on Dell PowerEdge R720 XD. Use when connecting to Proxmox server at 192.168.1.115:8006, listing VMs/containers, checking node status, managing virtual machines, or monitoring server resources.
---

# Proxmox VE Manager

Manage your Dell PowerEdge R720 XD virtualization server running Proxmox VE.

## Server Information

- **Hardware:** Dell PowerEdge R720 XD
- **Proxmox IP:** 192.168.1.115:8006
- **Web Interface:** https://192.168.1.115:8006

## Credentials

| User | Password | Realm | Notes |
|------|----------|-------|-------|
| root@pam | 987654321 | pam | Full admin access |
| sarah@pam | Smartai1 | pam | Needs permissions setup |

## Prerequisites

### 1. Set Proxmox Credentials

```bash
export PROXMOX_HOST="192.168.1.115"
export PROXMOX_USER="root@pam"
export PROXMOX_PASS="987654321"
```

Add to `~/.bashrc` for persistence:
```bash
echo 'export PROXMOX_PASS="your-password"' >> ~/.bashrc
```

### 2. Install Dependencies

```bash
pip install proxmoxer requests
```

Already installed in your virtual environment at `/home/sarah/.venvs/base`

## Quick Start

### Test Connection

```bash
python3 scripts/test-connection.py
```

### List All VMs and Containers

```bash
python3 scripts/list-vms.py
```

### Check Node Status

```bash
python3 scripts/node-status.py
```

## Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `test-connection.py` | Verify Proxmox connectivity | `python3 scripts/test-connection.py` |
| `list-vms.py` | List all VMs and containers | `python3 scripts/list-vms.py` |
| `node-status.py` | Check server resources and status | `python3 scripts/node-status.py` |

## Common Tasks

### View VMs and Containers

The `list-vms.py` script shows:
- VM ID and name
- Current status (🟢 running / 🔴 stopped)
- CPU usage percentage
- Memory usage

Example output:
```
📍 Node: proxmox
------------------------------------------------------------

   Virtual Machines (3):
   VMID     Name                 Status     CPU    Memory
   ------------------------------------------------------------
   100      web-server           🟢 running  12.5%  4.2GB
   101      database             🟢 running  8.3%   8.0GB
   102      test-vm              🔴 stopped  N/A    N/A
```

### Check Server Health

The `node-status.py` script displays:
- Proxmox version
- CPU information (model, cores)
- Memory usage (total/used/free)
- CPU usage percentage
- System uptime
- Load average
- Storage usage per disk

### Access Web Interface

For full management, use the web UI:
```
https://192.168.1.115:8006
```

Login with:
- Username: `root` (or your configured user)
- Password: Your Proxmox password
- Realm: Linux PAM standard authentication

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXMOX_HOST` | 192.168.1.115 | Proxmox server IP |
| `PROXMOX_PORT` | 8006 | Proxmox API port |
| `PROXMOX_USER` | root@pam | Username with realm |
| `PROXMOX_PASS` | (required) | Your password |

### Custom Configuration

```bash
# Use different user
export PROXMOX_USER="admin@pam"

# Different port (if using proxy)
export PROXMOX_PORT="443"
```

## Proxmox CLI Commands

If you have `pvesh` or SSH access:

```bash
# List VMs
pvesh get /nodes/proxmox/qemu

# Start VM
pvesh create /nodes/proxmox/qemu/100/status/start

# Stop VM
pvesh create /nodes/proxmox/qemu/100/status/stop

# Check node status
pvesh get /nodes/proxmox/status
```

## Troubleshooting

**"Connection refused" error:**
- Verify Proxmox is running: `ping 192.168.1.115`
- Check web interface loads: https://192.168.1.115:8006
- Ensure firewall allows port 8006

**"Invalid credentials" error:**
- Verify `PROXMOX_PASS` is set correctly
- Check username format: `root@pam` not just `root`
- Try logging in via web UI to confirm password

**SSL Certificate warnings:**
- Proxmox uses self-signed certificates by default
- Scripts use `verify_ssl=False` to handle this
- For production, consider proper SSL certificates

**No VMs showing:**
- Check permissions: user needs VM.Audit permission
- Verify node name matches (default: 'proxmox')
- Check if VMs are on different nodes in cluster

## Security Notes

⚠️ **Important:**
- Never commit passwords to version control
- Use environment variables or secure vaults
- Consider creating a dedicated API user with limited permissions
- For API tokens (more secure):
  ```bash
  # Create token in Proxmox: Datacenter > Permissions > API Tokens
  export PROXMOX_TOKEN="your-token-id"
  export PROXMOX_TOKEN_SECRET="your-token-secret"
  ```

## Dell R720 XD Specifics

Your server specifications (typical R720 XD):
- **CPU:** Dual Intel Xeon E5-2600 series
- **RAM:** Up to 768GB DDR3
- **Storage:** 12x 3.5" drive bays
- **Network:** 4x Gigabit Ethernet ports
- **Remote Management:** iDRAC 7

### iDRAC Access

For hardware-level management:
```
https://192.168.1.115:443 (or different IP if configured)
```

Useful for:
- Remote console (KVM)
- Hardware health monitoring
- Power control
- Virtual media mounting

## Integration with Other Tools

### VS Code Tasks

Add to `.vscode/tasks.json`:
```json
{
  "label": "Check Proxmox Status",
  "type": "shell",
  "command": "python3 /home/sarah/skills/proxmox-manager/scripts/node-status.py",
  "problemMatcher": []
}
```

### Shell Aliases

Add to `~/.bashrc`:
```bash
alias prox-status="python3 /home/sarah/skills/proxmox-manager/scripts/node-status.py"
alias prox-vms="python3 /home/sarah/skills/proxmox-manager/scripts/list-vms.py"
```

## Useful Links

- [Proxmox Web UI](https://192.168.1.115:8006)
- [Proxmox Documentation](https://pve.proxmox.com/wiki/Main_Page)
- [Proxmoxer Python Library](https://github.com/proxmoxer/proxmoxer)
- [Dell R720 XD Manual](https://www.dell.com/support/manuals/us/en/04/poweredge-r720xd)

## Examples

### Daily Health Check

```bash
# Check server status
python3 scripts/node-status.py

# List running VMs
python3 scripts/list-vms.py | grep "🟢"

# Check for any stopped VMs that should be running
python3 scripts/list-vms.py | grep "🔴"
```

### Resource Planning

```bash
# Check current resource usage
python3 scripts/node-status.py

# Look for high CPU/memory VMs
python3 scripts/list-vms.py
```

---

*Proxmox VE Manager for Dell PowerEdge R720 XD*

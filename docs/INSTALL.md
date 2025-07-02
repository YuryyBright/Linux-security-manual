# Linux Security Toolkit - Installation Guide

## Prerequisites

### System Requirements
- **OS**: Ubuntu 22.04 LTS or Debian 11+
- **Architecture**: x86_64 (AMD64)
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: Minimum 20GB free space
- **Network**: Active internet connection
- **Access**: Root or sudo privileges

### Pre-Installation Checklist
- [ ] Backup all important data
- [ ] Verify system compatibility
- [ ] Document current network configuration
- [ ] Note down any custom configurations
- [ ] Have recovery media ready

## Installation Methods

### Method 1: Quick Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-security-toolkit.git
cd linux-security-toolkit

# Run setup with maximum security
sudo ./setup.sh --level=maximum
```

### Method 2: Step-by-Step Installation

```bash
# 1. Clone and prepare
git clone https://github.com/yourusername/linux-security-toolkit.git
cd linux-security-toolkit
chmod +x scripts/*.sh

# 2. Configure variables
cp config/variables.conf config/variables.conf.bak
nano config/variables.conf

# 3. Run individual scripts
sudo ./scripts/01_disk_encryption.sh
sudo ./scripts/02_system_hardening.sh
sudo ./scripts/03_network_security.sh
sudo ./scripts/04_anonymity.sh
sudo ./scripts/05_monitoring.sh
sudo ./scripts/06_maintenance.sh
```

### Method 3: Custom Installation

```bash
# Install only specific components
cd linux-security-toolkit

# Example: Only network security
sudo ./scripts/03_network_security.sh

# Example: Only monitoring
sudo ./scripts/05_monitoring.sh
```

## Configuration

### Essential Variables

Edit `config/variables.conf` before installation:

```bash
# Security level
SECURITY_LEVEL="maximum"  # Options: standard, enhanced, maximum

# User configuration
PRIMARY_USER="yourusername"
ADMIN_EMAIL="your.email@domain.com"

# Network settings
SSH_PORT="2222"  # Change from default 22
VPN_SERVER="your-vpn-server.com"

# Backup settings
BACKUP_DIR="/mnt/backup"
BACKUP_RETENTION_DAYS="30"
```

### Security Levels Explained

#### Standard Level
- Basic firewall rules
- SSH hardening
- Automatic updates
- Basic monitoring

#### Enhanced Level
- All Standard features plus:
- Disk encryption
- AppArmor profiles
- Network monitoring
- Fail2ban

#### Maximum Level
- All Enhanced features plus:
- Tor integration
- MAC randomization
- Anti-forensics
- Full anonymity tools

## Installation Steps

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install git
sudo apt install -y git

# Clone repository
git clone https://github.com/yourusername/linux-security-toolkit.git
```

### Step 2: Configuration

```bash
cd linux-security-toolkit

# Edit configuration
nano config/variables.conf

# Verify settings
grep "SECURITY_LEVEL\|PRIMARY_USER\|SSH_PORT" config/variables.conf
```

### Step 3: Run Installation

```bash
# Make scripts executable
chmod +x setup.sh scripts/*.sh

# Run setup
sudo ./setup.sh --level=maximum
```

### Step 4: Post-Installation

```bash
# Verify installation
sudo security-check

# Check status
sudo security-status

# Review audit
sudo security-audit
```

## Disk Encryption Setup

**Warning**: Disk encryption should be configured during OS installation for best results.

### During OS Installation
1. Choose "Encrypt the new Ubuntu installation"
2. Set a strong passphrase (20+ characters)
3. Enable LVM
4. Use entire disk

### Post-Installation Encryption
```bash
# Check current encryption status
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT

# If not encrypted, backup data first!
# Then use the disk encryption script
sudo ./scripts/01_disk_encryption.sh
```

## Network Configuration

### VPN Setup
1. Obtain VPN credentials from your provider
2. Edit `/etc/wireguard/wg0.conf`
3. Add server public key
4. Start VPN: `sudo wg-quick up wg0`

### Tor Configuration
```bash
# Check Tor status
sudo systemctl status tor

# Test Tor connection
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## Troubleshooting

### Common Issues

#### SSH Connection Lost
```bash
# Boot from recovery media
# Mount system partition
mount /dev/sda1 /mnt
chroot /mnt

# Fix SSH configuration
nano /etc/ssh/sshd_config
# Set: PasswordAuthentication yes
# Set: Port 22
```

#### Firewall Blocking Everything
```bash
# From console:
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F
```

#### System Won't Boot (Encryption)
- Boot from Live USB
- Open encrypted drive
- Check /etc/crypttab
- Regenerate initramfs

### Recovery Mode

If system becomes inaccessible:

1. Boot from Live USB
2. Mount encrypted partitions
3. Chroot into system
4. Disable problematic services
5. Restore from backup

## Verification

### Security Checklist

After installation, verify:

- [ ] Firewall is active
- [ ] SSH uses non-standard port
- [ ] Root login disabled
- [ ] Automatic updates enabled
- [ ] Monitoring services running
- [ ] Encryption active
- [ ] Backups configured

### Testing Commands

```bash
# Check all security services
sudo security-status

# Run security audit
sudo security-audit

# Test firewall
sudo iptables -L -n

# Check encryption
lsblk -o NAME,FSTYPE,TYPE,SIZE,MOUNTPOINT

# Verify hardening
sudo security-check
```

## Maintenance

### Regular Tasks

```bash
# Daily: Check security status
sudo security-status

# Weekly: Run security audit
sudo security-audit

# Monthly: Update security rules
sudo security-update

# As needed: Check logs
sudo security-logs
```

### Backup Procedures

```bash
# Manual backup
sudo system-backup

# Verify backups
ls -la $BACKUP_DIR

# Restore from backup
sudo tar -xzf /mnt/backup/backup_*.tar.gz -C /
```

## Advanced Configuration

### Custom Firewall Rules

Add custom rules to `/etc/iptables/custom.rules`:

```bash
# Example: Allow specific IP
iptables -A INPUT -s 192.168.1.100 -j ACCEPT

# Example: Allow port range
iptables -A INPUT -p tcp --dport 8000:8100 -j ACCEPT
```

### Additional Hardening

```bash
# Disable USB storage
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

# Set file permissions
chmod 700 /home/$USER
chmod 600 ~/.ssh/authorized_keys
```

### Performance Tuning

If experiencing performance issues:

```bash
# Reduce security level
sudo nano /etc/security-toolkit.conf
# Change SECURITY_LEVEL to "enhanced"

# Disable specific features
sudo systemctl disable suricata  # Heavy IDS
sudo systemctl disable ossec      # Heavy HIDS
```

## Uninstallation

To remove the security toolkit:

```bash
# Create uninstall script
cat > uninstall.sh << 'EOF'
#!/bin/bash
echo "This will remove security hardening. Continue? (y/N)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    # Restore original configs
    mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    rm -f /etc/sysctl.d/99-security.conf
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    systemctl disable fail2ban apparmor auditd
    echo "Uninstall complete. Reboot required."
fi
EOF

chmod +x uninstall.sh
sudo ./uninstall.sh
```

## Support

For issues or questions:

1. Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Review system logs: `sudo journalctl -xe`
3. Run diagnostics: `sudo security-check`
4. Open an issue on GitHub

## Security Notes

- **Never** share your encryption keys or passphrases
- **Always** verify GPG signatures when updating
- **Regularly** review security logs
- **Keep** the toolkit updated
- **Test** changes in a VM first
- **Maintain** offline backups

---

**Remember**: Security is an ongoing process, not a one-time setup.

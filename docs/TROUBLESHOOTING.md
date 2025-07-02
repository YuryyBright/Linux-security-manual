# Linux Security Toolkit - Troubleshooting Guide

## Common Issues and Solutions

### System Access Issues

#### Cannot SSH into System

**Symptoms**: Connection refused or timeout when trying to SSH

**Solutions**:

1. **Check if SSH is running**:
   ```bash
   # From console
   sudo systemctl status sshd
   sudo systemctl start sshd
   ```

2. **Verify SSH port**:
   ```bash
   # Default changed to 2222
   sudo grep "Port" /etc/ssh/sshd_config
   
   # Connect with correct port
   ssh -p 2222 username@server
   ```

3. **Check firewall rules**:
   ```bash
   sudo iptables -L -n | grep 2222
   
   # Temporarily allow SSH
   sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT
   ```

4. **Reset SSH configuration**:
   ```bash
   # From console
   sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

#### Locked Out of System

**Recovery Steps**:

1. Boot from Live USB/CD
2. Mount root partition:
   ```bash
   # Find your partition
   lsblk
   
   # Mount it
   sudo mount /dev/sda2 /mnt
   sudo mount /dev/sda1 /mnt/boot
   
   # Chroot
   sudo chroot /mnt
   ```

3. Fix issues:
   ```bash
   # Reset password
   passwd username
   
   # Fix sudo
   usermod -aG sudo username
   
   # Disable firewall
   iptables -F
   iptables -P INPUT ACCEPT
   ```

### Network Issues

#### No Internet Connection

**Check VPN**:
```bash
# Disconnect VPN
sudo wg-quick down wg0

# Check connectivity
ping 1.1.1.1

# Restart networking
sudo systemctl restart NetworkManager
```

**Check Firewall**:
```bash
# View output rules
sudo iptables -L OUTPUT -n -v

# Temporarily allow all output
sudo iptables -P OUTPUT ACCEPT
```

**Check DNS**:
```bash
# Test DNS resolution
nslookup google.com
dig @1.1.1.1 google.com

# Reset DNS
sudo systemctl restart systemd-resolved
```

#### Tor Not Working

```bash
# Check Tor status
sudo systemctl status tor

# View Tor logs
sudo journalctl -u tor

# Restart Tor
sudo systemctl restart tor

# Test connection
curl --socks5 localhost:9050 https://check.torproject.org
```

### Performance Issues

#### System Running Slowly

**Identify resource usage**:
```bash
# CPU and memory
htop

# Disk I/O
iotop

# Network
iftop
```

**Disable heavy services**:
```bash
# Temporarily disable IDS
sudo systemctl stop suricata
sudo systemctl stop ossec

# Reduce logging
sudo systemctl stop auditd
```

**Clear caches**:
```bash
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

#### High CPU Usage

**Common culprits**:
- Suricata IDS
- OSSEC HIDS
- ClamAV scanning

**Solutions**:
```bash
# Adjust Suricata
sudo nano /etc/suricata/suricata.yaml
# Reduce threading

# Limit ClamAV
sudo systemctl stop clamav-daemon
```

### Security Service Issues

#### Fail2ban Not Blocking

**Check status**:
```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

**View logs**:
```bash
sudo tail -f /var/log/fail2ban.log
```

**Reload rules**:
```bash
sudo fail2ban-client reload
```

**Unban IP**:
```bash
sudo fail2ban-client unban 192.168.1.100
```

#### AppArmor Blocking Applications

**Check denials**:
```bash
sudo aa-status
sudo dmesg | grep apparmor
```

**Set profile to complain mode**:
```bash
sudo aa-complain /usr/bin/firefox
```

**Disable profile**:
```bash
sudo aa-disable /usr/bin/firefox
```

### Encryption Issues

#### Cannot Boot (Encrypted System)

**From Live USB**:
```bash
# Open encrypted volume
sudo cryptsetup luksOpen /dev/sda3 cryptroot

# Mount and fix
sudo mount /dev/mapper/cryptroot /mnt
sudo mount /dev/sda1 /mnt/boot

# Chroot and fix
sudo chroot /mnt
update-initramfs -u
```

#### Forgotten LUKS Password

**If you have the key file**:
```bash
sudo cryptsetup luksOpen --key-file /path/to/keyfile /dev/sda3 cryptroot
```

**Add new passphrase**:
```bash
sudo cryptsetup luksAddKey /dev/sda3
```

### Backup and Recovery Issues

#### Backup Failing

**Check disk space**:
```bash
df -h /mnt/backup
```

**Verify GPG key**:
```bash
gpg --list-keys
gpg --list-secret-keys
```

**Test backup manually**:
```bash
sudo system-backup
```

#### Cannot Restore Backup

**Decrypt backup**:
```bash
# List backups
ls -la /mnt/backup/

# Decrypt
gpg -d backup_file.tar.gz.gpg > backup_file.tar.gz

# Extract
tar -tzf backup_file.tar.gz  # List contents
tar -xzf backup_file.tar.gz  # Extract
```

### Monitoring Issues

#### No Alerts Being Sent

**Check mail configuration**:
```bash
# Test mail
echo "Test" | mail -s "Test Alert" admin@localhost

# Check mail logs
sudo tail -f /var/log/mail.log
```

**Verify alert configuration**:
```bash
# Check OSSEC
sudo /var/ossec/bin/ossec-control status

# Check alert script
sudo systemctl status security-alert
```

### Emergency Procedures Failed

#### Panic Button Not Working

**Manual emergency wipe**:
```bash
# WARNING: Destructive!
# Wipe swap
sudo swapoff -a
sudo dd if=/dev/urandom of=/dev/mapper/cryptswap bs=1M

# Wipe free space
sudo dd if=/dev/urandom of=/tmp/wipe bs=1M
sudo rm /tmp/wipe
```

#### System Won't Shutdown

**Force shutdown**:
```bash
# Sync and shutdown
sync
sudo systemctl poweroff -f

# If that fails
sudo poweroff -f

# Last resort
echo o > /proc/sysrq-trigger
```

## Diagnostic Commands

### System Health Check

```bash
#!/bin/bash
# Save as: /usr/local/bin/health-check

echo "=== System Health Check ==="
echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $5}')"
echo "Failed services: $(systemctl --failed | grep failed | wc -l)"
echo "Firewall rules: $(iptables -L -n | grep -c DROP)"
echo "Failed logins: $(grep -c "Failed password" /var/log/auth.log)"
```

### Debug Mode

Enable verbose logging:

```bash
# SSH debug
sudo /usr/sbin/sshd -d -p 2222

# Firewall logging
sudo iptables -I INPUT -j LOG --log-prefix "INPUT-DEBUG: "
sudo iptables -I OUTPUT -j LOG --log-prefix "OUTPUT-DEBUG: "

# View logs
sudo tail -f /var/log/syslog | grep DEBUG
```

## Getting Help

### Collect Diagnostic Info

```bash
# Create diagnostic report
sudo security-audit > diagnostic-report.txt
sudo systemctl status --failed >> diagnostic-report.txt
sudo dmesg | tail -50 >> diagnostic-report.txt
sudo journalctl -xe | tail -100 >> diagnostic-report.txt
```

### Safe Mode

Boot with minimal security:

1. Edit GRUB: Press 'e' at boot menu
2. Add to kernel line: `systemd.unit=multi-user.target`
3. Boot with Ctrl+X
4. Fix issues in minimal environment

### Reset to Defaults

```bash
#!/bin/bash
# Emergency reset script

echo "This will reset security settings. Continue? (y/N)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    # Restore firewall
    iptables -F
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Restore SSH
    sed -i 's/Port 2222/Port 22/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
    
    # Disable security services
    systemctl disable fail2ban apparmor auditd tor
    
    echo "Reset complete. Reboot required."
fi
```

---

If issues persist, please:
1. Document the exact error messages
2. Note what changed before the issue
3. Create a GitHub issue with diagnostic info
# Linux Security Toolkit - Usage Guide

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Security Commands](#security-commands)
3. [Network Security](#network-security)
4. [Privacy & Anonymity](#privacy--anonymity)
5. [Monitoring & Alerts](#monitoring--alerts)
6. [Emergency Procedures](#emergency-procedures)
7. [Maintenance](#maintenance)

## Daily Operations

### System Status Check

Start your day by checking the security status:

```bash
# Quick security overview
sudo security-status

# Detailed report
sudo security-report
```

### Secure Browsing

```bash
# Launch secure browser (routes through Tor)
secure-browser

# Browse with temporary identity
torify firefox --private-window
```

### File Operations

```bash
# Securely delete files
secure-delete sensitive-file.txt

# Clean metadata from files
clean-metadata document.pdf image.jpg

# Encrypt files
gpg -e -r your.email@domain.com file.txt

# Decrypt files
gpg -d file.txt.gpg > file.txt
```

## Security Commands

### System Audit

```bash
# Run comprehensive security audit
sudo security-audit

# Check specific components
sudo security-check

# View security logs
sudo security-logs

# Real-time log monitoring
sudo tail -f /var/log/auth.log
```

### Firewall Management

```bash
# View current rules
sudo iptables -L -n -v

# Temporarily allow a port
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Remove temporary rule
sudo iptables -D INPUT -p tcp --dport 8080 -j ACCEPT

# Save firewall rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Service Management

```bash
# Check security services
sudo systemctl status fail2ban
sudo systemctl status tor
sudo systemctl status apparmor

# Restart services
sudo systemctl restart fail2ban
```

## Network Security

### VPN Usage

```bash
# Connect to VPN
sudo wg-quick up wg0

# Disconnect VPN
sudo wg-quick down wg0

# Check VPN status
sudo wg show

# Test VPN connection
curl ifconfig.me
```

### Tor Operations

```bash
# Check Tor status
sudo systemctl status tor

# New Tor identity
sudo pkill -HUP tor

# Test Tor connection
curl --socks5 localhost:9050 https://check.torproject.org

# Use Tor for specific command
torify curl https://example.com
```

### Network Monitoring

```bash
# View active connections
sudo netstat -tulpn

# Monitor network traffic
sudo iftop

# Check for suspicious connections
sudo network-monitor

# View blocked IPs
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

## Privacy & Anonymity

### Identity Management

```bash
# Create new identity
sudo create-identity anon1

# Switch to identity
su - anon1

# Remove identity
sudo userdel -r anon1
```

### Metadata Removal

```bash
# Remove metadata from single file
mat2 document.pdf

# Batch process directory
find ~/Documents -type f -name "*.jpg" -exec mat2 {} \;

# Check file for metadata
mat2 -s file.pdf
```

### Secure Communications

```bash
# Generate GPG key
gpg --full-generate-key

# Export public key
gpg --armor --export your.email@domain.com > public.asc

# Encrypt message
echo "Secret message" | gpg -e -r recipient@email.com > message.gpg

# Sign and encrypt
gpg -s -e -r recipient@email.com file.txt
```

### Privacy Cleanup

```bash
# Quick privacy cleanup
privacy-cleanup

# Secure system wipe (careful!)
sudo security-clean

# Clear specific traces
history -c
rm -rf ~/.cache/*
find /tmp -user $USER -delete
```

## Monitoring & Alerts

### Log Analysis

```bash
# View authentication logs
sudo grep "Accepted" /var/log/auth.log | tail -20

# Check failed logins
sudo grep "Failed password" /var/log/auth.log | tail -20

# Monitor sudo usage
sudo grep "sudo" /var/log/auth.log | tail -20
```

### Alert Configuration

```bash
# Edit alert settings
sudo nano /usr/local/bin/security-alert

# Test email alerts
echo "Test alert" | mail -s "Security Test" admin@localhost

# View alert history
sudo cat /var/log/security-alerts.log
```

### Real-time Monitoring

```bash
# System resource monitor
htop

# Network connections monitor
sudo watch -n 1 'netstat -tulpn | grep ESTABLISHED'

# File system changes
sudo watch -n 60 'find /etc -mmin -1 -type f'
```

## Emergency Procedures

### Incident Response

```bash
# Collect forensic data
sudo incident-response collect

# Isolate system from network
sudo incident-response isolate

# Restore network access
sudo incident-response restore
```

### Emergency Lockdown

```bash
# Immediate lockdown (blocks ALL network)
sudo emergency-lockdown

# Restore from lockdown
sudo emergency-lockdown --restore
```

### Panic Mode

```bash
# WARNING: Destructive operations!

# Panic button (5 second delay)
sudo panic-button

# Full system wipe (NO RECOVERY!)
sudo panic-button --full
```

### Data Recovery

```bash
# List available backups
ls -la /mnt/backup/

# Restore specific backup
sudo gpg -d /mnt/backup/backup_20240315.tar.gz.gpg | tar -xz -C /

# Restore specific files
tar -tzf backup.tar.gz | grep "important"
tar -xzf backup.tar.gz path/to/important/file
```

## Maintenance

### System Updates

```bash
# Update all security components
sudo security-update

# Manual update check
sudo apt update && sudo apt list --upgradable

# Update specific tools
sudo suricata-update
sudo freshclam
```

### Backup Operations

```bash
# Manual backup
sudo system-backup

# Verify backup integrity
gpg -d /mnt/backup/latest-backup.tar.gz.gpg > /dev/null && echo "Backup OK"

# List backups
ls -lah /mnt/backup/
```

### Performance Optimization

```bash
# Check system performance
sudo security-status
top
iostat -x 1

# Clear caches
sudo sync && echo 3 > /proc/sys/vm/drop_caches

# Clean old logs
sudo journalctl --vacuum-time=7d
```

### Troubleshooting

```bash
# Check service failures
sudo systemctl --failed

# View system journal
sudo journalctl -xe

# Debug network issues
sudo tcpdump -i any -n port 22

# Test DNS
dig @1.1.1.1 example.com
```

## Best Practices

### Daily Routine

1. Morning: Check `security-status`
2. Throughout day: Use `secure-browser` for sensitive browsing
3. Before shutdown: Run `privacy-cleanup`
4. Weekly: Review `security-audit` results

### Security Hygiene

- Always use strong, unique passwords
- Enable 2FA where possible
- Regularly update all software
- Review logs for anomalies
- Test backups monthly
- Rotate encryption keys annually

### Operational Security

- Never run untrusted code
- Verify all downloads with GPG/checksums
- Use encrypted containers for sensitive data
- Maintain separate identities for different activities
- Always use VPN on public networks
- Regularly check for rootkits: `sudo rkhunter -c`

## Command Reference

### Quick Reference Card

| Task | Command |
|------|---------|
| Check status | `sudo security-status` |
| Run audit | `sudo security-audit` |
| View logs | `sudo security-logs` |
| Update security | `sudo security-update` |
| Secure browse | `secure-browser` |
| Delete securely | `secure-delete file` |
| Clean metadata | `clean-metadata file` |
| Backup system | `sudo system-backup` |
| Emergency lock | `sudo emergency-lockdown` |
| Incident response | `sudo incident-response collect` |

---

For more information, see the [Troubleshooting Guide](TROUBLESHOOTING.md).
#!/bin/bash
# System Maintenance and Utilities

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[MAINT] $1"; }

# Setup automatic updates
setup_auto_updates() {
    log "Configuring automatic updates..."
    
    # Install unattended-upgrades
    apt-get install -y unattended-upgrades apt-listchanges
    
    # Configure unattended upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
    // Don't auto-update these packages
    "linux-kernel*";
    "linux-image*";
    "linux-headers*";
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
    
    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

# Setup backup system
setup_backup() {
    log "Setting up automated backup system..."
    
    # Create backup script
    cat > /usr/local/bin/system-backup << 'EOF'
#!/bin/bash
# Automated system backup

BACKUP_DIR="BACKUP_DIR_PLACEHOLDER"
SOURCE_DIRS="/etc /home /var/log /root"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="backup_${HOSTNAME}_${DATE}"
GPG_RECIPIENT="GPG_EMAIL_PLACEHOLDER"
RETENTION_DAYS="RETENTION_PLACEHOLDER"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
log() { echo "[BACKUP] $1"; }

log "Starting backup: $BACKUP_NAME"

# Create tar archive
tar -czf "/tmp/${BACKUP_NAME}.tar.gz" \
    --exclude="*.log" \
    --exclude="*/cache/*" \
    --exclude="*/tmp/*" \
    $SOURCE_DIRS 2>/dev/null

# Encrypt backup
if gpg --list-keys "$GPG_RECIPIENT" &>/dev/null; then
    log "Encrypting backup..."
    gpg --trust-model always \
        --encrypt -r "$GPG_RECIPIENT" \
        --cipher-algo AES256 \
        --output "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg" \
        "/tmp/${BACKUP_NAME}.tar.gz"
else
    log "GPG key not found, storing unencrypted"
    mv "/tmp/${BACKUP_NAME}.tar.gz" "$BACKUP_DIR/"
fi

# Secure delete temporary file
shred -vfz -n 3 "/tmp/${BACKUP_NAME}.tar.gz" 2>/dev/null || true

# Clean old backups
find "$BACKUP_DIR" -name "backup_*.tar.gz*" -mtime +${RETENTION_DAYS} -delete

log "Backup complete: ${BACKUP_NAME}"
EOF
    
    # Replace placeholders
    sed -i "s|BACKUP_DIR_PLACEHOLDER|$BACKUP_DIR|g" /usr/local/bin/system-backup
    sed -i "s|GPG_EMAIL_PLACEHOLDER|$GPG_EMAIL|g" /usr/local/bin/system-backup
    sed -i "s|RETENTION_PLACEHOLDER|$BACKUP_RETENTION_DAYS|g" /usr/local/bin/system-backup
    
    chmod +x /usr/local/bin/system-backup
    
    # Schedule backups
    echo "0 2 * * * /usr/local/bin/system-backup" | crontab -l | crontab -
}

# Setup security audit
setup_security_audit() {
    log "Setting up security audit..."
    
    # Create comprehensive audit script
    cat > /usr/local/bin/security-audit << 'EOF'
#!/bin/bash
# Comprehensive security audit

AUDIT_LOG="/var/log/security-audit-$(date +%Y%m%d).log"

audit() {
    echo -e "\n[$1]" | tee -a "$AUDIT_LOG"
    shift
    "$@" 2>&1 | tee -a "$AUDIT_LOG"
}

echo "Security Audit Report - $(date)" > "$AUDIT_LOG"
echo "========================================" >> "$AUDIT_LOG"

# System information
audit "SYSTEM INFO" uname -a
audit "UPTIME" uptime

# User accounts
audit "USER ACCOUNTS" awk -F: '$3 >= 1000 {print $1}' /etc/passwd
audit "SUDO USERS" grep -Po '^sudo:\K.*' /etc/group
audit "EMPTY PASSWORDS" awk -F: '($2 == "") {print $1}' /etc/shadow

# File permissions
audit "SUID FILES" find / -perm -4000 -type f 2>/dev/null
audit "WORLD WRITABLE" find / -perm -2 -type f 2>/dev/null | head -20

# Network
audit "OPEN PORTS" netstat -tulpn
audit "ESTABLISHED CONNECTIONS" netstat -an | grep ESTABLISHED
audit "FIREWALL RULES" iptables -L -n -v

# Services
audit "RUNNING SERVICES" systemctl list-units --type=service --state=running

# Security tools status
audit "FAIL2BAN STATUS" fail2ban-client status
audit "APPARMOR STATUS" aa-status --summary 2>/dev/null || echo "AppArmor not active"

# Package updates
audit "SECURITY UPDATES" apt list --upgradable 2>/dev/null | grep -i security

# Logs
audit "AUTH FAILURES" grep "authentication failure" /var/log/auth.log | tail -20
audit "SUDO USAGE" grep "sudo.*COMMAND" /var/log/auth.log | tail -10

# System integrity
if command -v aide &>/dev/null; then
    audit "AIDE CHECK" aide --check --config=/etc/aide/aide.conf || true
fi

echo -e "\nAudit complete. Report saved to: $AUDIT_LOG"

# Email report
if [[ -n "$ALERT_EMAIL" ]]; then
    mail -s "Security Audit Report" "$ALERT_EMAIL" < "$AUDIT_LOG"
fi
EOF
    chmod +x /usr/local/bin/security-audit
    
    # Schedule weekly audits
    echo "0 6 * * 0 /usr/local/bin/security-audit" | crontab -l | crontab -
}

# Setup emergency response
setup_emergency_response() {
    log "Setting up emergency response tools..."
    
    # Create incident response script
    cat > /usr/local/bin/incident-response << 'EOF'
#!/bin/bash
# Incident response toolkit

case "$1" in
    collect)
        # Collect forensic data
        DIR="/tmp/incident-$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$DIR"
        
        echo "Collecting incident data to $DIR..."
        
        # System info
        uname -a > "$DIR/system.txt"
        date > "$DIR/date.txt"
        uptime > "$DIR/uptime.txt"
        
        # Process info
        ps aux > "$DIR/processes.txt"
        lsof > "$DIR/open_files.txt"
        
        # Network info
        netstat -tulpn > "$DIR/netstat.txt"
        ss -tulpn > "$DIR/ss.txt"
        iptables -L -n -v > "$DIR/iptables.txt"
        
        # User info
        w > "$DIR/logged_users.txt"
        last -20 > "$DIR/last_logins.txt"
        
        # Logs
        cp /var/log/auth.log "$DIR/"
        cp /var/log/syslog "$DIR/"
        journalctl -xe > "$DIR/journal.txt"
        
        # Create archive
        tar -czf "$DIR.tar.gz" -C /tmp "$(basename $DIR)"
        echo "Data collected: $DIR.tar.gz"
        ;;
        
    isolate)
        # Network isolation
        echo "Isolating system from network..."
        
        # Save current rules
        iptables-save > /tmp/iptables-backup-$(date +%s)
        
        # Block all traffic except local
        iptables -P INPUT DROP
        iptables -P OUTPUT DROP
        iptables -P FORWARD DROP
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        
        echo "System isolated. Backup rules saved."
        ;;
        
    restore)
        # Restore network
        if [[ -f /tmp/iptables-backup-* ]]; then
            BACKUP=$(ls -t /tmp/iptables-backup-* | head -1)
            iptables-restore < "$BACKUP"
            echo "Network restored from $BACKUP"
        else
            echo "No backup found"
        fi
        ;;
        
    *)
        echo "Usage: incident-response {collect|isolate|restore}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/incident-response
}

# Setup system hardening checks
setup_hardening_checks() {
    log "Setting up hardening verification..."
    
    # Create hardening check script
    cat > /usr/local/bin/security-check << 'EOF'
#!/bin/bash
# Security hardening verification

PASS=0
FAIL=0

check() {
    echo -n "Checking $1... "
    if eval "$2"; then
        echo "✓ PASS"
        ((PASS++))
    else
        echo "✗ FAIL"
        ((FAIL++))
    fi
}

echo "Security Hardening Check"
echo "========================"

# Kernel parameters
check "IP forwarding disabled" "sysctl net.ipv4.ip_forward | grep -q '= 0'"
check "SYN cookies enabled" "sysctl net.ipv4.tcp_syncookies | grep -q '= 1'"
check "ASLR enabled" "sysctl kernel.randomize_va_space | grep -q '= 2'"

# SSH configuration
check "SSH root login disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
check "SSH password auth disabled" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"

# Firewall
check "Firewall enabled" "iptables -L -n | grep -q DROP"

# Services
check "Fail2ban running" "systemctl is-active fail2ban | grep -q active"
check "AppArmor enabled" "systemctl is-active apparmor | grep -q active"

# Updates
check "Automatic updates enabled" "[[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]"

# Encryption
check "Disk encryption" "lsblk -o NAME,FSTYPE | grep -q crypto_LUKS"

echo
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    echo "WARNING: System hardening incomplete!"
    exit 1
fi
EOF
    chmod +x /usr/local/bin/security-check
}

# Setup log rotation
setup_log_rotation() {
    log "Configuring log rotation..."
    
    cat > /etc/logrotate.d/security-toolkit << 'EOF'
/var/log/security-*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}

/var/log/threat-hunt-*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
}

/var/log/security-audit-*.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
}
EOF
}

# Create utility commands
create_utilities() {
    log "Creating utility commands..."
    
    # Quick security report
    cat > /usr/local/bin/security-report << 'EOF'
#!/bin/bash
# Quick security report

echo "=== Security Report - $(date) ==="
echo
echo "Failed logins today: $(grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %e)" | wc -l)"
echo "Active SSH sessions: $(who | grep pts | wc -l)"
echo "Blocked IPs: $(fail2ban-client status sshd | grep "Currently banned" | awk '{print $NF}')"
echo "Open ports: $(netstat -tlpn 2>/dev/null | grep -v "127.0.0.1" | wc -l)"
echo "Running services: $(systemctl list-units --type=service --state=running | wc -l)"
echo "Disk usage: $(df -h / | awk 'NR==2 {print $5}')"
echo "Memory usage: $(free | awk '/^Mem:/ {printf "%.0f%%", $3/$2 * 100}')"
echo "Load average: $(uptime | awk -F'load average:' '{print $2}')"
echo
EOF
    chmod +x /usr/local/bin/security-report
    
    # Emergency lockdown
    cat > /usr/local/bin/emergency-lockdown << 'EOF'
#!/bin/bash
# Emergency lockdown mode

echo "ACTIVATING EMERGENCY LOCKDOWN!"
echo "This will block ALL network traffic. Continue? (y/N)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    # Block all network traffic
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    iptables -F
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Stop network services
    systemctl stop networking
    systemctl stop NetworkManager
    
    # Kill all network connections
    killall -9 ssh sshd
    
    echo "System is now in lockdown mode"
    echo "To restore: emergency-lockdown --restore"
elif [[ "$1" == "--restore" ]]; then
    systemctl start networking
    systemctl start NetworkManager
    /usr/local/bin/incident-response restore
    echo "Lockdown released"
fi
EOF
    chmod +x /usr/local/bin/emergency-lockdown
    
    # Security update
    cat > /usr/local/bin/security-update << 'EOF'
#!/bin/bash
# Update security components

echo "Updating security components..."

# Update system packages
apt-get update
apt-get upgrade -y

# Update security tools
if command -v suricata-update &>/dev/null; then
    suricata-update
fi

if [[ -d /var/ossec/bin ]]; then
    /var/ossec/bin/update_ruleset
fi

# Update ClamAV
if command -v freshclam &>/dev/null; then
    freshclam
fi

# Update fail2ban
if command -v fail2ban-client &>/dev/null; then
    fail2ban-client reload
fi

echo "Security update complete"
EOF
    chmod +x /usr/local/bin/security-update
}

# Setup system cleaner
setup_system_cleaner() {
    log "Setting up system cleaner..."
    
    cat > /usr/local/bin/security-clean << 'EOF'
#!/bin/bash
# Security-focused system cleanup

echo "Starting security cleanup..."

# Clear package cache
apt-get clean
apt-get autoclean
apt-get autoremove -y

# Clear old kernels
dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs apt-get -y purge

# Clear logs
find /var/log -type f -name "*.log" -mtime +30 -delete
find /var/log -type f -name "*.gz" -delete
journalctl --vacuum-time=30d

# Clear temporary files
find /tmp -type f -atime +7 -delete
find /var/tmp -type f -atime +7 -delete

# Clear bash history
cat /dev/null > ~/.bash_history
history -c

echo "Cleanup complete"
EOF
    chmod +x /usr/local/bin/security-clean
}

# Main execution
main() {
    setup_auto_updates
    setup_backup
    setup_security_audit
    setup_emergency_response
    setup_hardening_checks
    setup_log_rotation
    create_utilities
    setup_system_cleaner
    
    log "Maintenance setup complete"
    
    # Create final setup marker
    cat > /etc/security-toolkit.conf << EOF
# Security Toolkit Configuration
INSTALLED=$(date)
VERSION=1.0
SECURITY_LEVEL=$SECURITY_LEVEL
EOF
    
    log "All security configurations applied successfully!"
}

main
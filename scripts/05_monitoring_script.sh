#!/bin/bash
# Security Monitoring and Detection Setup

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[MONITOR] $1"; }

# Setup OSSEC HIDS
setup_ossec() {
    log "Installing OSSEC HIDS..."
    
    # Download and install
    cd /tmp
    wget -q https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
    tar -xzf 3.7.0.tar.gz
    cd ossec-hids-3.7.0
    
    # Automated installation
    ./install.sh << EOF
en
server
/var/ossec
n
y
y
y
y
y
y
n
EOF
    
    # Configure OSSEC
    cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>ALERT_EMAIL</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>ossec@localhost</email_from>
    <email_maxperhour>12</email_maxperhour>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>iptables_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <frequency>7200</frequency>
    <alert_new_files>yes</alert_new_files>
    
    <directories check_all="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" report_changes="yes">/bin,/sbin,/boot</directories>
    
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>36000</frequency>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>netstat -tulpn | grep -v 127.0.0.1</command>
    <frequency>120</frequency>
  </localfile>
</ossec_config>
EOF
    
    # Replace email
    sed -i "s/ALERT_EMAIL/$ALERT_EMAIL/g" /var/ossec/etc/ossec.conf
    
    # Start OSSEC
    /var/ossec/bin/ossec-control start
    
    cd /
    rm -rf /tmp/ossec-hids-3.7.0*
}

# Setup system integrity monitoring
setup_aide() {
    log "Setting up AIDE integrity monitoring..."
    
    # Configure AIDE
    cat > /etc/aide/aide.conf << 'EOF'
# AIDE configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
verbose=5
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Rule definitions
NORMAL = p+i+n+u+g+s+m+c+md5+sha256
DIR = p+i+n+u+g
PERMS = p+u+g+acl+selinux+xattrs
DATAONLY = p+n+u+g+s+acl+selinux+xattrs+md5+sha256

# Directories to monitor
/boot NORMAL
/bin NORMAL
/sbin NORMAL
/lib NORMAL
/lib64 NORMAL
/opt NORMAL
/usr NORMAL
/root NORMAL

# Critical files
/etc/passwd NORMAL
/etc/shadow NORMAL
/etc/gshadow NORMAL
/etc/group NORMAL
/etc/ssh/sshd_config NORMAL
/etc/sudoers NORMAL
/etc/crontab NORMAL

# Logs
!/var/log
!/var/cache
!/var/spool
!/var/tmp
EOF
    
    # Initialize database
    aideinit
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Create check script
    cat > /usr/local/bin/aide-check << 'EOF'
#!/bin/bash
# AIDE integrity check

LOG="/var/log/aide/aide-check.log"
mkdir -p /var/log/aide

echo "[$(date)] Starting AIDE check" >> "$LOG"
aide --check >> "$LOG" 2>&1

if [[ $? -ne 0 ]]; then
    echo "[$(date)] AIDE detected changes!" >> "$LOG"
    # Send alert
    mail -s "AIDE Alert: System changes detected" "$ALERT_EMAIL" < "$LOG"
fi

# Update database
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
EOF
    chmod +x /usr/local/bin/aide-check
    
    # Schedule daily checks
    echo "0 3 * * * /usr/local/bin/aide-check" | crontab -l | crontab -
}

# Setup log monitoring
setup_log_monitoring() {
    log "Setting up log monitoring..."
    
    # Configure rsyslog
    cat >> /etc/rsyslog.conf << 'EOF'

# Security logging
auth,authpriv.*         /var/log/auth.log
*.*;auth,authpriv.none  /var/log/syslog
kern.*                  /var/log/kern.log

# Remote logging (if configured)
#*.* @@remote-syslog-server:514
EOF
    
    # Setup logwatch
    apt-get install -y logwatch
    
    cat > /etc/logwatch/conf/logwatch.conf << EOF
LogDir = /var/log
TmpDir = /var/cache/logwatch
Output = mail
Format = html
Encode = none
MailTo = $ALERT_EMAIL
MailFrom = Logwatch
Range = yesterday
Detail = High
Service = All
Service = "-zz-network"
Service = "-zz-sys"
Service = "-eximstats"
EOF
    
    # Create monitoring dashboard script
    cat > /usr/local/bin/security-status << 'EOF'
#!/bin/bash
# Security status dashboard

clear
echo "═══════════════════════════════════════════════════════"
echo "            SECURITY STATUS DASHBOARD"
echo "═══════════════════════════════════════════════════════"
echo

# System info
echo "[SYSTEM]"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime -p)"
echo "Kernel: $(uname -r)"
echo

# Security services
echo "[SERVICES]"
for service in fail2ban apparmor auditd tor suricata ossec; do
    if systemctl is-active --quiet $service; then
        echo "✓ $service: active"
    else
        echo "✗ $service: inactive"
    fi
done
echo

# Failed logins
echo "[AUTHENTICATION]"
echo "Failed logins (last 24h): $(grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %e)" | wc -l)"
echo "Current users: $(who | wc -l)"
echo

# Network
echo "[NETWORK]"
echo "Active connections: $(netstat -an | grep ESTABLISHED | wc -l)"
echo "Listening ports: $(netstat -tlpn 2>/dev/null | grep -v "127.0.0.1" | wc -l)"
echo

# Disk encryption
echo "[ENCRYPTION]"
if lsblk -o NAME,FSTYPE | grep -q crypto_LUKS; then
    echo "✓ Disk encryption: active"
else
    echo "✗ Disk encryption: inactive"
fi
echo

# Updates
echo "[UPDATES]"
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
echo "Pending updates: $UPDATES"
echo

echo "═══════════════════════════════════════════════════════"
EOF
    chmod +x /usr/local/bin/security-status
}

# Setup real-time alerting
setup_alerting() {
    log "Setting up real-time alerting..."
    
    # Create alert script
    cat > /usr/local/bin/security-alert << 'EOF'
#!/bin/bash
# Security alert system

ALERT_LOG="/var/log/security-alerts.log"
ALERT_EMAIL="ALERT_EMAIL_PLACEHOLDER"

send_alert() {
    local severity="$1"
    local message="$2"
    
    echo "[$(date)] [$severity] $message" >> "$ALERT_LOG"
    
    if [[ "$severity" == "CRITICAL" ]]; then
        echo "$message" | mail -s "CRITICAL Security Alert" "$ALERT_EMAIL"
    fi
}

# Monitor auth log
tail -F /var/log/auth.log | while read line; do
    # SSH brute force
    if echo "$line" | grep -q "Failed password.*ssh"; then
        IP=$(echo "$line" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
        COUNT=$(grep "$IP" /var/log/auth.log | grep -c "Failed password")
        if [[ $COUNT -gt 5 ]]; then
            send_alert "HIGH" "SSH brute force attempt from $IP ($COUNT attempts)"
        fi
    fi
    
    # Successful root login
    if echo "$line" | grep -q "Accepted.*root"; then
        send_alert "CRITICAL" "Root login detected!"
    fi
    
    # sudo usage
    if echo "$line" | grep -q "sudo.*COMMAND"; then
        USER=$(echo "$line" | grep -oP "sudo:\s+\K\w+")
        CMD=$(echo "$line" | grep -oP "COMMAND=\K.*")
        send_alert "INFO" "Sudo usage: $USER executed $CMD"
    fi
done &
EOF
    
    sed -i "s/ALERT_EMAIL_PLACEHOLDER/$ALERT_EMAIL/g" /usr/local/bin/security-alert
    chmod +x /usr/local/bin/security-alert
    
    # Create systemd service
    cat > /etc/systemd/system/security-alert.service << 'EOF'
[Unit]
Description=Security Alert Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-alert
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable security-alert.service
    systemctl start security-alert.service
}

# Setup threat hunting
setup_threat_hunting() {
    log "Setting up threat hunting tools..."
    
    # Create threat hunting script
    cat > /usr/local/bin/threat-hunt << 'EOF'
#!/bin/bash
# Automated threat hunting

REPORT="/var/log/threat-hunt-$(date +%Y%m%d).log"

echo "Threat Hunting Report - $(date)" > "$REPORT"
echo "======================================" >> "$REPORT"

# Check for suspicious processes
echo -e "\n[Suspicious Processes]" >> "$REPORT"
ps aux | grep -E "(nc|netcat|python.*SimpleHTTP|perl.*-e)" >> "$REPORT"

# Check for hidden files
echo -e "\n[Hidden Files in System Directories]" >> "$REPORT"
find /bin /sbin /usr/bin /usr/sbin -name ".*" -type f >> "$REPORT"

# Check for unauthorized SUID binaries
echo -e "\n[Non-standard SUID Binaries]" >> "$REPORT"
find / -perm -4000 -type f 2>/dev/null | grep -v -E "(ping|su|sudo|passwd|mount|umount)" >> "$REPORT"

# Check for suspicious network connections
echo -e "\n[Suspicious Network Connections]" >> "$REPORT"
netstat -tulpn | grep -E ":(4444|31337|6667|1337)" >> "$REPORT"

# Check for modified system files
echo -e "\n[Recently Modified System Files]" >> "$REPORT"
find /etc /bin /sbin -mtime -1 -type f >> "$REPORT"

# Check for large files in /tmp
echo -e "\n[Large Files in /tmp]" >> "$REPORT"
find /tmp -size +100M -type f >> "$REPORT"

# Email report if issues found
if [[ $(wc -l < "$REPORT") -gt 10 ]]; then
    mail -s "Threat Hunting Report" "$ALERT_EMAIL" < "$REPORT"
fi
EOF
    chmod +x /usr/local/bin/threat-hunt
    
    # Schedule daily threat hunting
    echo "0 4 * * * /usr/local/bin/threat-hunt" | crontab -l | crontab -
}

# Main execution
main() {
    setup_ossec
    setup_aide
    setup_log_monitoring
    setup_alerting
    setup_threat_hunting
    
    log "Monitoring and detection setup complete"
}

main
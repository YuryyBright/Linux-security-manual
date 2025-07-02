#!/bin/bash
# System Security Hardening Script

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[HARDEN] $1"; }

# Kernel hardening via sysctl
harden_kernel() {
    log "Hardening kernel parameters..."
    
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Memory Protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
kernel.net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1

# Filesystem Protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Core dumps
kernel.core_uses_pid = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Performance
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF
    
    sysctl -p /etc/sysctl.d/99-security.conf
}

# Configure users and sudo
harden_users() {
    log "Hardening user configuration..."
    
    # Lock root account
    passwd -l root
    
    # Configure sudo timeout
    cat > /etc/sudoers.d/security << EOF
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        timestamp_timeout=5
Defaults        passwd_timeout=1
Defaults        logfile="/var/log/sudo.log"
Defaults        lecture="always"
Defaults        requiretty
Defaults        use_pty
EOF
    
    # Set password policies
    cat > /etc/security/pwquality.conf << EOF
minlen = $PASSWORD_MIN_LENGTH
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxclassrepeat = 2
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
    
    # Configure login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Configure PAM
    cat > /etc/pam.d/common-password << 'EOF'
password    requisite   pam_pwquality.so retry=3
password    [success=1 default=ignore]  pam_unix.so obscure use_authtok try_first_pass sha512 rounds=65536
password    requisite   pam_deny.so
password    required    pam_permit.so
EOF
}

# SSH hardening
harden_ssh() {
    log "Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Generate strong host keys
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    
    # Configure SSH
    cat > /etc/ssh/sshd_config << EOF
# SSH Security Configuration
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
LoginGraceTime 30s
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
AllowUsers $PRIMARY_USER
X11Forwarding no
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
Compression no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Banner
Banner /etc/ssh/banner
EOF
    
    # Create SSH banner
    cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                            SECURITY WARNING
***************************************************************************
This is a private system. Unauthorized access is strictly prohibited.
All activities are monitored and logged. Trespassers will be prosecuted.
***************************************************************************
EOF
    
    systemctl restart sshd
}

# Configure firewall
setup_firewall() {
    log "Setting up firewall rules..."
    
    # Reset rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # Loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow essential outbound
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    
    # SSH (if enabled)
    if [[ -n "$SSH_PORT" ]]; then
        iptables -A INPUT -p tcp --dport "$SSH_PORT" -m limit --limit 3/min --limit-burst 3 -j ACCEPT
    fi
    
    # Additional allowed ports
    if [[ -n "$ALLOWED_PORTS" ]]; then
        IFS=',' read -ra PORTS <<< "$ALLOWED_PORTS"
        for port in "${PORTS[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        done
    fi
    
    # Protection rules
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
    
    # Logging
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-denied: "
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    # Enable IPv6 firewall
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables-save > /etc/iptables/rules.v6
}

# Configure fail2ban
setup_fail2ban() {
    log "Configuring fail2ban..."
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
banaction = iptables-multiport
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
EOF
    
    systemctl restart fail2ban
}

# Configure AppArmor
setup_apparmor() {
    log "Configuring AppArmor..."
    
    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    # Set all profiles to enforce mode
    aa-enforce /etc/apparmor.d/*
    
    # Create custom profile for sensitive binaries
    cat > /etc/apparmor.d/usr.bin.wget << 'EOF'
#include <tunables/global>

/usr/bin/wget {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>
  
  /usr/bin/wget mr,
  /etc/wgetrc r,
  /etc/hosts r,
  /etc/ssl/** r,
  
  owner @{HOME}/.wget* rw,
  owner @{HOME}/Downloads/** rw,
  owner /tmp/** rw,
  
  network inet stream,
  network inet6 stream,
  
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny @{HOME}/.ssh/** r,
}
EOF
    
    apparmor_parser -r /etc/apparmor.d/usr.bin.wget
}

# Disable unnecessary services
disable_services() {
    log "Disabling unnecessary services..."
    
    local services=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "ModemManager"
        "apache2"
        "nginx"
        "mysql"
        "postgresql"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            systemctl disable "$service"
            systemctl stop "$service"
            log "Disabled $service"
        fi
    done
}

# Configure audit daemon
setup_auditd() {
    log "Configuring audit daemon..."
    
    # Configure audit rules
    cat > /etc/audit/rules.d/security.rules << 'EOF'
# Delete all rules
-D

# Buffer size
-b 8192

# Failure mode
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor system calls
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S socket -k socket
-a always,exit -F arch=b64 -S connect -k connect

# Monitor file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Monitor admin actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOF
    
    service auditd restart
}

# Main execution
main() {
    harden_kernel
    harden_users
    harden_ssh
    setup_firewall
    setup_fail2ban
    
    if [[ "$APPARMOR_ENABLED" == "yes" ]]; then
        setup_apparmor
    fi
    
    disable_services
    setup_auditd
    
    log "System hardening complete"
}

main
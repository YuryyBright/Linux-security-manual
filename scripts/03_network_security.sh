#!/bin/bash
# Network Security Configuration Script

set -euo pipefail
source "$(dirname "$0")/../config/variables.conf"

log() { echo "[NETWORK] $1"; }

# Configure DNS over TLS/HTTPS
setup_secure_dns() {
    log "Setting up secure DNS..."
    
    # Install systemd-resolved if not present
    apt-get install -y systemd-resolved
    
    # Configure DNS over TLS
    cat > /etc/systemd/resolved.conf << EOF
[Resolve]
DNS=$DNS_SERVERS
FallbackDNS=1.0.0.1 149.112.112.112
Domains=~.
DNSSEC=yes
DNSOverTLS=yes
Cache=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOF
    
    # Enable and restart resolved
    systemctl enable systemd-resolved
    systemctl restart systemd-resolved
    
    # Link resolv.conf
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
}

# Setup WireGuard VPN
setup_wireguard() {
    if [[ "$VPN_ENABLED" != "yes" ]]; then
        log "VPN disabled in configuration"
        return
    fi
    
    log "Setting up WireGuard VPN..."
    
    # Generate keys if not exist
    local privkey="/etc/wireguard/client_private.key"
    local pubkey="/etc/wireguard/client_public.key"
    
    if [[ ! -f "$privkey" ]]; then
        wg genkey | tee "$privkey" | wg pubkey > "$pubkey"
        chmod 600 "$privkey"
    fi
    
    # Create config
    cat > "/etc/wireguard/${VPN_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = $(cat "$privkey")
Address = 10.0.0.2/24
DNS = $DNS_SERVERS

# Kill switch
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -j REJECT

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY
Endpoint = ${VPN_SERVER}:${VPN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # Create systemd service for auto-connect
    systemctl enable "wg-quick@${VPN_INTERFACE}"
}

# Setup Tor
setup_tor() {
    if [[ "$TOR_ENABLED" != "yes" ]]; then
        log "Tor disabled in configuration"
        return
    fi
    
    log "Setting up Tor..."
    
    # Configure Tor
    cat > /etc/tor/torrc << EOF
# Basic Configuration
SocksPort $TOR_PROXY_PORT
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
ControlPort $TOR_CONTROL_PORT
CookieAuthentication 1

# Security
ClientRejectInternalAddresses 1
NewCircuitPeriod 30
MaxCircuitDirtiness 600
EnforceDistinctSubnets 1
StrictNodes 1

# Country restrictions
ExitNodes $TOR_COUNTRIES
ExcludeNodes {cn},{ru},{by},{kp},{ir}

# Performance
NumEntryGuards 3
NumDirectoryGuards 3
GuardLifetime 2 months

# Logging
Log notice file /var/log/tor/notices.log
DataDirectory /var/lib/tor
EOF
    
    # Create tor user if not exists
    id -u debian-tor &>/dev/null || useradd -r -s /bin/false debian-tor
    
    # Set permissions
    chown -R debian-tor:debian-tor /var/lib/tor /var/log/tor
    chmod 700 /var/lib/tor
    
    # Enable and start
    systemctl enable tor
    systemctl restart tor
}

# Configure proxy chains
setup_proxychains() {
    log "Configuring proxy chains..."
    
    cat > /etc/proxychains4.conf << EOF
# ProxyChains Configuration
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Tor
socks5 127.0.0.1 $TOR_PROXY_PORT

# Add additional proxies here
# http proxy.example.com 8080 username password
# socks5 proxy2.example.com 1080
EOF
}

# Network intrusion detection
setup_suricata() {
    log "Setting up Suricata IDS..."
    
    # Basic configuration
    cat > /etc/suricata/suricata.yaml << 'EOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

default-log-dir: /var/log/suricata/

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
EOF
    
    # Update rules
    suricata-update
    
    # Enable service
    systemctl enable suricata
    systemctl restart suricata
}

# Configure network monitoring
setup_network_monitoring() {
    log "Setting up network monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/network-monitor << 'EOF'
#!/bin/bash
# Network monitoring script

LOG="/var/log/network-monitor.log"

# Check for suspicious connections
SUSPICIOUS=$(netstat -tulpn | grep -E ":(4444|31337|12345|27374|16660|65000)" | wc -l)
if [[ $SUSPICIOUS -gt 0 ]]; then
    echo "[$(date)] WARNING: Suspicious ports detected" >> "$LOG"
    netstat -tulpn | grep -E ":(4444|31337|12345|27374|16660|65000)" >> "$LOG"
fi

# Check for port scans
SCANS=$(grep "portscan" /var/log/suricata/fast.log 2>/dev/null | wc -l)
if [[ $SCANS -gt 10 ]]; then
    echo "[$(date)] WARNING: Possible port scan detected ($SCANS events)" >> "$LOG"
fi

# Check for unusual outbound connections
OUTBOUND=$(netstat -an | grep ESTABLISHED | grep -v "127.0.0.1" | wc -l)
if [[ $OUTBOUND -gt 50 ]]; then
    echo "[$(date)] WARNING: High number of outbound connections: $OUTBOUND" >> "$LOG"
fi
EOF
    
    chmod +x /usr/local/bin/network-monitor
    
    # Add to cron
    echo "*/5 * * * * /usr/local/bin/network-monitor" | crontab -l | crontab -
}

# Setup stunnel for encrypted connections
setup_stunnel() {
    log "Setting up stunnel..."
    
    # Generate certificate
    openssl req -new -x509 -days 365 -nodes \
        -out /etc/stunnel/stunnel.pem \
        -keyout /etc/stunnel/stunnel.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    
    chmod 600 /etc/stunnel/stunnel.pem
    
    # Basic configuration
    cat > /etc/stunnel/stunnel.conf << EOF
; Stunnel configuration
cert = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel.pid
output = /var/log/stunnel.log

; Service definitions
[https]
accept = 8443
connect = 127.0.0.1:443
EOF
    
    systemctl enable stunnel4
    systemctl restart stunnel4
}

# Configure MAC address randomization
setup_mac_randomization() {
    if [[ "$MAC_RANDOMIZE" != "yes" ]]; then
        log "MAC randomization disabled"
        return
    fi
    
    log "Setting up MAC address randomization..."
    
    # NetworkManager method
    if command -v nmcli &>/dev/null; then
        cat > /etc/NetworkManager/conf.d/99-random-mac.conf << EOF
[main]
plugins=keyfile

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random

[connection-mac-randomization]
wifi.scan-rand-mac-address=yes
EOF
        systemctl restart NetworkManager
    fi
    
    # Systemd service method
    cat > /etc/systemd/system/mac-randomize.service << EOF
[Unit]
Description=MAC Address Randomization
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/randomize-mac
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # Create randomization script
    cat > /usr/local/bin/randomize-mac << 'EOF'
#!/bin/bash
for interface in eth0 wlan0; do
    if ip link show "$interface" &>/dev/null; then
        ip link set "$interface" down
        macchanger -r "$interface"
        ip link set "$interface" up
    fi
done
EOF
    
    chmod +x /usr/local/bin/randomize-mac
    systemctl enable mac-randomize.service
}

# Main execution
main() {
    setup_secure_dns
    setup_wireguard
    setup_tor
    setup_proxychains
    setup_suricata
    setup_network_monitoring
    setup_stunnel
    setup_mac_randomization
    
    log "Network security configuration complete"
}

main